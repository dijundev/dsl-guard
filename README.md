# dsl-guard

[![tests](https://github.com/dijundev/dsl-guard/actions/workflows/tests.yml/badge.svg)](https://github.com/dijundev/dsl-guard/actions/workflows/tests.yml)

配置驱动的系统里，「表达式」「SQL」「值」是三处最容易变成事故的入口。这个库把三道**确定性边界**摆在那里：

| 层 | 防什么 | 怎么做 |
| --- | --- | --- |
| `expr` | 配置里的算式被执行 | 自研递归下降解析器 + AST 白名单，**不开放 `eval`** |
| `sqlguard` | 拼出来的语句越权/写库 | sqlglot 走 AST：只读校验、表白名单、JOIN/IN/LIMIT 限制、权限下推 |
| `values` | 干净语句里的脏值 | 长度、控制字符、NUL、NaN/Inf、整数范围 |

不依赖 Web 框架，`sqlglot` 是唯一外部依赖。**103 个测试**。

## 为什么需要它

低代码平台、报表工具、规则引擎都有同一个问题：**表达式和查询来自配置，而配置是可以被人写坏的**。

两种常见做法都有洞：

| 做法 | 问题 |
| --- | --- |
| `eval(expr)` / `exec` | 配置里写 `__import__('os').system('id')` 就等于远程执行 |
| 黑名单过滤关键词 | 绕过方式无穷：编码变形、大小写混写、注释符拆词、同义函数替换 |

反过来做就干净了：**语法里根本不存在危险结构**。自研解析器只认数字、字符串、字段名、运算符和一张写死的函数表，属性访问、下标、`import`、`lambda` 连**解析阶段**都过不去——不需要靠黑名单去猜。

**但结构安全只是第一层。** 一条完全合法的 `SELECT ... WHERE name = 'x'`，值里带 NUL 一样能截断日志；带 NaN 一样能让数值比较静默失效。所以值要单独过一层。

## 三道边界

### 1. 表达式：语法层面就没有执行能力

```python
from dslguard import expr

node = expr.parse("sum(amount) / count_distinct(order_id)")
expr.to_sql(node)          # (SUM(amount) / COUNT(DISTINCT order_id))
```

攻击在解析阶段就被挡住：

```
expr.parse("__import__('os').system('id')")   # ExprError: 非法字符：'.'
expr.parse("1; DROP TABLE sales")             # ExprError: 非法字符：';'
expr.parse("eval('1+1')")                     # ExprError: 未在白名单内的函数：eval
```

### 2. 值：结构合法 ≠ 值干净

```python
from dslguard import check_value, ValueRejected

check_value("华东")          # 通过
check_value("a\x00b")        # ValueRejected: 字符串含 NUL（\x00）
check_value(float("nan"))    # ValueRejected: 浮点值为 NaN
check_value(2**70)           # ValueRejected: 整数超出 BIGINT 范围
check_value([1, 2])          # ValueRejected: 不支持的值类型：list
```

一条容易被忽略的原则：**`' OR 1=1 --` 不是值层该拦的东西**。它的危险来自被拼进 SQL，
正确解法是**参数化**，不是把值本身判成非法——把这类值判非法，正常业务里带引号的名字就写不进去了。

### 3. SQL：一切改写都走 AST，不做字符串拼接

```python
from dslguard import guard, GuardPolicy

policy = GuardPolicy(
    allowed_tables=frozenset({"sales"}),
    require_limit=True,
    max_limit=1000,
    max_joins=4,
    max_in_list=100,
)

r = guard("SELECT region_id, SUM(amount) FROM sales GROUP BY region_id", policy)
r.ok              # False
r.rules           # ['missing_limit']

guard("SELECT * FROM payroll LIMIT 10", policy).rules        # ['table_not_allowed']
guard("SELECT 1 FROM sales LIMIT 10; DROP TABLE sales").rules # ['multiple_statements']
guard("SELECT SLEEP(10) FROM sales").rules                   # ['denied_function']
guard("SELECT").rules                                        # ['empty_projection']
```

`guard()` **不抛异常**：校验失败是正常业务分支（配置写错了要能回显给人改），不是程序错误。
真需要异常的地方调 `raise_if_failed()`。

检查顺序是刻意的：**先做不需要解析的廉价检查**（长度、多语句、关键字），再进解析器，
最后做 AST 层的事。恶意超大输入不会走到 sqlglot 里。

## 权限条件下推到最内层 WHERE

```sql
-- 改写前
SELECT region_id, SUM(amount) FROM (SELECT region_id, amount FROM sales) t GROUP BY region_id

-- inject_where(ast, "region_id", ["R1","R2"], target_tables={"sales"})
SELECT region_id, SUM(amount)
FROM (SELECT region_id, amount FROM sales WHERE sales.region_id IN ('R1','R2')) t
GROUP BY region_id          -- ↑ 注入在内层，不在外层
```

两个细节都必须对：

1. **注到最内层**。注在外层的话，聚合先按全量算完再过滤，用户拿「总计 − 可见明细」就能反推出被隐藏的部分——这是推断式越权。
2. **列名必须用该层别名限定**。裸写 `region_id` 在 `sales JOIN regions` 上会命中两列，MySQL 直接报 ambiguous。

空权限范围不能退化成「不过滤」，会生成恒假条件：

```python
sqlguard.inject_where(ast, "region_id", [], target_tables={"sales"})   # → WHERE FALSE
```

## 生产环境怎么接

### 一、字面量不要进 SQL 文本

`to_sql(node)` 默认把字面量渲染进 SQL（方便调试），但生产应该用参数化版本：

```python
node = expr.parse("region == '华东' and amount > 1000")

expr.to_sql(node)                    # ((region = '华东') AND (amount > 1000))
expr.to_sql_with_params(node)        # ("((region = %s) AND (amount > 1000))", ['华东', 1000])
```

为什么不能靠转义：`str.replace("'", "''")` 在 `NO_BACKSLASH_ESCAPES` 关闭、或 GBK 这类
字符集下都可能出错（经典宽字节注入 `0xbf27` 就是吃掉反斜杠）。参数化是根治，转义只是补丁。

传了 `params` 之后，字面量会先过 `check_value` 再入列——脏值在编译阶段就报错。

### 二、把护栏收成一个 policy

不要在生产代码里散着调 `is_readonly()` + `denied_keyword()` + `extract_tables()`——漏一个就是漏洞。

```python
DEFAULT_POLICY   # 宽松：不校验表、不强制 LIMIT（保证升级不破坏既有调用方）
STRICT_POLICY    # 收紧：必须 LIMIT、JOIN ≤ 4、IN ≤ 100、语句 ≤ 8KB
```

`STRICT_POLICY` 的 `allowed_tables` 刻意留 `None`——空集合会拒绝一切查询。
用它的时候必须自己填上本业务允许的表。

### 三、结果按规则名分支

`Violation.rule` 是稳定的机器可读标识，可以直接映射到前端提示：

```python
{
    "empty": "语句为空",
    "too_long": "语句过长",
    "multiple_statements": "一次只允许一条语句",
    "parse": "语法不合法",
    "not_readonly": "只允许只读查询",
    "denied_keyword": "包含危险关键字",
    "denied_function": "包含危险函数",
    "empty_projection": "SELECT 没有输出列",
    "table_not_allowed": "访问了未授权的表",
    "too_many_joins": "JOIN 过多",
    "in_list_too_long": "IN 列表过长",
    "missing_limit": "缺少 LIMIT",
    "limit_too_large": "LIMIT 过大",
}
```

## 白名单

显式列出，不放行的一律拒绝。共 20 个函数：

- **聚合**：`sum` `count` `count_distinct` `avg` `min` `max`
- **标量**：`if` `coalesce` `nullif` `round` `abs` `concat` `lower` `upper` `length` `date` `hour` `date_format` `greatest` `least`

另外两条限制：表达式长度上限 512 字符，嵌套深度上限 24 层（防递归下降被超长输入拖死）。
以 `_` 开头的标识符一律拒绝——那是 `__class__` 这类反射入口的入口。

## 跑一遍

```bash
pip install -r requirements.txt

python examples/demo.py       # 九段演示：白名单 / 攻击拦截 / 值校验 / 参数化 / guard
python -m pytest tests -q     # 103 passed
```

`examples/demo.py` 用的是**虚构的** `sales` / `regions` 表，只为了让 SQL 看起来真实。

## 测试覆盖（103 个）

| 文件 | 关注点 |
| --- | --- |
| `test_dslguard.py` | 21 条攻击表达式全部拒绝、12 条合法表达式通过、源码不出现 `eval/exec`、权限下推位置与别名 |
| `test_production.py` | 脏值（NUL/控制字符/超长/NaN/Inf/超范围整数/复合类型）、参数化输出、13 条 guard 规则、policy 默认值不突变 |

## 已知局限

写清楚边界比声称「全覆盖」更有用：

1. **值层不管语义正确性**。`check_value` 只判「这个值不可能是合法的 SQL 参数」，
   不判「这个值在业务上对不对」。枚举越界、外键不存在这些要靠业务校验。
2. **白名单是要维护的**。业务需要新函数时必须显式加进来——这既是安全属性也是维护成本。
3. **`sqlguard` 依赖 `sqlglot` 的解析结果**。如果 `sqlglot` 对某种方言的解析与目标数据库不一致，
   校验可能落空。目前固定 `mysql` 方言。
4. **不做查询复杂度治理**。`max_joins` / `max_in_list` 只是粗粒度闸门，
   真正的慢查询要靠执行计划审查、超时与资源配额。
5. **`LIMIT` 不能替代分页**。大 OFFSET 仍然是全表扫描，本库不管。
6. **没有连接池 / 重试 / 熔断**。这是校验层，不是数据访问层。

## 版本

- `0.2.0` — 新增 `values` 值层校验、`to_sql_with_params` 参数化输出、`guard()` 一站式入口与 `GuardPolicy`
- `0.1.0` — 表达式 DSL 与 SQL 安全层

## 来源

从我做的一个低代码页面搭建平台里抽出来的通用层。业务代码（指标口径、表结构、权限数据）全部剥离，
这里只剩解析器、白名单、值校验和 SQL 守卫——它们本身不含业务信息，因此可以独立使用。

## License

MIT
