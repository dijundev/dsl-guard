# dsl-guard

配置驱动的系统里，「表达式」和「SQL」是最容易变成执行入口的两处。这个库用两道**确定性边界**把它们关住：

- **`expr`** — 表达式 DSL。自研递归下降解析器 + AST 白名单，**不开放 `eval`**
- **`sqlguard`** — SQL 安全层。只读校验、危险关键字拦截、权限条件下推到最内层 WHERE

不依赖任何 Web 框架，`sqlglot` 是唯一的外部依赖。

## 为什么需要它

低代码平台、报表工具、规则引擎都有同一个问题：**表达式和查询语句来自配置，而配置是可以被人写坏的**。

最常见的两种做法都有洞：

| 做法 | 问题 |
| --- | --- |
| `eval(expr)` 或 `exec` | 配置里写 `__import__('os').system('id')` 就等于远程执行 |
| 黑名单过滤关键词 | 绕过方式无穷：编码变形、大小写混写、注释符拆词、同义函数替换 |

反过来做就干净了：**语法里根本不存在危险结构**。自研解析器只认数字、字符串、字段名、运算符和一张写死的函数表，属性访问、下标、`import`、`lambda` 连**解析阶段**都过不去——不需要靠黑名单去猜。

## 两道边界

### 1. 表达式：语法层面就没有执行能力

```python
from dslguard import expr

node = expr.parse("sum(amount) / count_distinct(order_id)")
print(expr.to_sql(node))
# (SUM(amount) / COUNT(DISTINCT order_id))
```

攻击在解析阶段就被挡住：

```python
expr.parse("__import__('os').system('id')")   # ExprError: 非法字符：'.'
expr.parse("1; DROP TABLE sales")             # ExprError: 非法字符：';'
expr.parse("eval('1+1')")                     # ExprError: 未在白名单内的函数：eval
expr.parse("a.b.c")                           # ExprError: 非法字符：'.'
```

同一个 AST 还能在本地求值，用来算条件而不碰数据库：

```python
node = expr.parse("region == '华东' and amount > 1000")
expr.evaluate(node, {"region": "华东", "amount": 1500})   # True
expr.evaluate(node, {"region": "华东", "amount": 500})    # False
```

### 2. SQL：一切改写都走 AST，不做字符串拼接

```python
from dslguard import sqlguard

ast = sqlguard.parse("SELECT region_id, SUM(amount) FROM sales GROUP BY region_id")
sqlguard.is_readonly(ast)        # True
sqlguard.extract_tables(ast)     # {'sales'}
```

拦得住的东西：

- 非只读语句（`DELETE` / `UPDATE` / `INSERT` / `DROP` / `TRUNCATE`）
- 危险关键字（`INTO OUTFILE` / `INTO DUMPFILE` / `LOAD DATA` / `INFORMATION_SCHEMA`）
- 危险函数（`SLEEP` / `BENCHMARK` / `LOAD_FILE`）

**权限条件下推到最内层 WHERE** 是最容易被写错的一步：

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

## 白名单

显式列出，不放行的一律拒绝。共 20 个函数：

- **聚合**：`sum` `count` `count_distinct` `avg` `min` `max`
- **标量**：`if` `coalesce` `nullif` `round` `abs` `concat` `lower` `upper` `length` `date` `hour` `date_format` `greatest` `least`

另外两条限制：表达式长度上限 512 字符，嵌套深度上限 24 层（防递归下降被超长输入拖死）。以 `_` 开头的标识符一律拒绝——那是 `__class__` 这类反射入口的入口。

```python
expr.whitelist_info()
# {'aggregate': [...], 'scalar': [...], 'count': 20, 'max_len': 512, 'max_depth': 24}
```

## 跑一遍

```bash
pip install -r requirements.txt

python examples/demo.py       # 六段演示，含攻击拦截与权限下推
python -m pytest tests -q     # 53 passed
```

`examples/demo.py` 用的是**虚构的** `sales` / `regions` 表，只为了让 SQL 看起来真实。

## 测试覆盖

53 个用例，分四组：

| 组 | 内容 |
| --- | --- |
| 攻击表达式 | 21 条（代码执行 / 反射 / 语句注入 / 不该存在的语法 / 白名单外调用）全部拒绝 |
| 合法表达式 | 12 条全部通过，并校验编译出的 SQL 片段 |
| 源码约束 | 断言 `expr.py` 里不出现 `eval` / `exec` / `builtins.compile` |
| SQL 安全层 | 写操作、危险关键字、危险函数、权限下推位置与别名限定、空范围恒假 |

## 已知局限

写清楚边界比声称「全覆盖」更有用：

1. **只防「配置写坏」，不防「数据本身有问题」**。表达式里的字符串字面量是安全的，但如果值来自不可信输入，仍要靠参数化查询。
2. **白名单是要维护的**。业务需要新函数时必须显式加进来——这既是安全属性也是维护成本。
3. **`sqlguard` 依赖 `sqlglot` 的解析结果**。如果 `sqlglot` 对某种方言的解析与目标数据库不一致，校验可能落空。目前固定 `mysql` 方言。
4. **不处理多语句**。`parse()` 一次只接受一条语句，多语句会直接解析失败。
5. **不做性能兜底**。危险函数拦了 `SLEEP` / `BENCHMARK`，但一条合法的巨型 JOIN 仍可能拖慢数据库，这属于查询复杂度治理，不在本库范围。

## 来源

从我做的一个低代码页面搭建平台里抽出来的通用层。业务代码（指标口径、表结构、权限数据）全部剥离，这里只剩解析器、白名单和 SQL 守卫——它们本身不含任何业务信息，因此可以独立使用。

## License

MIT
