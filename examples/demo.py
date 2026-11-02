"""演示：用一套虚构的销售表，跑通两道边界。

运行：
    python examples/demo.py

表结构是编的，只为了让 SQL 看起来真实：
    sales(order_id, region_id, amount, qty, status, sold_at)
    regions(region_id, region_name)
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dslguard import expr, sqlguard  # noqa: E402


def title(text):
    print()
    print(text)
    print("-" * 62)


title("① 白名单摘要")
info = expr.whitelist_info()
print(f"放行函数 {info['count']} 个：聚合 {info['aggregate']}")
print(f"标量 {info['scalar']}")
print(f"表达式长度上限 {info['max_len']}，嵌套深度上限 {info['max_depth']}")


title("② 合法表达式 → SQL 片段")
for text in ["sum(amount)", "sum(amount) / count_distinct(order_id)", "round(avg(qty), 2)"]:
    print(f"  {text:<42} → {expr.to_sql(expr.parse(text))}")


title("③ 攻击表达式 → 解析阶段就被拒绝")
attacks = [
    "__import__('os').system('id')",
    "().__class__.__bases__[0].__subclasses__()",
    "1; DROP TABLE sales",
    "sales; SELECT SLEEP(10)",
    "open('/etc/passwd').read()",
    "eval('1+1')",
    "a.b.c",
    "unknown_func(1)",
]
for text in attacks:
    try:
        expr.parse(text)
        print(f"  {text:<42} → 竟然通过了（不该发生）")
    except expr.ExprError as e:
        print(f"  {text:<42} → 拒绝：{e}")


title("④ 条件表达式在本地求值（不碰数据库）")
node = expr.parse("region == '华东' and amount > 1000")
for ctx in [{"region": "华东", "amount": 1500}, {"region": "华东", "amount": 800}]:
    print(f"  {ctx} → {expr.evaluate(node, ctx)}")


title("⑤ SQL 安全层：只读 + 危险操作拦截")
good = "SELECT region_id, SUM(amount) AS amt FROM sales WHERE status = 'PAID' GROUP BY region_id"
ast = sqlguard.parse(good)
print(f"  只读 = {sqlguard.is_readonly(ast)}，涉及表 = {sqlguard.extract_tables(ast)}")


def one_line(err):
    return str(err).strip().splitlines()[0][:52]


bad_cases = [
    "DELETE FROM sales",
    "UPDATE sales SET amount = 0",
    "SELECT * FROM sales INTO OUTFILE '/tmp/x'",
    "SELECT SLEEP(10)",
    "SELECT * FROM information_schema.tables",
]
for sql in bad_cases:
    # 第一道：便宜的字符串预筛（不需要解析），先拦明显危险的写法
    kw = sqlguard.denied_keyword(sql)
    if kw:
        print(f"  {sql:<52} → 关键字 {kw}")
        continue
    try:
        a = sqlguard.parse(sql)
    except sqlguard.SqlRejected as e:
        print(f"  {sql:<52} → 解析拒绝：{one_line(e)}")
        continue
    # 第二道：解析成 AST 之后再判只读与危险函数
    verdict = []
    if not sqlguard.is_readonly(a):
        verdict.append("非只读")
    if sqlguard.denied_functions(a):
        verdict.append(f"函数 {sqlguard.denied_functions(a)}")
    print(f"  {sql:<52} → {'；'.join(verdict) or '未拦截'}")


title("⑥ 权限条件下推到最内层 WHERE")
sql = (
    "SELECT region_id, SUM(amount) AS amt "
    "FROM (SELECT region_id, amount FROM sales WHERE status = 'PAID') t "
    "GROUP BY region_id"
)
print("  改写前：")
print("   ", sql)
ast = sqlguard.parse(sql)
count = sqlguard.inject_where(ast, "region_id", ["R1", "R2"], target_tables={"sales"})
print(f"  注入点 {count} 处（只注入直接读 sales 的那一层），改写后：")
print("   ", sqlguard.to_sql(ast).replace("\n", " "))

print()
print("为什么必须注到最内层：如果注在外层，SUM 会先按全量算完再过滤，")
print("用户拿「总计 − 可见明细」就能反推出看不到的部分 —— 这是推断式越权。")
