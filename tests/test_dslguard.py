"""dsl-guard 测试。

跑法：
    python -m pytest tests -q
"""

import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dslguard import expr, sqlguard  # noqa: E402

# ---------------------------------------------------------------- 表达式：攻击面

ATTACKS = [
    # 代码执行
    "__import__('os').system('id')",
    "eval('1+1')",
    "exec('x=1')",
    "compile('1', '', 'eval')",
    "globals()",
    "getattr(x, 'y')",
    # 反射 / 属性访问
    "().__class__.__bases__[0].__subclasses__()",
    "x.__dict__",
    "__globals__",
    "open('/etc/passwd').read()",
    # 语句注入
    "1; DROP TABLE sales",
    "sales; SELECT SLEEP(10)",
    "sum(amount)); DROP TABLE sales;--",
    # 语法层面不该存在的结构
    "lambda: 1",
    "1 if 1 else 2",
    "[x for x in y]",
    "import os",
    "a.b.c",
    # 白名单外 / 参数个数不对
    "unknown_func(1)",
    "sum(1, 2)",
    "count()",
]


@pytest.mark.parametrize("text", ATTACKS)
def test_attack_expressions_are_rejected(text):
    with pytest.raises(expr.ExprError):
        expr.parse(text)


LEGAL = [
    "sum(amount)",
    "sum(amount) / count_distinct(order_id)",
    "round(avg(qty), 2)",
    "amount > 1000",
    "region == '华东' and amount > 100",
    "region in ['华东', '华南']",
    "not (amount < 100)",
    "if(status == 'PAID', 1, 0)",
    "coalesce(x, 0) + 1",
    "date_format(sold_at, '%Y-%m')",
    "greatest(a, b, c)",
    "-amount + 1",
]


@pytest.mark.parametrize("text", LEGAL)
def test_legal_expressions_pass(text):
    assert expr.parse(text) is not None


def test_compiles_to_sql():
    node = expr.parse("sum(amount) / count_distinct(order_id)")
    out = expr.to_sql(node)
    assert "SUM(amount)" in out
    assert "COUNT(DISTINCT order_id)" in out


def test_evaluate_without_touching_db():
    node = expr.parse("region == '华东' and amount > 1000")
    assert expr.evaluate(node, {"region": "华东", "amount": 1500}) is True
    assert expr.evaluate(node, {"region": "华东", "amount": 500}) is False
    assert expr.evaluate(node, {"region": "华南", "amount": 5000}) is False


def test_expression_limits():
    with pytest.raises(expr.ExprError):
        expr.parse("a" + " + a" * 400)
    with pytest.raises(expr.ExprError):
        expr.parse("(" * 40 + "1" + ")" * 40)


def test_source_never_calls_eval_or_exec():
    """硬约束：源码里不允许出现 Python 的 eval / exec / builtins.compile。

    注意排除 `re.compile(`：它是正则预编译，和 builtins.compile 无关。
    """
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dslguard", "expr.py"
    )
    source = open(path, encoding="utf-8").read()
    assert not re.search(r"(?<![.\w])(eval|exec)\s*\(", source), "出现 eval/exec 调用"
    assert not re.search(r"(?<!re\.)compile\s*\(", source), "出现 builtins.compile 调用"
    assert "__builtins__" not in source


def test_whitelist_is_explicit():
    info = expr.whitelist_info()
    assert info["count"] == len(info["aggregate"]) + len(info["scalar"])
    assert "sum" in info["aggregate"]
    assert "sleep" not in info["scalar"]
    assert info["max_len"] > 0 and info["max_depth"] > 0


# ---------------------------------------------------------------- SQL 安全层

GOOD_SQL = "SELECT region_id, SUM(amount) AS amt FROM sales WHERE status = 'PAID' GROUP BY region_id"


def test_select_is_readonly_and_tables_extracted():
    ast = sqlguard.parse(GOOD_SQL)
    assert sqlguard.is_readonly(ast) is True
    assert sqlguard.extract_tables(ast) == {"sales"}
    assert sqlguard.denied_keyword(GOOD_SQL) is None
    assert sqlguard.denied_functions(ast) == []


@pytest.mark.parametrize(
    "sql",
    [
        "DELETE FROM sales",
        "UPDATE sales SET amount = 0",
        "INSERT INTO sales (order_id) VALUES (1)",
        "DROP TABLE sales",
        "TRUNCATE TABLE sales",
    ],
)
def test_write_statements_are_not_readonly(sql):
    ast = sqlguard.parse(sql)
    assert sqlguard.is_readonly(ast) is False


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM sales INTO OUTFILE '/tmp/x'",
        "SELECT * FROM sales INTO DUMPFILE '/tmp/x'",
        "LOAD DATA INFILE '/tmp/x' INTO TABLE sales",
        "SELECT * FROM information_schema.tables",
    ],
)
def test_dangerous_keywords_are_detected(sql):
    assert sqlguard.denied_keyword(sql) is not None


@pytest.mark.parametrize("sql", ["SELECT SLEEP(10)", "SELECT BENCHMARK(1000000, MD5('x'))"])
def test_dangerous_functions_are_detected(sql):
    assert sqlguard.denied_functions(sqlguard.parse(sql))


def test_inject_where_lands_on_innermost_select():
    sql = (
        "SELECT region_id, SUM(amount) AS amt "
        "FROM (SELECT region_id, amount FROM sales WHERE status = 'PAID') t "
        "GROUP BY region_id"
    )
    ast = sqlguard.parse(sql)
    injected = sqlguard.inject_where(ast, "region_id", ["R1", "R2"], target_tables={"sales"})
    out = sqlguard.to_sql(ast).replace("\n", " ")

    assert injected == 1, "只应注入直接读 sales 的那一层"
    assert "region_id IN ('R1', 'R2')" in out
    # 注入点必须在子查询内部，而不是外层 WHERE
    inner = out[out.index("FROM ("):]
    assert "region_id IN ('R1', 'R2')" in inner


def test_inject_where_qualifies_column_with_alias():
    sql = "SELECT s.region_id, SUM(s.amount) FROM sales AS s GROUP BY s.region_id"
    ast = sqlguard.parse(sql)
    sqlguard.inject_where(ast, "region_id", ["R1"], target_tables={"sales"})
    out = sqlguard.to_sql(ast)
    assert "s.region_id IN ('R1')" in out, "必须用该层别名限定，否则 JOIN 上会列名歧义"


def test_empty_scope_yields_false_condition():
    """空权限范围 = 看不到任何数据，不能退化成「不过滤」。"""
    ast = sqlguard.parse("SELECT SUM(amount) FROM sales")
    sqlguard.inject_where(ast, "region_id", [], target_tables={"sales"})
    out = sqlguard.to_sql(ast).upper()
    assert "FALSE" in out or "1 = 0" in out or "1=0" in out
