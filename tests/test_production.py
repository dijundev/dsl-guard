"""生产向能力的测试：值层校验、参数化输出、一站式 guard、policy 护栏。"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dslguard import GuardPolicy, ValueRejected, check_list, check_value, expr, guard, is_clean, sqlguard  # noqa: E402
from dslguard.policy import DEFAULT_POLICY  # noqa: E402

# ---------------------------------------------------------------- 值层校验


@pytest.mark.parametrize(
    "value",
    [
        "a\x00b",              # NUL
        "a\x01b",              # C0 控制字符
        "a\x1fb",
        "a\x7fb",              # DEL
        "a\ud800b",            # 孤立代理项
    ],
)
def test_dirty_strings_rejected(value):
    with pytest.raises(ValueRejected):
        check_value(value)


@pytest.mark.parametrize("value", ["普通值", "a\tb", "a\nb", "a\rb", "", "' OR 1=1 --"])
def test_legal_strings_pass(value):
    """注意最后一条：`' OR 1=1 --` 不是**值层**该拦的 —— 它的危险来自被拼进 SQL，
    正确解法是参数化，不是把值本身判成非法。"""
    assert check_value(value) == value


def test_string_length_limit():
    check_value("a" * 1024)
    with pytest.raises(ValueRejected):
        check_value("a" * 1025)
    with pytest.raises(ValueRejected):
        check_value("a" * 10, max_len=5)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_floats_rejected(value):
    with pytest.raises(ValueRejected):
        check_value(value)


def test_int_range():
    check_value(2**63 - 1)
    check_value(-(2**63))
    with pytest.raises(ValueRejected):
        check_value(2**63)
    with pytest.raises(ValueRejected):
        check_value(-(2**63) - 1)


@pytest.mark.parametrize("value", [None, True, False, 0, -1, 3.14, ""])
def test_scalar_types_allowed(value):
    assert check_value(value) == value


@pytest.mark.parametrize("value", [[1, 2], {"a": 1}, (1,), object()])
def test_composite_types_rejected(value):
    with pytest.raises(ValueRejected):
        check_value(value)


def test_list_limits():
    assert check_list([1, 2, 3]) == [1, 2, 3]
    with pytest.raises(ValueRejected):
        check_list(range(501))
    with pytest.raises(ValueRejected):
        check_list([1, "a\x00"])


def test_is_clean_never_raises():
    assert is_clean("正常") is True
    assert is_clean("a\x00") is False


# ---------------------------------------------------------------- 参数化输出


def test_to_sql_with_params_extracts_literals():
    node = expr.parse("region == '华东' and amount > 100")
    sql, params = expr.to_sql_with_params(node)
    assert sql == "((region = %s) AND (amount > %s))"
    assert params == ["华东", 100]
    assert "华东" not in sql, "值绝不能出现在 SQL 文本里"


def test_to_sql_with_params_validates_values():
    """手工构造一个含脏字面量的 AST —— 表达式写不出来，但 API 是公开的，得挡住。"""
    from dslguard.expr import Binary, Col, Lit

    dirty = Binary(op="==", left=Col(name="name", table=None), right=Lit(value="a\x00b"))
    with pytest.raises(ValueRejected):
        expr.to_sql_with_params(dirty)


def test_plain_to_sql_still_works():
    """不传 params 时保持旧行为，向后兼容。"""
    node = expr.parse("sum(amount)")
    assert expr.to_sql(node) == "SUM(amount)"
    node2 = expr.parse("region == '华东'")
    assert "华东" in expr.to_sql(node2)


# ---------------------------------------------------------------- 一站式 guard

GOOD = "SELECT region_id, SUM(amount) AS amt FROM sales GROUP BY region_id"


def test_guard_accepts_clean_select():
    r = guard(GOOD)
    assert r.ok is True
    assert r.tables == frozenset({"sales"})
    assert r.readonly is True
    assert r.rules == []


def test_guard_reports_empty_input():
    r = guard("   ")
    assert r.ok is False
    assert "empty" in r.rules


def test_guard_rejects_multiple_statements():
    r = guard("SELECT 1 FROM sales; DROP TABLE sales")
    assert r.ok is False
    assert "multiple_statements" in r.rules


def test_guard_allows_trailing_semicolon():
    r = guard("SELECT region_id FROM sales;")
    assert r.ok is True


def test_guard_rejects_write_statements():
    r = guard("DELETE FROM sales")
    assert r.ok is False
    assert "not_readonly" in r.rules


def test_guard_rejects_denied_function():
    r = guard("SELECT SLEEP(10) FROM sales")
    assert r.ok is False
    assert "denied_function" in r.rules


def test_guard_rejects_denied_keyword():
    r = guard("SELECT * FROM sales INTO OUTFILE '/tmp/x'")
    assert r.ok is False
    assert "denied_keyword" in r.rules


def test_guard_enforces_table_whitelist():
    policy = GuardPolicy(allowed_tables=frozenset({"sales"}))
    assert guard("SELECT region_id FROM sales", policy).ok is True
    r = guard("SELECT * FROM secret_table", policy)
    assert r.ok is False
    assert "table_not_allowed" in r.rules


def test_guard_limits_joins():
    sql = (
        "SELECT s.a FROM sales s "
        "JOIN t1 ON s.id = t1.id JOIN t2 ON s.id = t2.id "
        "JOIN t3 ON s.id = t3.id JOIN t4 ON s.id = t4.id JOIN t5 ON s.id = t5.id"
    )
    policy = GuardPolicy(max_joins=4)
    r = guard(sql, policy)
    assert r.ok is False
    assert "too_many_joins" in r.rules


def test_guard_limits_in_list():
    items = ", ".join(str(i) for i in range(1, 8))
    sql = f"SELECT region_id FROM sales WHERE region_id IN ({items})"
    policy = GuardPolicy(max_in_list=5)
    r = guard(sql, policy)
    assert r.ok is False
    assert "in_list_too_long" in r.rules


def test_guard_requires_limit_when_asked():
    policy = GuardPolicy(require_limit=True)
    r = guard(GOOD, policy)
    assert r.ok is False
    assert "missing_limit" in r.rules
    assert guard(GOOD + " LIMIT 100", policy).ok is True


def test_guard_caps_limit():
    policy = GuardPolicy(max_limit=1000)
    r = guard(GOOD + " LIMIT 5000", policy)
    assert r.ok is False
    assert "limit_too_large" in r.rules


def test_guard_rejects_oversized_sql():
    policy = GuardPolicy(max_sql_len=100)
    r = guard("SELECT region_id FROM sales WHERE x = '" + "a" * 200 + "'", policy)
    assert r.ok is False
    assert "too_long" in r.rules


def test_guard_raise_if_failed():
    with pytest.raises(sqlguard.SqlRejected):
        guard("DELETE FROM sales").raise_if_failed()
    assert guard(GOOD).raise_if_failed().ok is True


def test_default_policy_is_permissive():
    """默认策略不能突然变严格，否则升级即事故。"""
    assert DEFAULT_POLICY.allowed_tables is None
    assert DEFAULT_POLICY.require_limit is False


def test_guard_never_raises_on_bad_input():
    for sql in ["", "   ", ";;;", "SELECT", "not sql at all", "SELECT '" + "a" * 50000 + "'"]:
        r = guard(sql)
        assert r.ok is False
        assert r.violations


# ---------------------------------------------------------------- 权限值校验


def test_inject_where_rejects_dirty_values():
    ast = sqlguard.parse("SELECT region_id FROM sales")
    with pytest.raises(ValueRejected):
        sqlguard.inject_where(ast, "region_id", ["R1", "a\x00"])


def test_inject_where_rejects_oversized_list():
    ast = sqlguard.parse("SELECT region_id FROM sales")
    with pytest.raises(ValueRejected):
        sqlguard.inject_where(ast, "region_id", [f"R{i}" for i in range(501)])
