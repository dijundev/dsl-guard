"""SQL 安全层：只读校验、危险关键字拦截、权限条件下推到最内层 WHERE。

**一切改写都走 AST，绝不用字符串拼接** —— 拼接会被注释符、编码变形、
大小写混合绕过。这个约束是硬性的：本模块对外只暴露 AST 级的操作。

面向生产：`guard()` 是推荐入口，一次返回结构化结果（通过与否 + 逐条违规原因），
而不是让调用方自己把四五个检查串起来 —— 漏一个就是漏洞。
"""

from dataclasses import dataclass, field

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError

from .policy import DEFAULT_POLICY, DENY_FUNCTIONS, DENY_KEYWORDS, GuardPolicy
from .values import ValueRejected, check_list

DIALECT = "mysql"

__all__ = [
    "DIALECT",
    "DENY_FUNCTIONS",
    "DENY_KEYWORDS",
    "GuardPolicy",
    "DEFAULT_POLICY",
    "SqlRejected",
    "Violation",
    "GuardResult",
    "parse",
    "to_sql",
    "is_readonly",
    "denied_keyword",
    "denied_functions",
    "extract_tables",
    "direct_sources",
    "count_joins",
    "max_in_list_size",
    "has_limit",
    "limit_value",
    "build_in_condition",
    "inject_where",
    "guard",
]

_WRITE_NODES = tuple(
    node
    for node in (
        getattr(exp, "Insert", None), getattr(exp, "Update", None),
        getattr(exp, "Delete", None), getattr(exp, "Drop", None),
        getattr(exp, "Create", None), getattr(exp, "Alter", None),
        getattr(exp, "TruncateTable", None), getattr(exp, "Merge", None),
    )
    if node is not None
)


class SqlRejected(Exception):
    """SQL 未通过安全校验（`parse` 阶段）。"""


def parse(sql):
    if not sql or not sql.strip():
        raise SqlRejected("SQL 为空")
    try:
        ast = sqlglot.parse_one(sql, dialect=DIALECT)
    except ParseError as exc:
        raise SqlRejected(f"SQL 语法不合法：{exc}")
    if ast is None:
        raise SqlRejected("SQL 解析结果为空")
    return ast


def to_sql(ast):
    return ast.sql(dialect=DIALECT)


def is_readonly(ast):
    """不要用「根节点必须是 Select」判断：UNION 的根节点是 Union。"""
    for node_type in _WRITE_NODES:
        if ast.find(node_type) is not None:
            return False
    return ast.find(exp.Select) is not None


def denied_keyword(sql, keywords=None):
    upper = sql.upper()
    for keyword in (keywords if keywords is not None else DENY_KEYWORDS):
        if keyword in upper:
            return keyword
    return None


def denied_functions(ast, deny=None):
    deny = DENY_FUNCTIONS if deny is None else deny
    hits = []
    for select in ast.find_all(exp.Select):
        for func in select.find_all(exp.Anonymous):
            if func.name and func.name.lower() in deny:
                hits.append(func.name)
    return hits


def extract_tables(ast):
    return {t.name.lower() for t in ast.find_all(exp.Table) if t.name}


def count_joins(ast):
    """所有 SELECT 层的 JOIN 总数（含子查询）。"""
    total = 0
    for select in ast.find_all(exp.Select):
        total += len(select.args.get("joins") or [])
    return total


def max_in_list_size(ast):
    """最长的那个 IN 列表的元素个数。没有 IN 则为 0。"""
    biggest = 0
    for node in ast.find_all(exp.In):
        biggest = max(biggest, len(node.expressions or []))
    return biggest


def has_limit(ast):
    return ast.find(exp.Limit) is not None


def limit_value(ast):
    """取根层 LIMIT 的数值；取不到（或不是字面量）返回 None。"""
    node = ast.args.get("limit") if isinstance(ast, exp.Select) else None
    if node is None:
        node = ast.find(exp.Limit)
    if node is None:
        return None
    this = node.args.get("expression") or node.args.get("this")
    try:
        return int(this.name)
    except (AttributeError, TypeError, ValueError):
        return None


def direct_sources(select):
    """本层 SELECT **直接**引用的 (表名, 别名)，不下钻子查询。

    为什么不能用 find_all(Table)：它会连带返回子查询里的表，
    于是权限条件会被注入到不持有该列的外层，SQL 直接报 Unknown column。
    权限注入必须落到**真正读取该表行的那一层**。
    """
    sources = []
    nodes = []
    from_ = select.args.get("from_") or select.args.get("from")
    if from_ is not None:
        nodes.append(from_.this)
    for join in select.args.get("joins") or []:
        nodes.append(join.this)
    for node in nodes:
        if isinstance(node, exp.Table) and node.name:
            sources.append((node.name.lower(), node.alias or None))
    return sources


def build_in_condition(column, values, table=None):
    """构造 `column IN (...)`。

    值来自权限表（系统内部数据），但仍要过一遍值校验：脏值进到 SQL 文本里
    一样会截断日志、破坏下游解析。校验不过抛 `ValueRejected`。

    不要手动把单引号替换成两个 —— exp.Literal.string() 自己会转义，
    手动再转一次会变成双重转义，值里含单引号时语义就错了。
    """
    values = check_list(values)
    literals = []
    for value in values:
        if isinstance(value, bool):
            literals.append(exp.Literal.number(1 if value else 0))
        elif isinstance(value, (int, float)):
            literals.append(exp.Literal.number(value))
        elif value is not None:
            literals.append(exp.Literal.string(str(value)))
    if not literals:
        # 空范围 = 无可见数据，用恒假条件表达
        return exp.false()
    return exp.In(
        this=exp.column(column, table=table) if table else exp.column(column),
        expressions=literals,
    )


def _and_into_where(select, condition):
    where = select.args.get("where")
    if where is not None and isinstance(where.this, exp.Expression):
        select.set("where", exp.Where(this=exp.and_(where.this, condition)))
    else:
        select.set("where", exp.Where(this=condition))


def inject_where(ast, column, values, target_tables=None):
    """把 `column IN (values)` 注入到每个「直接引用目标表」的 SELECT 的 WHERE。

    两条不能让步的约束：
      1. **注入到最内层**。注到外层的话，聚合发生在过滤之前，
         用户可以用「总数 − 可见明细」反推隐藏数据（推断式越权）。
      2. **列名必须用该层别名限定**。裸写 `region_id` 在 `sales JOIN regions`
         上会命中两列，MySQL 报 Column 'region_id' in where clause is ambiguous。
    """
    values_list = list(values)
    injected = 0
    for select in ast.find_all(exp.Select):
        hits = [
            (name, alias)
            for name, alias in direct_sources(select)
            if not target_tables or name in target_tables
        ]
        for name, alias in hits:
            _and_into_where(select, build_in_condition(column, values_list, alias or name))
            injected += 1
    return injected


# ---------------------------------------------------------------- 一站式入口
@dataclass(frozen=True)
class Violation:
    """一条违规。`rule` 是稳定的机器可读标识，`detail` 给人看。"""

    rule: str
    detail: str

    def __str__(self):
        return f"{self.rule}: {self.detail}"


@dataclass
class GuardResult:
    """`guard()` 的返回值。

    设计上**不抛异常**：校验失败是正常业务分支（配置写错了要能回显给人改），
    不是程序错误。真需要异常的地方调 `raise_if_failed()`。
    """

    ok: bool
    sql: str
    tables: frozenset
    violations: tuple
    ast: object = None
    readonly: bool = False

    def raise_if_failed(self):
        if not self.ok:
            raise SqlRejected("; ".join(str(v) for v in self.violations))
        return self

    @property
    def rules(self):
        return [v.rule for v in self.violations]


def guard(sql, policy=DEFAULT_POLICY):
    """按 policy 校验一条 SQL，返回结构化结果。

    检查顺序是刻意的：**先做不需要解析的廉价检查**（长度、多语句、关键字），
    再进 sqlglot 解析，最后做 AST 层面能做的（只读、函数、表白名单、JOIN、
    IN 长度、LIMIT）。这样恶意超大输入不会走到解析器里。
    """
    violations = []

    def bad(rule, detail):
        violations.append(Violation(rule, detail))

    def result(ast=None, tables=frozenset(), readonly=False):
        return GuardResult(
            ok=not violations,
            sql=text,
            tables=frozenset(tables),
            violations=tuple(violations),
            ast=ast,
            readonly=readonly,
        )

    text = (sql or "").strip()
    if not text:
        bad("empty", "SQL 为空")
        return result()

    if len(text) > policy.max_sql_len:
        bad("too_long", f"语句长度 {len(text)} 超过上限 {policy.max_sql_len}")
        return result()

    # 多语句：去掉结尾一个分号后仍含分号，就是多条语句。
    body = text[:-1] if text.endswith(";") else text
    if ";" in body and not policy.allow_multiple_statements:
        bad("multiple_statements", "一次只允许一条语句")
        return result()

    keyword = denied_keyword(text, policy.deny_keywords)
    if keyword:
        bad("denied_keyword", keyword)

    try:
        ast = parse(text)
    except SqlRejected as exc:
        bad("parse", str(exc))
        return result()

    readonly = is_readonly(ast)
    if not readonly:
        bad("not_readonly", "只允许只读查询")

    # 裸 `SELECT`（没有任何输出列）sqlglot 会解析成一个空 Select。
    # 它不是注入，但也不可能是一条真实查询 —— 当成畸形语句拒绝，别让它静默通过。
    if isinstance(ast, exp.Select) and not ast.expressions:
        bad("empty_projection", "SELECT 没有任何输出列")

    for name in denied_functions(ast, policy.deny_functions):
        bad("denied_function", name)

    tables = extract_tables(ast)
    if policy.allowed_tables is not None:
        extra = tables - set(policy.allowed_tables)
        if extra:
            bad("table_not_allowed", "、".join(sorted(extra)))

    joins = count_joins(ast)
    if joins > policy.max_joins:
        bad("too_many_joins", f"{joins} 个 JOIN，上限 {policy.max_joins}")

    in_size = max_in_list_size(ast)
    if in_size > policy.max_in_list:
        bad("in_list_too_long", f"IN 列表 {in_size} 项，上限 {policy.max_in_list}")

    if policy.require_limit and not has_limit(ast):
        bad("missing_limit", "必须带 LIMIT")

    limit = limit_value(ast)
    if limit is not None and limit > policy.max_limit:
        bad("limit_too_large", f"LIMIT {limit} 超过上限 {policy.max_limit}")

    return result(ast=ast, tables=tables, readonly=readonly)
