"""SQL 安全层：只读校验、危险关键字拦截、权限条件下推到最内层 WHERE。

**一切改写都走 AST，绝不用字符串拼接** —— 拼接会被注释符、编码变形、
大小写混合绕过。这个约束是硬性的：本模块对外只暴露 AST 级的操作。
"""

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError

DIALECT = "mysql"

DENY_FUNCTIONS = frozenset({"sleep", "benchmark", "load_file"})
DENY_KEYWORDS = ("INTO OUTFILE", "INTO DUMPFILE", "LOAD DATA", "INFORMATION_SCHEMA")

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
    """SQL 未通过安全校验。"""


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


def denied_keyword(sql):
    upper = sql.upper()
    for keyword in DENY_KEYWORDS:
        if keyword in upper:
            return keyword
    return None


def denied_functions(ast):
    hits = []
    for select in ast.find_all(exp.Select):
        for func in select.find_all(exp.Anonymous):
            if func.name and func.name.lower() in DENY_FUNCTIONS:
                hits.append(func.name)
    return hits


def extract_tables(ast):
    return {t.name.lower() for t in ast.find_all(exp.Table) if t.name}


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
    """构造 `column IN (...)`。值来自权限表（系统内部数据），用字面量是安全的。

    不要手动把单引号替换成两个 —— exp.Literal.string() 自己会转义，
    手动再转一次会变成双重转义，值里含单引号时语义就错了。
    """
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
