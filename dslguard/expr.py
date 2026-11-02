"""表达式 DSL —— 把「配置里的算式」变成受白名单约束的 AST。

两条硬规则：

1. **不开放 `eval`**。表达式来自配置（可能是业务人员写的），等于把「代码执行权」
   交给配置内容。这里用自研的递归下降解析器把表达式变成自己的 AST，再用**显式白名单**
   树遍历求值；语法里根本不存在属性访问 / 下标 / import / lambda，所以
   `__import__('os').system(...)` 连**解析**都过不去，而不是靠黑名单去堵。

2. **函数与列都必须过白名单**。放行函数是一个写死的集合；
   以 `_` 开头的标识符一律拒绝（防 `__class__` 这类反射入口）。

同一个 AST 有两种消费方式：
    · `to_sql()` —— 聚合表达式编译成只读 SQL 片段
    · `evaluate()` —— 条件判断在本地求值，不碰数据库
"""

import re

from .errors import ExprError
from .values import ValueRejected, check_value

MAX_LEN = 512          # 表达式长度上限
MAX_DEPTH = 24         # 语法嵌套深度上限

# ---------------------------------------------------------------- 白名单
# 聚合函数：聚合表达式 → SQL
AGG_FUNCS = {
    "sum": 1,
    "count": 1,
    "count_distinct": 1,
    "avg": 1,
    "min": 1,
    "max": 1,
}

# 标量函数：既可用于 SQL，也可用于联动条件求值
SCALAR_FUNCS = {
    "if": 3,
    "coalesce": -1,        # -1 表示可变参数
    "nullif": 2,
    "round": -1,
    "abs": 1,
    "concat": -1,
    "lower": 1,
    "upper": 1,
    "length": 1,
    "date": 1,
    "hour": 1,
    "date_format": 2,
    "greatest": -1,
    "least": -1,
}

FUNCS = {**AGG_FUNCS, **SCALAR_FUNCS}

# SQL 里必须原样保留的方言函数名
_SQL_NAME = {"count_distinct": "COUNT(DISTINCT {0})"}

_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

_TOKEN_RE = re.compile(
    r"""
    (?P<ws>\s+)
  | (?P<num>\d+(?:\.\d+)?)
  | (?P<str>'[^']*')
  | (?P<ident>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?)
  | (?P<op><=|>=|<>|!=|==|&&|\|\||[-+*/<>!=])
  | (?P<lp>\()
  | (?P<rp>\))
  | (?P<lb>\[)
  | (?P<rb>\])
  | (?P<comma>,)
    """,
    re.VERBOSE,
)


class Node:
    """AST 基类（不用 dataclass，避免暴露 __dict__ 之外的反射面）。"""

    kind = "node"

    def __init__(self, **kw):
        self.__dict__.update(kw)


class Lit(Node):
    kind = "lit"


class Col(Node):
    kind = "col"


class Call(Node):
    kind = "call"


class Unary(Node):
    kind = "unary"


class Binary(Node):
    kind = "binary"


class InList(Node):
    kind = "in"


class ListLit(Node):
    kind = "list"


# ---------------------------------------------------------------- 词法
def tokenize(text):
    if len(text) > MAX_LEN:
        raise ExprError(f"表达式过长（>{MAX_LEN}）")
    tokens, pos = [], 0
    while pos < len(text):
        m = _TOKEN_RE.match(text, pos)
        if not m:
            raise ExprError(f"非法字符：{text[pos]!r}")
        pos = m.end()
        if m.lastgroup == "ws":
            continue
        tokens.append((m.lastgroup, m.group()))
    return tokens


# ---------------------------------------------------------------- 语法
class _Parser:
    def __init__(self, tokens):
        self.toks = tokens
        self.i = 0
        self.depth = 0

    def peek(self):
        return self.toks[self.i] if self.i < len(self.toks) else (None, None)

    def next(self):
        tok = self.peek()
        self.i += 1
        return tok

    def accept_op(self, *ops):
        kind, val = self.peek()
        if kind == "op" and val in ops:
            self.i += 1
            return val
        return None

    def accept_comma(self):
        """逗号在词法里是独立的 comma 组，不能走 accept_op。"""
        kind, _val = self.peek()
        if kind == "comma":
            self.i += 1
            return True
        return False

    def accept_word(self, *words):
        kind, val = self.peek()
        if kind == "ident" and val.lower() in words:
            self.i += 1
            return val.lower()
        return None

    def expect(self, kind, val=None):
        k, v = self.next()
        if k != kind or (val is not None and v != val):
            raise ExprError(f"语法错误：期望 {val or kind}，实际 {v!r}")
        return v

    def _enter(self):
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise ExprError(f"表达式嵌套过深（>{MAX_DEPTH}）")

    def _leave(self):
        self.depth -= 1

    def parse(self):
        node = self.or_()
        if self.i != len(self.toks):
            raise ExprError(f"表达式尾部有多余内容：{self.toks[self.i][1]!r}")
        return node

    def or_(self):
        self._enter()
        left = self.and_()
        while self.accept_op("||") or self.accept_word("or"):
            left = Binary(op="or", left=left, right=self.and_())
        self._leave()
        return left

    def and_(self):
        left = self.not_()
        while self.accept_op("&&") or self.accept_word("and"):
            left = Binary(op="and", left=left, right=self.not_())
        return left

    def not_(self):
        if self.accept_op("!") or self.accept_word("not"):
            return Unary(op="not", operand=self.not_())
        return self.cmp_()

    def cmp_(self):
        left = self.add_()
        kind, val = self.peek()
        if kind == "op" and val in ("=", "==", "!=", "<>", ">", ">=", "<", "<="):
            self.i += 1
            return Binary(op=val, left=left, right=self.add_())
        if kind == "ident" and val.lower() in ("in", "like"):
            self.i += 1
            if val.lower() == "in":
                return InList(expr=left, items=self.list_or_single(), negated=False)
            return Binary(op="like", left=left, right=self.add_())
        if kind == "ident" and val.lower() == "not":
            save = self.i
            self.i += 1
            if self.accept_word("in"):
                return InList(expr=left, items=self.list_or_single(), negated=True)
            self.i = save
        return left

    def list_or_single(self):
        kind, val = self.peek()
        if kind == "lb":
            self.i += 1
            items = []
            if self.peek()[0] != "rb":
                items.append(self.or_())
                while self.accept_comma():
                    items.append(self.or_())
            self.expect("rb")
            return ListLit(items=items)
        return ListLit(items=[self.or_()])

    def add_(self):
        left = self.mul_()
        while True:
            op = self.accept_op("+", "-")
            if not op:
                break
            left = Binary(op=op, left=left, right=self.mul_())
        return left

    def mul_(self):
        left = self.unary_()
        while True:
            op = self.accept_op("*", "/")
            if not op:
                break
            left = Binary(op=op, left=left, right=self.unary_())
        return left

    def unary_(self):
        if self.accept_op("-"):
            return Unary(op="-", operand=self.unary_())
        if self.accept_op("+"):
            return self.unary_()
        return self.primary_()

    def primary_(self):
        self._enter()
        try:
            kind, val = self.next()
            if kind == "num":
                return Lit(value=float(val) if "." in val else int(val), is_str=False)
            if kind == "str":
                return Lit(value=val[1:-1].replace("''", "'"), is_str=True)
            if kind == "lp":
                node = self.or_()
                self.expect("rp")
                return node
            if kind == "ident":
                low = val.lower()
                if self.peek()[0] == "lp":
                    return self.func_(val)
                if low == "true":
                    return Lit(value=True, is_str=False)
                if low == "false":
                    return Lit(value=False, is_str=False)
                if low == "null":
                    return Lit(value=None, is_str=False)
                return self.column_(val)
            raise ExprError(f"语法错误：无法解析 {val!r}")
        finally:
            self._leave()

    def column_(self, raw):
        if raw.startswith("_"):
            # 反射入口（__class__ / __globals__ …）——直接拒绝，别等求值
            raise ExprError(f"不允许的标识符：{raw}")
        if "." in raw:
            table, name = raw.split(".", 1)
            if table.startswith("_") or name.startswith("_"):
                raise ExprError(f"不允许的标识符：{raw}")
            return Col(table=table, name=name)
        return Col(table=None, name=raw)

    def func_(self, raw):
        name = raw.lower()
        if name.startswith("_"):
            raise ExprError(f"不允许的函数：{raw}")
        if name not in FUNCS:
            raise ExprError(f"未在白名单内的函数：{raw}")
        self.expect("lp")
        args = []
        if self.peek()[0] != "rp":
            args.append(self.or_())
            while self.accept_comma():
                args.append(self.or_())
        self.expect("rp")
        arity = FUNCS[name]
        if arity >= 0 and len(args) != arity:
            raise ExprError(f"{name} 需要 {arity} 个参数，实际 {len(args)} 个")
        if arity < 0 and not args:
            raise ExprError(f"{name} 至少需要 1 个参数")
        return Call(name=name, args=args)


def parse(text):
    """把表达式文本解析成 AST。任何可疑写法都在这里被拒。"""
    if text is None or str(text).strip() == "":
        raise ExprError("表达式为空")
    tokens = tokenize(str(text))
    if not tokens:
        raise ExprError("表达式为空")
    return _Parser(tokens).parse()


# ---------------------------------------------------------------- 遍历
def walk(node):
    yield node
    for key in ("left", "right", "expr", "operand"):
        child = node.__dict__.get(key)
        if isinstance(child, Node):
            yield from walk(child)
    for key in ("args", "items"):
        for child in node.__dict__.get(key) or []:
            if isinstance(child, Node):
                yield from walk(child)


def has_aggregate(node):
    return any(isinstance(n, Call) and n.name in AGG_FUNCS for n in walk(node))


def columns(node):
    return [n for n in walk(node) if isinstance(n, Col)]


def functions(node):
    return [n.name for n in walk(node) if isinstance(n, Call)]


# ---------------------------------------------------------------- 求值（不开放 eval）
def _render_value(value):
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, (int, float)):
        return str(value)
    escaped = str(value).replace("\\", "\\\\").replace("'", "''")
    return f"'{escaped}'"


def _sql_func(node, params=None):
    name = node.name
    if name == "count_distinct":
        return f"COUNT(DISTINCT {to_sql(node.args[0], params)})"
    rendered = ", ".join(to_sql(a, params) for a in node.args)
    return f"{name.upper()}({rendered})"


def to_sql(node, params=None):
    """AST → SQL 片段。只产出只读表达式，不含任何语句级关键字。

    `params` 决定字面量怎么处理：

    - **None（默认）**：字面量直接渲染进 SQL 文本。只适合本地调试、常量对照，
      或确实不含外部输入的场景。
    - **传一个 list**：字面量先过 `check_value` 校验，再替换成 `%s` 占位符
      并追加进这个 list，最终交给数据库驱动做参数绑定。

    生产环境应该用后者。手工转义（`replace("'", "''")`）在 NO_BACKSLASH_ESCAPES
    关闭、或 GBK 这类字符集下都可能出错，参数化才是根治。
    """
    if isinstance(node, Lit):
        if params is None:
            return _render_value(node.value)
        check_value(node.value)
        params.append(node.value)
        return "%s"
    if isinstance(node, Col):
        return f"{node.table}.{node.name}" if node.table else node.name
    if isinstance(node, Call):
        return _sql_func(node, params)
    if isinstance(node, Unary):
        if node.op == "not":
            return f"(NOT {to_sql(node.operand, params)})"
        return f"({node.op}{to_sql(node.operand, params)})"
    if isinstance(node, Binary):
        op = {"==": "=", "<>": "!=", "&&": "AND", "||": "OR"}.get(node.op, node.op)
        if node.op == "and":
            op = "AND"
        if node.op == "or":
            op = "OR"
        if node.op == "like":
            op = "LIKE"
        return f"({to_sql(node.left, params)} {op} {to_sql(node.right, params)})"
    if isinstance(node, ListLit):
        return "(" + ", ".join(to_sql(i, params) for i in node.items) + ")"
    if isinstance(node, InList):
        neg = "NOT " if node.negated else ""
        return f"({to_sql(node.expr, params)} {neg}IN {to_sql(node.items, params)})"
    raise ExprError(f"无法编译的节点：{type(node).__name__}")


def to_sql_with_params(node):
    """编译成 (SQL 片段, 参数列表)。字面量全部变成 `%s`，值单独带走。"""
    params = []
    return to_sql(node, params), params


_EVAL_SCALARS = {
    "if": lambda c, a, b: a if c else b,
    "coalesce": lambda *xs: next((x for x in xs if x is not None), None),
    "nullif": lambda a, b: None if a == b else a,
    "round": lambda x, n=0: round(x, int(n)),
    "abs": abs,
    "concat": lambda *xs: "".join("" if x is None else str(x) for x in xs),
    "lower": lambda s: str(s).lower(),
    "upper": lambda s: str(s).upper(),
    "length": lambda s: len(s or ""),
    "date": lambda s: str(s)[:10],
    "hour": lambda s: int(str(s)[11:13]) if s and len(str(s)) >= 13 else None,
    "greatest": max,
    "least": min,
}


def evaluate(node, ctx):
    """在给定上下文里求值（联动 / 可见性条件）。**不使用 Python eval**。

    只做显式分支分发：遇到未知节点类型直接报错，
    不存在「把字符串当代码执行」的路径。
    """
    if isinstance(node, Lit):
        return node.value
    if isinstance(node, Col):
        if node.table:
            for key in (f"{node.table}.{node.name}", node.name):
                if key in ctx:
                    return ctx[key]
        elif node.name in ctx:
            return ctx[node.name]
        raise ExprError(f"变量未定义：{node.table + '.' if node.table else ''}{node.name}")
    if isinstance(node, Call):
        if node.name in AGG_FUNCS:
            raise ExprError(f"联动条件里不允许聚合函数：{node.name}")
        fn = _EVAL_SCALARS.get(node.name)
        if fn is None:
            raise ExprError(f"函数 {node.name} 不支持在联动条件中求值")
        return fn(*[evaluate(a, ctx) for a in node.args])
    if isinstance(node, Unary):
        if node.op == "not":
            return not evaluate(node.operand, ctx)
        value = evaluate(node.operand, ctx)
        return -value if node.op == "-" else value
    if isinstance(node, Binary):
        if node.op == "and":
            return bool(evaluate(node.left, ctx)) and bool(evaluate(node.right, ctx))
        if node.op == "or":
            return bool(evaluate(node.left, ctx)) or bool(evaluate(node.right, ctx))
        left, right = evaluate(node.left, ctx), evaluate(node.right, ctx)
        return _compare(node.op, left, right)
    if isinstance(node, ListLit):
        return [evaluate(i, ctx) for i in node.items]
    if isinstance(node, InList):
        value = evaluate(node.expr, ctx)
        items = evaluate(node.items, ctx)
        hit = value in items
        return (not hit) if node.negated else hit
    raise ExprError(f"无法求值的节点：{type(node).__name__}")


def _compare(op, left, right):
    if op in ("=", "=="):
        return left == right
    if op in ("!=", "<>"):
        return left != right
    if left is None or right is None:
        return False
    if op == ">":
        return left > right
    if op == ">=":
        return left >= right
    if op == "<":
        return left < right
    if op == "<=":
        return left <= right
    if op == "like":
        pattern = str(right).replace("%", ".*").replace("_", ".")
        return re.fullmatch(pattern, str(left)) is not None
    raise ExprError(f"不支持的运算符：{op}")


def whitelist_info():
    """给接口 / 文档用的白名单摘要。"""
    return {
        "aggregate": sorted(AGG_FUNCS),
        "scalar": sorted(SCALAR_FUNCS),
        "count": len(FUNCS),
        "max_len": MAX_LEN,
        "max_depth": MAX_DEPTH,
    }
