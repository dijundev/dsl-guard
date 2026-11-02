"""值层校验：表达式里的字面量、绑定到 SQL 的参数，都要先过这里。

为什么需要单独一层：AST 白名单只保证**语句形状**合法，不保证**值**是干净的。
脏数据在这个库关心的范围里有这些形态：

  · 含 NUL / 控制字符 —— 截断日志、破坏下游解析、在某些驱动下提前结束字符串
  · 超长字符串 —— 一条表达式就能撑爆内存和审计日志
  · NaN / ±Inf —— 进入 SQL 变成非法数字，或让所有数值比较静默失效
  · 孤立代理项 —— 写库时报编码错误，或在字符集转换中被吞掉
  · 超大 IN 列表 —— 一条语句打满数据库连接

另外要说明一件事：**转义不是防线**。`str.replace("'", "''")` 这种手工转义在
`NO_BACKSLASH_ESCAPES` 关闭 / 字符集为 GBK 等场景下都可能出错（经典宽字节注入
`0xbf27` 就是吃掉反斜杠）。真正的解法是**参数化**——字面量不进 SQL 文本，
走 `to_sql(node, params=[...])` 收集成占位符。这一层的职责是把不可能合法的值挡在更前面。
"""

from .errors import DslGuardError

# 单个字符串值的长度上限。1024 足够覆盖正常业务值（名称 / 编码 / 路径），
# 又能在被滥用时立刻暴露 —— 真正的长文走 TEXT 列，不该走表达式。
MAX_STR_LEN = 1024

# 一次 IN 列表的元素上限。超过这个量级说明查询本身设计有问题。
MAX_LIST_LEN = 500

# SQL BIGINT 范围。超出的整数在各家数据库上行为不一致（截断 / 报错 / 转浮点）。
INT_MIN = -(2**63)
INT_MAX = 2**63 - 1

# 允许出现的控制字符：制表、换行、回车 —— 地址、备注这类字段里是合法的。
_ALLOWED_CONTROLS = {"\t", "\n", "\r"}


class ValueRejected(DslGuardError):
    """值未通过校验。"""

    code = 4005


def _check_str(value, max_len):
    if len(value) > max_len:
        raise ValueRejected(f"字符串超长：{len(value)} > {max_len}")
    for ch in value:
        code = ord(ch)
        if code == 0:
            raise ValueRejected("字符串含 NUL（\\x00）")
        if code < 0x20 and ch not in _ALLOWED_CONTROLS:
            raise ValueRejected(f"字符串含控制字符 U+{code:04X}")
        if code == 0x7F:
            raise ValueRejected("字符串含 DEL 控制字符")
        if 0xD800 <= code <= 0xDFFF:
            raise ValueRejected(f"字符串含孤立代理项 U+{code:04X}（编码非法）")
    return value


def check_value(value, max_len=MAX_STR_LEN):
    """校验单个值，通过则原样返回，不通过抛 `ValueRejected`。

    允许的类型：`None` / `bool` / `int` / `float` / `str`。
    其余类型（list / dict / 自定义对象）一律拒绝 —— 表达式不该承载复合值。
    """
    if value is None:
        return value
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        if not (INT_MIN <= value <= INT_MAX):
            raise ValueRejected(f"整数超出 BIGINT 范围：{value}")
        return value
    if isinstance(value, float):
        if value != value:
            raise ValueRejected("浮点值为 NaN")
        if value in (float("inf"), float("-inf")):
            raise ValueRejected("浮点值为 Infinity")
        return value
    if isinstance(value, str):
        return _check_str(value, max_len)
    raise ValueRejected(f"不支持的值类型：{type(value).__name__}")


def check_list(values, max_items=MAX_LIST_LEN, max_len=MAX_STR_LEN):
    """校验一组值（IN 列表 / 权限范围），返回校验后的 list。"""
    values = list(values)
    if len(values) > max_items:
        raise ValueRejected(f"列表过长：{len(values)} > {max_items}")
    return [check_value(v, max_len) for v in values]


def is_clean(value, max_len=MAX_STR_LEN):
    """不抛异常的布尔版本，便于在过滤场景里用。"""
    try:
        check_value(value, max_len)
        return True
    except ValueRejected:
        return False
