"""生产环境的护栏配置。

默认值按「不破坏既有调用方」设：表白名单为空表示不校验、不强制 LIMIT。
真正上线时应该显式给一份 policy，至少把 `allowed_tables` 和 `require_limit` 定下来 ——
没有表范围校验的只读检查只防注入，不防「查了不该查的表」。
"""

from dataclasses import dataclass

# 这些函数会拖死或探测数据库，业务查询没有理由用到。
DENY_FUNCTIONS = frozenset({"sleep", "benchmark", "load_file"})

# 这些关键字不出现在任何合法的只读查询里。
DENY_KEYWORDS = ("INTO OUTFILE", "INTO DUMPFILE", "LOAD DATA", "INFORMATION_SCHEMA")


@dataclass(frozen=True)
class GuardPolicy:
    """一次 SQL 校验的完整护栏。frozen 是为了可以安全地跨线程复用。"""

    # 允许访问的表。None 表示不校验（默认，向后兼容）；生产环境应显式指定。
    allowed_tables: frozenset | None = None
    deny_functions: frozenset = DENY_FUNCTIONS
    deny_keywords: tuple = DENY_KEYWORDS

    # 语句长度上限（字符）。防超大语句撑爆解析器与日志。
    max_sql_len: int = 20_000

    # JOIN 数量上限。超过通常说明查询没设计好，且容易拖垮实例。
    max_joins: int = 8

    # 单个 IN 列表的元素上限。
    max_in_list: int = 500

    # 是否强制带 LIMIT，以及 LIMIT 的上限。
    require_limit: bool = False
    max_limit: int = 10_000

    # 是否允许一次传多条语句（用分号分隔）。默认不允许。
    allow_multiple_statements: bool = False


DEFAULT_POLICY = GuardPolicy()

# 面向公网 / 多租户场景的收紧版：必须带 LIMIT、JOIN 更少、列表更小。
# 注意 `allowed_tables` 这里刻意留 None —— 空集合会拒绝一切查询。
# 用它的时候必须自己填上该业务允许的表，例如：
#     STRICT_POLICY.__class__(allowed_tables=frozenset({"sales"}), ...)
STRICT_POLICY = GuardPolicy(
    max_joins=4,
    max_in_list=100,
    require_limit=True,
    max_limit=1_000,
    max_sql_len=8_000,
)
