"""dsl-guard —— 配置驱动系统里的三道确定性边界。

- `expr`    ：表达式 DSL。自研递归下降解析器 + AST 白名单，**不开放 eval**；
              可编译成参数化 SQL（`to_sql_with_params`），字面量不进 SQL 文本。
- `sqlguard`：SQL 安全层。只读校验、危险关键字、表白名单、JOIN/IN/LIMIT 限制，
              权限条件下推到最内层 WHERE。`guard()` 是推荐的一站式入口。
- `values`  ：值层校验。长度、控制字符、NUL、NaN/Inf、整数范围 —— 结构合法不等于值干净。

- `policy`  ：把护栏收成一个 `GuardPolicy`，生产环境按业务配置，而不是散落的常量。
"""

from . import expr, policy, sqlguard, values
from .errors import DslGuardError, ExprError
from .expr import evaluate, parse, to_sql, to_sql_with_params, whitelist_info
from .policy import DEFAULT_POLICY, DENY_FUNCTIONS, DENY_KEYWORDS, STRICT_POLICY, GuardPolicy
from .sqlguard import GuardResult, SqlRejected, Violation, guard
from .values import (
    MAX_LIST_LEN,
    MAX_STR_LEN,
    ValueRejected,
    check_list,
    check_value,
    is_clean,
)

__version__ = "0.2.0"

__all__ = [
    "expr",
    "sqlguard",
    "values",
    "policy",
    "parse",
    "to_sql",
    "to_sql_with_params",
    "evaluate",
    "whitelist_info",
    "guard",
    "GuardResult",
    "Violation",
    "GuardPolicy",
    "DEFAULT_POLICY",
    "STRICT_POLICY",
    "DENY_FUNCTIONS",
    "DENY_KEYWORDS",
    "check_value",
    "check_list",
    "is_clean",
    "MAX_STR_LEN",
    "MAX_LIST_LEN",
    "DslGuardError",
    "ExprError",
    "SqlRejected",
    "ValueRejected",
    "__version__",
]
