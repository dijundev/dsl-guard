"""dsl-guard —— 配置驱动系统里的两道确定性边界。

- `expr`    ：表达式 DSL。自研递归下降解析器 + AST 白名单，**不开放 eval**。
- `sqlguard`：SQL 安全层。只读校验、危险关键字拦截、权限条件下推到最内层 WHERE。

典型用法：业务方在界面上写一个算式 / 拼一段查询，服务端先过这里，
通过之后才允许生成 SQL 或执行。
"""

from . import expr, sqlguard
from .errors import DslGuardError, ExprError
from .expr import evaluate, parse, to_sql, whitelist_info
from .sqlguard import SqlRejected

__version__ = "0.1.0"

__all__ = [
    "expr",
    "sqlguard",
    "parse",
    "to_sql",
    "evaluate",
    "whitelist_info",
    "DslGuardError",
    "ExprError",
    "SqlRejected",
    "__version__",
]
