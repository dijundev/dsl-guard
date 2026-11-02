"""统一异常。"""


class DslGuardError(Exception):
    """本库所有异常的基类。"""

    code = 5000

    def __init__(self, message, code=None):
        super().__init__(message)
        self.message = message
        if code is not None:
            self.code = code


class ExprError(DslGuardError):
    """表达式解析 / 求值错误（含被白名单拦截）。"""

    code = 4001
