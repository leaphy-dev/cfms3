class AppException(Exception):
    """基础异常类型"""
    code = 500
    message = "服务器内部错误"


class AuthenticationError(AppException):
    code = 401
    message = "认证失败"


class AuthorizationError(AppException):
    code = 403
    message = "权限不足"


class InvalidTokenError(AuthenticationError):
    code = 401
    message = "无效令牌"


class TokenExpiredError(InvalidTokenError):
    message = "令牌已过期"


class PermissionDeniedError(AuthorizationError):
    message = "操作权限不足"


class ResourceNotFoundError(AppException):
    code = 404
    message = "资源不存在"


...
