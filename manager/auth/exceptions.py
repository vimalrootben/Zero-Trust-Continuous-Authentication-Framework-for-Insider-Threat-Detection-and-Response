class AuthException(Exception):
    """Base exception for authentication and authorization errors."""
    default_message = "Authentication error"
    status_code = 401

    def __init__(self, message: str = None):
        super().__init__(message or self.default_message)
        self.message = message or self.default_message


class InvalidCredentialsError(AuthException):
    default_message = "Invalid username or password"
    status_code = 401


class AccountLockedError(AuthException):
    default_message = "Account is locked due to too many failed login attempts. Try again in 15 minutes."
    status_code = 401


class AccountInactiveError(AuthException):
    default_message = "Account is inactive. Please contact your system administrator."
    status_code = 403


class MFARequiredError(AuthException):
    default_message = "Multi-factor authentication code is required"
    status_code = 401

    def __init__(self, message: str = None, user_id: str = None):
        super().__init__(message or self.default_message)
        self.user_id = user_id


class InvalidMFACodeError(AuthException):
    default_message = "Invalid multi-factor authentication code"
    status_code = 401


class InvalidRefreshTokenError(AuthException):
    default_message = "Invalid or expired refresh token"
    status_code = 401


class ExpiredTokenError(AuthException):
    default_message = "Access token has expired"
    status_code = 401


class InvalidTokenError(AuthException):
    default_message = "Invalid access token"
    status_code = 401


class WeakPasswordError(AuthException):
    default_message = "Password does not meet complexity requirements"
    status_code = 400


class PermissionDeniedError(AuthException):
    default_message = "Permission denied"
    status_code = 403


class RoleNotFoundError(AuthException):
    default_message = "Role not found"
    status_code = 404
