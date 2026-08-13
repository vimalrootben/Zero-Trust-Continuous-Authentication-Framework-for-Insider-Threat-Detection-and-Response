"""
Agent Registration & Heartbeat custom exceptions.
"""
from manager.auth.exceptions import AuthException


class AgentException(Exception):
    """Base class for all agent-related exceptions."""
    def __init__(self, message: str):
        self.message = message
        super().__init__(message)


class TokenExpiredError(AgentException):
    pass


class TokenExhaustedError(AgentException):
    pass


class TokenRevokedError(AgentException):
    pass


class TokenNotFoundError(AgentException):
    pass


class DuplicateAgentError(AgentException):
    pass


class InvalidCSRError(AgentException):
    pass


class AgentNotFoundError(AgentException):
    pass
