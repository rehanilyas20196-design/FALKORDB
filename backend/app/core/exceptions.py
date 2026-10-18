
from typing import Any


class GraphGuardException(Exception):
    """Base exception for GraphGuard AI."""

    def __init__(
        self,
        message: str = "An unexpected application error occurred.",
        status_code: int = 500,
        details: Any = None,
    ):
        self.message = message
        self.status_code = status_code
        self.details = details
        super().__init__(message)


class ConfigurationException(GraphGuardException):
    """Raised when application configuration is invalid."""

    def __init__(
        self,
        message: str = "Application configuration error.",
        details: Any = None,
    ):
        super().__init__(
            message=message,
            status_code=500,
            details=details,
        )


class DatabaseException(GraphGuardException):
    """Raised when a database operation fails."""

    def __init__(
        self,
        message: str = "Database operation failed.",
        details: Any = None,
    ):
        super().__init__(
            message=message,
            status_code=503,
            details=details,
        )


class ResourceNotFoundException(GraphGuardException):
    """Raised when a requested resource does not exist."""

    def __init__(
        self,
        resource: str = "Resource",
        resource_id: str | None = None,
    ):
        message = f"{resource} was not found."

        if resource_id:
            message = f"{resource} '{resource_id}' was not found."

        super().__init__(
            message=message,
            status_code=404,
        )


class ValidationException(GraphGuardException):
    """Raised when supplied data is invalid."""

    def __init__(
        self,
        message: str = "Request validation failed.",
        details: Any = None,
    ):
        super().__init__(
            message=message,
            status_code=422,
            details=details,
        )


class AuthenticationException(GraphGuardException):
    """Raised when authentication fails."""

    def __init__(
        self,
        message: str = "Authentication required.",
    ):
        super().__init__(
            message=message,
            status_code=401,
        )


class AuthorizationException(GraphGuardException):
    """Raised when a user lacks permission."""

    def __init__(
        self,
        message: str = "You do not have permission to perform this action.",
    ):
        super().__init__(
            message=message,
            status_code=403,
        )


class DetectionException(GraphGuardException):
    """Raised when a threat detection operation fails."""

    def __init__(
        self,
        message: str = "Threat detection failed.",
        details: Any = None,
    ):
        super().__init__(
            message=message,
            status_code=500,
            details=details,
        )


class InvestigationException(GraphGuardException):
    """Raised when an alert investigation fails."""

    def __init__(
        self,
        message: str = "Alert investigation failed.",
        details: Any = None,
    ):
        super().__init__(
            message=message,
            status_code=500,
            details=details,
        )


class AIServiceException(GraphGuardException):
    """Raised when an AI service operation fails."""

    def __init__(
        self,
        message: str = "AI service is unavailable.",
        details: Any = None,
    ):
        super().__init__(
            message=message,
            status_code=503,
            details=details,
        )


class RateLimitException(GraphGuardException):
    """Raised when a client exceeds a request limit."""

    def __init__(
        self,
        message: str = "Too many requests. Please try again later.",
    ):
        super().__init__(
            message=message,
            status_code=429,
        )


def exception_to_dict(
    exc: GraphGuardException,
    include_details: bool = False,
) -> dict[str, Any]:
    """Convert a GraphGuard exception into a response-friendly dictionary."""
    response: dict[str, Any] = {
        "error": True,
        "type": type(exc).__name__,
        "message": exc.message,
        "status_code": exc.status_code,
    }

    # Details may contain internal information, so omit them by default.
    if include_details and exc.details is not None:
        response["details"] = exc.details

    return response
