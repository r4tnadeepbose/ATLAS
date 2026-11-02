from typing import Any

from fastapi import HTTPException, status


class AppError(HTTPException):
    code = "error"
    status_code = status.HTTP_400_BAD_REQUEST

    def __init__(self, message: str, *, details: Any = None, code: str | None = None):
        payload: dict[str, Any] = {"error": code or self.code, "message": message}
        if details is not None:
            payload["details"] = details
        super().__init__(status_code=self.status_code, detail=payload)


class NotFoundError(AppError):
    code = "not_found"
    status_code = status.HTTP_404_NOT_FOUND


class ConflictError(AppError):
    code = "conflict"
    status_code = status.HTTP_409_CONFLICT


class ForbiddenError(AppError):
    code = "forbidden"
    status_code = status.HTTP_403_FORBIDDEN


class ValidationError(AppError):
    code = "validation_error"
    status_code = 422


class ScopeViolationError(AppError):
    code = "scope_violation"
    status_code = status.HTTP_403_FORBIDDEN


class IntegrationError(AppError):
    code = "integration_error"
    status_code = status.HTTP_502_BAD_GATEWAY


class UnauthorizedError(AppError):
    code = "unauthorized"
    status_code = status.HTTP_401_UNAUTHORIZED
