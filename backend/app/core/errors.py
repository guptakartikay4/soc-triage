"""
Consistent API error handling.

Every error response has the shape::

    {
      "detail": "<human readable message>",       # kept for backward compatibility
      "error": {"code": "...", "message": "...", "details": ...}
    }

Error classes distinguish:
  * validation errors      -> 422 (client input problems)
  * not found / conflict   -> 404 / 409
  * database failures      -> 503 (logged, no internals leaked)
  * unexpected failures    -> 500 (logged with stack trace server-side only)

Note: *security alerts* are data, not errors — a malicious-looking alert is a
perfectly valid input and never raises here.  AI provider failures are not
surfaced as errors at all; the briefing service falls back deterministically.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.exc import SQLAlchemyError
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger("app.errors")


class ErrorBody(BaseModel):
    code: str
    message: str
    details: Optional[Any] = None


class ErrorResponse(BaseModel):
    detail: Any
    error: ErrorBody


class AppError(Exception):
    status_code: int = status.HTTP_400_BAD_REQUEST
    code: str = "bad_request"

    def __init__(self, message: str, *, details: Any = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details


class NotFoundError(AppError):
    status_code = status.HTTP_404_NOT_FOUND
    code = "not_found"


class ConflictError(AppError):
    status_code = status.HTTP_409_CONFLICT
    code = "conflict"


class InvalidRequestError(AppError):
    status_code = status.HTTP_400_BAD_REQUEST
    code = "invalid_request"


def _payload(code: str, message: str, details: Any = None, detail: Any = None) -> dict:
    return jsonable_encoder({
        "detail": detail if detail is not None else message,
        "error": {"code": code, "message": message, "details": details},
    })


def register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def _app_error(_: Request, exc: AppError):
        return JSONResponse(status_code=exc.status_code,
                            content=_payload(exc.code, exc.message, exc.details))

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_: Request, exc: StarletteHTTPException):
        code = {404: "not_found", 405: "method_not_allowed", 409: "conflict"}.get(
            exc.status_code, "http_error")
        message = exc.detail if isinstance(exc.detail, str) else "HTTP error"
        return JSONResponse(status_code=exc.status_code,
                            content=_payload(code, message, detail=exc.detail))

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_: Request, exc: RequestValidationError):
        errors = exc.errors()
        # Drop raw input echo of large bodies; keep loc/msg/type.
        slim = [{"loc": e.get("loc"), "msg": e.get("msg"), "type": e.get("type")} for e in errors]
        return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                            content=_payload("validation_error", "Request validation failed",
                                             details=slim, detail=slim))

    @app.exception_handler(SQLAlchemyError)
    async def _db_error(request: Request, exc: SQLAlchemyError):
        logger.error("database_error path=%s error_type=%s", request.url.path, type(exc).__name__)
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            content=_payload("database_error",
                                             "Database unavailable or not migrated "
                                             "(run `alembic upgrade head`)."))

    @app.exception_handler(Exception)
    async def _unexpected(request: Request, exc: Exception):
        logger.exception("unexpected_error path=%s error_type=%s", request.url.path, type(exc).__name__)
        return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            content=_payload("internal_error", "Internal server error"))
