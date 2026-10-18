
"""
FolderDB AI Agent - FastAPI Application Entry Point

Location:
    backend/app/main.py

Run from:
    D:\\AI agent

Command:
    python -m uvicorn backend.app.main:app --reload
"""

from contextlib import asynccontextmanager
from datetime import datetime, timezone
import logging
import os
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from backend.app.api.assistant import router as assistant_router
from backend.app.api.event import router as event_router


# =========================================================
# 1. LOGGING
# =========================================================

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format=(
        "%(asctime)s | %(levelname)s | "
        "%(name)s | %(message)s"
    ),
)

logger = logging.getLogger("folderdb-agent")


# =========================================================
# 2. APPLICATION CONFIGURATION
# =========================================================

APP_NAME = "FolderDB AI Agent"
APP_VERSION = os.getenv("APP_VERSION", "1.0.0")
API_PREFIX = "/api/v1"


# =========================================================
# 3. OPTIONAL PROJECT SETTINGS
# =========================================================

try:
    from backend.app.config import settings

    logger.info("Project configuration loaded successfully.")

except ImportError:
    settings = None

    logger.warning(
        "Project settings unavailable. "
        "Using environment-based defaults."
    )


def get_setting(*names: str) -> Any:
    """Read the first available setting from project configuration."""
    if settings is None:
        return None

    for name in names:
        value = getattr(settings, name, None)

        if value is not None:
            return value

    return None


def get_cors_origins() -> list[str]:
    """Resolve allowed frontend origins."""

    configured_origins = get_setting(
        "cors_origins",
        "CORS_ORIGINS",
        "allowed_origins",
    )

    if configured_origins is None:
        configured_origins = os.getenv(
            "CORS_ORIGINS",
            "http://localhost:3000,http://localhost:5173,https://falkordb.vercel.app",
        )

    if isinstance(configured_origins, str):
        origins = configured_origins.split(",")

    elif isinstance(configured_origins, (list, tuple, set)):
        origins = list(configured_origins)

    else:
        logger.warning(
            "Invalid CORS configuration. Using local defaults."
        )
        origins = [
            "http://localhost:3000",
            "http://localhost:5173",
        ]

    result = [
        str(origin).strip().rstrip("/")
        for origin in origins
        if str(origin).strip()
    ]

    if "*" in result:
        logger.warning(
            "Wildcard CORS origin configured. "
            "Use explicit trusted origins in production."
        )

    return result


# =========================================================
# 4. RESPONSE MODELS
# =========================================================

class HealthResponse(BaseModel):
    status: str
    application: str
    version: str
    timestamp: datetime


class ReadinessResponse(BaseModel):
    status: str
    application: str
    database: str
    timestamp: datetime


class ErrorResponse(BaseModel):
    detail: Any


# =========================================================
# 5. APPLICATION LIFECYCLE
# =========================================================

@asynccontextmanager
async def lifespan(application: FastAPI):
    """
    Initialize application state on startup and clean up on shutdown.

    Database initialization is intentionally not simulated.
    Integrate your actual FalkorDB connection manager here
    if your project requires explicit startup initialization.
    """

    application.state.started_at = datetime.now(timezone.utc)
    application.state.ready = False

    logger.info("%s is starting.", APP_NAME)

    try:
        # The API can serve requests after its application
        # startup completes. Database connectivity is checked
        # separately and is not assumed here.
        application.state.ready = True

        logger.info(
            "%s startup completed successfully.",
            APP_NAME,
        )

        yield

    except Exception:
        logger.exception("Application lifecycle error.")
        raise

    finally:
        application.state.ready = False

        logger.info(
            "%s is shutting down.",
            APP_NAME,
        )


# =========================================================
# 6. FASTAPI APPLICATION
# =========================================================

app = FastAPI(
    title=APP_NAME,
    description=(
        "API for the FolderDB AI Agent, including security "
        "event ingestion, graph analysis, attack paths, "
        "threat detection, investigations, case management, "
        "audit operations, and AI assistant services."
    ),
    version=APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)


# =========================================================
# 7. CORS MIDDLEWARE
# =========================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_cors_origins(),
    allow_credentials=True,
    allow_methods=[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
    ],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "Accept",
        "Origin",
        "X-Request-ID",
    ],
)


# =========================================================
# 8. API ROUTERS
# =========================================================

app.include_router(
    assistant_router,
    prefix=API_PREFIX,
)

app.include_router(
    event_router,
    prefix=API_PREFIX,
)

logger.info("Assistant router registered at %s.", API_PREFIX)
logger.info("Event router registered at %s.", API_PREFIX)


# =========================================================
# 9. ROOT ENDPOINT
# =========================================================

@app.get(
    "/",
    tags=["System"],
    summary="Application information",
)
async def root() -> dict[str, Any]:
    """Return basic information about the running application."""

    return {
        "application": APP_NAME,
        "version": APP_VERSION,
        "status": "running",
        "docs": "/docs",
        "redoc": "/redoc",
        "health": "/health",
        "readiness": "/ready",
        "api_prefix": API_PREFIX,
    }


# =========================================================
# 10. LIVENESS / HEALTH CHECK
# =========================================================

@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["System"],
    summary="Check API health",
)
async def health_check() -> HealthResponse:
    """
    Confirm that the FastAPI process is responding.

    This endpoint does not verify FalkorDB or AI provider access.
    """

    return HealthResponse(
        status="healthy",
        application=APP_NAME,
        version=APP_VERSION,
        timestamp=datetime.now(timezone.utc),
    )


# =========================================================
# 11. READINESS CHECK
# =========================================================

@app.get(
    "/ready",
    response_model=ReadinessResponse,
    tags=["System"],
    summary="Check application readiness",
)
async def readiness_check(request: Request) -> ReadinessResponse:
    """
    Report application startup status.

    Database status remains not_checked until a real database
    connectivity check is integrated.
    """

    if not getattr(request.app.state, "ready", False):
        raise HTTPException(
            status_code=503,
            detail="Application is not ready.",
        )

    return ReadinessResponse(
        status="ready",
        application=APP_NAME,
        database="not_checked",
        timestamp=datetime.now(timezone.utc),
    )


# =========================================================
# 12. API INFORMATION
# =========================================================

@app.get(
    f"{API_PREFIX}/info",
    tags=["System"],
    summary="Get API information",
)
async def api_info() -> dict[str, Any]:
    """Describe the API and its registered modules."""

    routes = []

    for route in app.routes:
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None)

        if path and methods:
            routes.append(
                {
                    "path": path,
                    "methods": sorted(
                        method
                        for method in methods
                        if method not in {"HEAD", "OPTIONS"}
                    ),
                }
            )

    return {
        "name": APP_NAME,
        "version": APP_VERSION,
        "api_prefix": API_PREFIX,
        "documentation": "/docs",
        "openapi": "/openapi.json",
        "endpoints": {
            "root": "/",
            "health": "/health",
            "readiness": "/ready",
            "api_info": f"{API_PREFIX}/info",
        },
        "modules": [
            "graph_analysis",
            "attack_paths",
            "detection",
            "case_management",
            "audit",
            "ingestion",
            "AI_services",
        ],
        "registered_routes": routes,
    }


# =========================================================
# 13. HTTP EXCEPTION HANDLER
# =========================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(
    request: Request,
    exc: HTTPException,
) -> JSONResponse:
    """Return consistent HTTP error responses."""

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "detail": exc.detail,
        },
        headers=exc.headers,
    )


# =========================================================
# 14. REQUEST VALIDATION ERROR HANDLER
# =========================================================

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    """Return a clear 422 response for invalid request data."""

    errors = []

    for error in exc.errors():
        errors.append(
            {
                "location": list(error.get("loc", ())),
                "message": error.get("msg", "Invalid input"),
                "type": error.get("type", "validation_error"),
            }
        )

    return JSONResponse(
        status_code=422,
        content={
            "detail": "Request validation failed.",
            "errors": errors,
        },
    )


# =========================================================
# 15. UNEXPECTED ERROR HANDLER
# =========================================================

@app.exception_handler(Exception)
async def unhandled_exception_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    """
    Log unexpected server errors without disclosing internals
    to the API client.
    """

    logger.exception(
        "Unhandled error on %s %s",
        request.method,
        request.url.path,
    )

    return JSONResponse(
        status_code=500,
        content={
            "detail": "An internal server error occurred."
        },
    )


# =========================================================
# 16. APPLICATION ENTRY POINT
# =========================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "backend.app.main:app",
        host=os.getenv("HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "8000")),
        reload=os.getenv("RELOAD", "true").lower() == "true",
        log_level=LOG_LEVEL.lower(),
    )
