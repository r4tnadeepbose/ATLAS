from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy import text

from app.api.v1.router import api_router
from app.config import settings
from app.core.exceptions import AppError
from app.core.logging import configure_logging, get_logger
from app.core.middleware import RateLimitMiddleware, RequestContextMiddleware, SecurityHeadersMiddleware
from app.database.models.base import Base
from app.database.session import SessionLocal, engine

configure_logging("DEBUG" if settings.debug else "INFO")
logger = get_logger("app")


def _bootstrap() -> None:
    import app.database.models  # noqa: F401 - register all metadata
    from app.auth.service import ensure_roles_seeded
    from app.core.permissions import Permission
    from app.database.models.identity import Permission as PermissionModel, Role, RolePermission

    # In production the migration job owns schema changes. Local/test/demo
    # environments create missing tables for zero-friction first run.
    if settings.app_env != "production":
        Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        ensure_roles_seeded(db)
        existing = {row.key for row in db.query(PermissionModel).all()}
        for permission in Permission:
            if permission.value not in existing:
                db.add(PermissionModel(key=permission.value, description=permission.value.replace(":", " "), category=permission.value.split(":")[0]))
        db.commit()
        permissions = {row.key: row for row in db.query(PermissionModel).all()}
        from app.core.permissions import ROLE_PERMISSIONS

        for key, permission_keys in ROLE_PERMISSIONS.items():
            role = db.query(Role).filter(Role.key == key, Role.organization_id.is_(None)).first()
            if role is None:
                continue
            current = {link.permission.key for link in db.query(RolePermission).filter(RolePermission.role_id == role.id).all()}
            for permission_key in permission_keys:
                permission = permissions.get(permission_key)
                if permission and permission_key not in current:
                    db.add(RolePermission(role_id=role.id, permission_id=permission.id))
        db.commit()
        if settings.seed_demo_data or settings.app_env == "demo":
            from app.demo.seed import seed_demo_data

            seed_demo_data(db)
    finally:
        db.close()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    _bootstrap()
    logger.info("ATLAS started", extra={"environment": settings.app_env})
    yield
    logger.info("ATLAS stopped")


app = FastAPI(
    title="ATLAS API",
    description="Advanced Threat & Asset Lifecycle Security — enterprise security orchestration and intelligence platform.",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    expose_headers=["X-Request-ID", "X-RateLimit-Remaining"],
)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestContextMiddleware)
app.add_middleware(RateLimitMiddleware, limit_per_minute=settings.rate_limit_per_minute)
if settings.allowed_hosts and settings.allowed_hosts != ["*"]:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)

app.include_router(api_router, prefix=settings.api_prefix)


@app.exception_handler(AppError)
async def app_error_handler(_request: Request, exc: AppError) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content=exc.detail)


@app.exception_handler(RequestValidationError)
async def validation_error_handler(_request: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content={
            "error": "validation_error",
            "message": "Request validation failed",
            "details": [
                {"field": ".".join(str(part) for part in error.get("loc", [])), "message": error.get("msg")}
                for error in exc.errors()
            ],
        },
    )


@app.get("/health", tags=["Health"])
def health() -> dict:
    return {"status": "ok", "service": "atlas-api", "environment": settings.app_env, "version": "1.0.0"}


@app.get("/health/live", tags=["Health"])
def live() -> dict:
    return {"status": "alive"}


@app.get("/health/ready", tags=["Health"])
def ready() -> JSONResponse:
    checks = {"database": False, "redis": None, "broker": None}
    try:
        db = SessionLocal()
        db.execute(text("SELECT 1"))
        db.close()
        checks["database"] = True
    except Exception as exc:  # noqa: BLE001
        logger.error("database readiness failed: %s", exc)
    if settings.redis_url:
        try:
            import redis

            redis.Redis.from_url(settings.redis_url, socket_timeout=2).ping()
            checks["redis"] = True
        except Exception:  # noqa: BLE001
            checks["redis"] = False
    status = "ready" if checks["database"] else "not_ready"
    return JSONResponse(status_code=200 if checks["database"] else 503, content={"status": status, "checks": checks})


@app.get("/metrics", tags=["Health"], response_class=PlainTextResponse)
def metrics() -> str:
    from app.core.metrics import snapshot

    data = snapshot()
    lines = []
    for key, value in data["counters"].items():
        lines.append(f"atlas_{key} {value}")
    for key, value in data["gauges"].items():
        lines.append(f"atlas_{key} {value}")
    return "\n".join(lines) + "\n"
