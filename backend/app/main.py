import logging
import time
from collections import OrderedDict
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware
from sqlalchemy.exc import IntegrityError
from app.config import Settings
from app.db import database
from app.security.crypto import Vault
from app.api import auth, devices, policies, agent, mikrotik, deployments, ssh, operations, maintenance, identities, groups, infrastructure, diagnostics, profiles, inventory, credentials

log = logging.getLogger("lantern")


def create_app(settings=None):
    settings = settings or Settings()
    engine, sessions = database(settings.database_url)
    app = FastAPI(title="Suro LAN Management", version="0.1.0", docs_url="/api/docs", openapi_url="/api/openapi.json")
    app.state.settings, app.state.engine, app.state.sessions = settings, engine, sessions
    app.state.vault = Vault(settings)
    from app.services.transfers import TransferBudget
    app.state.transfers=TransferBudget()
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.trusted_hosts.split(","))
    buckets = OrderedDict()

    @app.middleware("http")
    async def boundary(request: Request, call_next):
        started = time.monotonic()
        ip = request.client.host if request.client else "unknown"
        category = "login" if request.url.path.endswith(("/login", "/enroll")) else "api"
        key = (ip, category)
        now = time.monotonic()
        count, until = buckets.get(key, (0, now + 60))
        if until < now:
            count, until = 0, now + 60
        buckets[key] = (count + 1, until)
        buckets.move_to_end(key)
        if len(buckets) > 10000:
            buckets.popitem(last=False)
        if count >= (15 if category == "login" else 600):
            return JSONResponse({"error": {"code": "request.rate_limited"}}, 429, headers={"Retry-After": "60"})
        # Streaming receive cap also handles missing or dishonest Content-Length.
        max_body = settings.upload_chunk_bytes if "/packages/uploads/" in request.url.path and request.method == "PUT" else 1024 * 1024
        original_receive, received = request._receive, 0
        async def receive():
            nonlocal received
            message = await original_receive()
            received += len(message.get("body", b""))
            if received > max_body:
                raise HTTPException(413, "request.too_large")
            return message
        request._receive = receive
        try:
            if int(request.headers.get("content-length", "0")) > max_body:
                return JSONResponse({"error": {"code": "request.too_large"}}, 413)
            response = await call_next(request)
        except Exception:
            log.exception("request.failed method=%s path=%s", request.method, request.url.path)
            return JSONResponse({"error": {"code": "request.internal_error"}}, 500)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        log.info("request method=%s path=%s status=%s duration_ms=%.1f", request.method, request.url.path, response.status_code, (time.monotonic() - started) * 1000)
        return response

    @app.exception_handler(HTTPException)
    async def http_error(request, exc):
        return JSONResponse({"error": {"code": exc.detail if isinstance(exc.detail, str) else "request.failed"}}, exc.status_code, headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        # Never echo input (tokens, keys, passwords) in validation responses.
        return JSONResponse({"error": {"code": "request.validation", "fields": [".".join(str(x) for x in e["loc"]) for e in exc.errors()]}}, 422)

    from pydantic import ValidationError
    @app.exception_handler(ValidationError)
    async def typed_operation_error(request, exc):
        return JSONResponse({"error": {"code": "request.validation", "fields": [".".join(str(x) for x in e["loc"]) for e in exc.errors()]}}, 422)

    @app.exception_handler(IntegrityError)
    async def conflict(request, exc):
        return JSONResponse({"error": {"code": "request.conflict"}}, 409)

    from app.policies.resolver import PolicyConflict
    @app.exception_handler(PolicyConflict)
    async def policy_conflict(request, exc):
        return JSONResponse({"error": {"code": "policy.group_conflict", "control": str(exc).split(":", 1)[-1]}}, 409)

    for module in (auth, devices, policies, agent, mikrotik, deployments, ssh, operations, maintenance, identities, groups, infrastructure, diagnostics, profiles, inventory, credentials):
        app.include_router(module.router, prefix="/api/v1")

    @app.get("/healthz")
    def healthz():
        from sqlalchemy import text
        with sessions() as db:
            db.execute(text("SELECT 1"))
        return {"status": "ok"}
    return app
