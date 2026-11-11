"""FastAPI application factory."""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from cryptography.exceptions import InvalidTag
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import select
from starlette.exceptions import HTTPException as StarletteHTTPException

from api.db import Base, make_engine, make_session_factory
from api.logging_conf import configure_logging
from api.models import User
from api.routes import auth, evidence, system
from api.security import hash_password
from api.sync import reconcile
from core.config import get_settings
from core.crypto import LocalFileKeyProvider
from core.errors import (
    BVESError,
    ChainError,
    IntegrityError,
    InvalidEvidenceError,
    IPFSError,
    NotFoundError,
)

log = logging.getLogger("bves.api")

DESCRIPTION = """
**BVES** anchors cloud-intrusion logs on a local Ethereum chain.

The database is only a cache. `/evidence/verify` and `/evidence/{id}` always read the chain.

Log in at `POST /auth/login`, then use the **Authorize** button with the returned token.
Demo users: `investigator`, `auditor`, `admin` (passwords in `.env`).
"""


def _seed_users(db) -> None:  # type: ignore[no-untyped-def]
    s = get_settings()
    for name, pw in (
        ("investigator", s.investigator_password),
        ("auditor", s.auditor_password),
        ("admin", s.admin_password),
    ):
        if not db.scalar(select(User).where(User.username == name)):
            db.add(User(username=name, password_hash=hash_password(pw), role=name))
    db.commit()


def create_app(chain=None, ipfs=None, keys=None, engine=None) -> FastAPI:  # type: ignore[no-untyped-def]
    """Build the app. Pass fakes for tests; production wiring happens in the lifespan."""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        configure_logging()
        s = get_settings()
        if s.jwt_secret.startswith("change-me"):
            log.warning("JWT_SECRET is the placeholder value; set a real one in .env")
        eng = engine or make_engine(s.database_url)
        app.state.session_factory = make_session_factory(eng)
        if engine is not None:  # tests use create_all; prod uses Alembic
            Base.metadata.create_all(eng)
        if chain is None:
            from core.chain import Web3Chain

            Web3Chain.wait_for_deployment(s.deployment_file)
            app.state.chain = Web3Chain(s.rpc_url, s.deployment_file, s.signer_private_key)
        else:
            app.state.chain = chain
        if ipfs is None:
            from core.ipfs import IPFSClient

            app.state.ipfs = IPFSClient(s.ipfs_api_url)
        else:
            app.state.ipfs = ipfs
        app.state.keys = keys or LocalFileKeyProvider.from_settings(s.master_key_file, s.master_key_b64)
        with app.state.session_factory() as db:
            _seed_users(db)
            reconcile(db, app.state.chain)
        log.info("BVES API ready")
        yield

    app = FastAPI(title="BVES API", version="0.1.0", description=DESCRIPTION, lifespan=lifespan)

    @app.middleware("http")
    async def request_log(request: Request, call_next):  # type: ignore[no-untyped-def]
        rid = request.headers.get("x-request-id", uuid.uuid4().hex[:12])
        request.state.request_id = rid
        t0 = time.perf_counter()
        response = await call_next(request)
        response.headers["x-request-id"] = rid
        log.info("request", extra={
            "request_id": rid, "method": request.method, "path": request.url.path,
            "status": response.status_code,
            "duration_ms": round((time.perf_counter() - t0) * 1000, 1),
        })
        return response

    def err(request: Request, status: int, code: str, message: str) -> JSONResponse:
        rid = getattr(request.state, "request_id", None)
        return JSONResponse(
            status_code=status,
            content={"error": {"code": code, "message": message, "request_id": rid}},
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_exc(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        resp = err(request, exc.status_code, "http_error", str(exc.detail))
        if exc.headers:
            resp.headers.update(exc.headers)
        return resp

    @app.exception_handler(RequestValidationError)
    async def validation_exc(request: Request, exc: RequestValidationError) -> JSONResponse:
        msg = "; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors())
        return err(request, 422, "validation_error", msg)

    @app.exception_handler(NotFoundError)
    async def nf(request: Request, exc: NotFoundError) -> JSONResponse:
        return err(request, 404, "not_found", str(exc))

    @app.exception_handler(InvalidEvidenceError)
    async def bad(request: Request, exc: InvalidEvidenceError) -> JSONResponse:
        return err(request, 422, "invalid_evidence", str(exc))

    @app.exception_handler(IntegrityError)
    async def integ(request: Request, exc: IntegrityError) -> JSONResponse:
        return err(request, 409, "integrity_failure", str(exc))

    @app.exception_handler(InvalidTag)
    async def tag(request: Request, exc: InvalidTag) -> JSONResponse:
        return err(request, 409, "integrity_failure",
                   "Stored ciphertext failed authentication: the encrypted file or key is not intact.")

    @app.exception_handler(ChainError)
    async def chain_err(request: Request, exc: ChainError) -> JSONResponse:
        status = 409 if "duplicate" in str(exc) else 502
        return err(request, status, "chain_error", str(exc))

    @app.exception_handler(IPFSError)
    async def ipfs_err(request: Request, exc: IPFSError) -> JSONResponse:
        return err(request, 502, "ipfs_error", str(exc))

    @app.exception_handler(BVESError)
    async def domain(request: Request, exc: BVESError) -> JSONResponse:
        return err(request, 400, "bves_error", str(exc))

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled error", extra={"request_id": getattr(request.state, "request_id", None)})
        return err(request, 500, "internal_error", "Internal server error")

    app.include_router(auth.router)
    app.include_router(evidence.router)
    app.include_router(system.router)
    return app


app = create_app()
