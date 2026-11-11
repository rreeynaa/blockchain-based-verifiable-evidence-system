"""FastAPI dependencies: DB session, services, authentication, RBAC."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass

import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from api.security import decode_token
from core.pipeline import EvidencePipeline
from core.types import ChainClient

bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class CurrentUser:
    """Authenticated principal."""

    username: str
    role: str


def get_db(request: Request) -> Iterator[Session]:
    """Yield a DB session."""
    db = request.app.state.session_factory()
    try:
        yield db
    finally:
        db.close()


def get_chain(request: Request) -> ChainClient:
    """Chain client singleton."""
    return request.app.state.chain


def get_pipeline(request: Request) -> EvidencePipeline:
    """Pipeline built from app-level services."""
    s = request.app.state
    return EvidencePipeline(s.chain, s.ipfs, s.keys)


def current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(bearer),
) -> CurrentUser:
    """Resolve the bearer token to a user or raise 401."""
    if creds is None:
        raise HTTPException(401, "Not authenticated", headers={"WWW-Authenticate": "Bearer"})
    try:
        claims = decode_token(creds.credentials)
    except jwt.PyJWTError as exc:
        raise HTTPException(
            401, "Invalid or expired token", headers={"WWW-Authenticate": "Bearer"}
        ) from exc
    return CurrentUser(claims["sub"], claims["role"])


def require_roles(*roles: str) -> Callable[..., CurrentUser]:
    """Dependency factory enforcing that the caller has one of ``roles``."""

    def checker(user: CurrentUser = Depends(current_user)) -> CurrentUser:
        if user.role not in roles:
            raise HTTPException(403, f"Role '{user.role}' may not perform this action")
        return user

    return checker
