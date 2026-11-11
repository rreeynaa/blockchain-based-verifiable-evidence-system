"""POST /auth/login."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.audit import audit
from api.deps import get_db
from api.models import User
from api.schemas import LoginRequest, TokenResponse
from api.security import create_token, hash_password, verify_password
from core.config import get_settings

router = APIRouter(prefix="/auth", tags=["auth"])
_DUMMY = hash_password("dummy")  # equalise timing for unknown usernames


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    """Exchange username/password for a JWT carrying the user's role."""
    user = db.scalar(select(User).where(User.username == body.username))
    ok = verify_password(body.password, user.password_hash if user else _DUMMY)
    if not user or not ok:
        audit(db, None, "LOGIN_FAILED", actor=body.username, result="FAIL")
        raise HTTPException(401, "Invalid username or password")
    token = create_token(user.username, user.role)
    audit(db, None, "LOGIN", actor=user.username, role=user.role, result="OK")
    return TokenResponse(
        access_token=token, role=user.role, expires_in=get_settings().jwt_expire_minutes * 60
    )
