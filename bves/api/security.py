"""Password hashing (stdlib scrypt) and JWT helpers."""

from __future__ import annotations

import hashlib
import hmac
import os
from datetime import datetime, timedelta, timezone

import jwt

from core.config import get_settings

ROLES = ("investigator", "auditor", "admin")
_N, _R, _P = 2**14, 8, 1


def hash_password(password: str) -> str:
    """Return ``scrypt$salt$hash`` (hex)."""
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P)
    return f"scrypt${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time password check."""
    try:
        _, salt_hex, hash_hex = stored.split("$")
        dk = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), n=_N, r=_R, p=_P)
        return hmac.compare_digest(dk.hex(), hash_hex)
    except ValueError:
        return False


def create_token(username: str, role: str) -> str:
    """Issue a signed JWT."""
    s = get_settings()
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now + timedelta(minutes=s.jwt_expire_minutes),
    }
    return jwt.encode(payload, s.jwt_secret, algorithm="HS256")


def decode_token(token: str) -> dict:
    """Decode and validate a JWT (raises ``jwt.PyJWTError``)."""
    return jwt.decode(token, get_settings().jwt_secret, algorithms=["HS256"])
