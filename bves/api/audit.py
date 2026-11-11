"""Audit-log helper."""

from __future__ import annotations

from sqlalchemy.orm import Session

from api.deps import CurrentUser
from api.models import AuditLog


def audit(
    db: Session,
    user: CurrentUser | None,
    action: str,
    *,
    actor: str | None = None,
    role: str = "-",
    batch_id: int | None = None,
    tx_hash: str | None = None,
    result: str | None = None,
    detail: str = "",
) -> None:
    """Append an audit row and commit it."""
    db.add(
        AuditLog(
            actor=user.username if user else (actor or "anonymous"),
            role=user.role if user else role,
            action=action,
            batch_id=batch_id,
            tx_hash=tx_hash,
            result=result,
            detail=detail[:2000],
        )
    )
    db.commit()
