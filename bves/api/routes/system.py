"""Audit log, dashboard stats and health."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.deps import CurrentUser, get_chain, get_db, require_roles
from api.models import AuditLog, FileCache
from api.schemas import AuditLogOut, StatsOut
from core.types import ChainClient

router = APIRouter(tags=["system"])


@router.get("/audit-log", response_model=list[AuditLogOut], summary="Audit log (auditor, admin)")
def audit_log(
    action: str | None = Query(None, description="Filter by action, e.g. VERIFY"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    _: CurrentUser = Depends(require_roles("auditor", "admin")),
    db: Session = Depends(get_db),
) -> list[AuditLog]:
    """Every action: who, what, when, tx hash. Newest first."""
    stmt = select(AuditLog)
    if action:
        stmt = stmt.where(AuditLog.action == action.upper())
    return list(db.scalars(stmt.order_by(AuditLog.id.desc()).offset(offset).limit(limit)))


@router.get("/stats", response_model=StatsOut, summary="Dashboard counters")
def stats(
    _: CurrentUser = Depends(require_roles("investigator", "auditor", "admin")),
    chain: ChainClient = Depends(get_chain),
    db: Session = Depends(get_db),
) -> StatsOut:
    """Batch count comes from the chain; file/verification counts from the cache/audit log."""

    def count(result: str) -> int:
        return db.scalar(
            select(func.count()).select_from(AuditLog).where(
                AuditLog.action == "VERIFY", AuditLog.result == result
            )
        ) or 0

    return StatsOut(
        batches=chain.batch_count(),
        files=db.scalar(select(func.count()).select_from(FileCache)) or 0,
        verifications_passed=count("VERIFIED"),
        verifications_failed=count("TAMPERED"),
    )


@router.get("/health", summary="Liveness + dependency check")
def health(request_chain: ChainClient = Depends(get_chain)) -> dict:
    """Unauthenticated health probe."""
    try:
        return {"status": "ok", "batches_on_chain": request_chain.batch_count()}
    except Exception as exc:  # noqa: BLE001
        return {"status": "degraded", "chain_error": str(exc)}
