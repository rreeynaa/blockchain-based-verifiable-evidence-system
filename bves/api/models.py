"""ORM models. The DB is a *cache/index* only: chain data is the source of truth."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from api.db import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    """API user (scrypt-hashed password)."""

    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    role: Mapped[str] = mapped_column(String(32))


class BatchCache(Base):
    """Cached batch header (``batch_id`` is the on-chain id)."""

    __tablename__ = "batches"
    batch_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    case_id: Mapped[str] = mapped_column(String(64), index=True)
    merkle_root: Mapped[str] = mapped_column(String(64), index=True)
    tx_hash: Mapped[str] = mapped_column(String(66))
    block_number: Mapped[int] = mapped_column(Integer)
    timestamp: Mapped[int] = mapped_column(Integer)
    submitter: Mapped[str] = mapped_column(String(64))
    file_count: Mapped[int] = mapped_column(Integer)
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class FileCache(Base):
    """Cached file record. Holds filenames (which are not stored on-chain)."""

    __tablename__ = "files"
    __table_args__ = (UniqueConstraint("batch_id", "file_index"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    batch_id: Mapped[int] = mapped_column(ForeignKey("batches.batch_id"), index=True)
    file_index: Mapped[int] = mapped_column(Integer)
    filename: Mapped[str] = mapped_column(String(255), index=True)
    size: Mapped[int] = mapped_column(Integer)
    file_hash: Mapped[str] = mapped_column(String(64), index=True)
    cid: Mapped[str] = mapped_column(String(128), index=True)


class AuditLog(Base):
    """Every user action: who, what, when, tx hash."""

    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    actor: Mapped[str] = mapped_column(String(64))
    role: Mapped[str] = mapped_column(String(32))
    action: Mapped[str] = mapped_column(String(32), index=True)
    batch_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tx_hash: Mapped[str | None] = mapped_column(String(66), nullable=True)
    result: Mapped[str | None] = mapped_column(String(16), nullable=True)
    detail: Mapped[str] = mapped_column(Text, default="")
