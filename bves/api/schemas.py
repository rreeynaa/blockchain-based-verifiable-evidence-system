"""Pydantic v2 request/response models."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    """Credentials."""

    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class TokenResponse(BaseModel):
    """JWT bearer token."""

    access_token: str
    token_type: str = "bearer"
    role: str
    expires_in: int


class ProofStepOut(BaseModel):
    """One Merkle proof step."""

    sibling: str
    position: Literal["left", "right"]


class FileOut(BaseModel):
    """File as anchored in a batch."""

    index: int
    filename: str
    size: int | None = None
    file_hash: str
    cid: str
    merkle_proof: list[ProofStepOut] = []


class SubmitResponse(BaseModel):
    """Result of POST /evidence/submit."""

    batch_id: int
    case_id: str
    merkle_root: str
    tx_hash: str
    block_number: int
    gas_used: int
    timestamp: int
    files: list[FileOut]
    timings_ms: dict[str, float]


class BatchSummary(BaseModel):
    """Row in the batch list."""

    batch_id: int
    case_id: str
    merkle_root: str
    tx_hash: str
    block_number: int
    timestamp: int
    file_count: int
    created_by: str


class BatchDetail(BaseModel):
    """Batch read from the chain (source of truth) plus cached filenames."""

    batch_id: int
    case_id: str
    merkle_root: str
    timestamp: int
    submitter: str
    current_custodian: str
    file_count: int
    tx_hash: str | None
    block_number: int | None
    root_consistent: bool
    files: list[FileOut]


class CustodyEntryOut(BaseModel):
    """One chain-of-custody entry."""

    from_addr: str
    to_addr: str
    reason: str
    timestamp: int


class TransferRequest(BaseModel):
    """Custody transfer request."""

    new_custodian: str = Field(pattern=r"^0x[0-9a-fA-F]{40}$")
    reason: str = Field(min_length=1, max_length=500)


class TransferResponse(BaseModel):
    """Result of a custody transfer."""

    batch_id: int
    tx_hash: str
    block_number: int
    new_custodian: str


class VerifyResponse(BaseModel):
    """Verification outcome."""

    status: Literal["VERIFIED", "TAMPERED", "NOT_FOUND"]
    detail: str
    batch_id: int | None = None
    case_id: str | None = None
    file_index: int | None = None
    cid: str | None = None
    expected_hash: str | None = None
    computed_hash: str
    hash_match: bool | None = None
    onchain_hash_check: bool | None = None
    onchain_root: str | None = None
    recomputed_root: str | None = None
    inclusion_valid: bool | None = None
    root_consistent: bool | None = None
    merkle_proof: list[ProofStepOut] = []
    tx_hash: str | None = None
    block_number: int | None = None
    timestamp: int | None = None
    submitter: str | None = None


class AuditLogOut(BaseModel):
    """Audit log row."""

    id: int
    ts: datetime
    actor: str
    role: str
    action: str
    batch_id: int | None
    tx_hash: str | None
    result: str | None
    detail: str

    model_config = {"from_attributes": True}


class StatsOut(BaseModel):
    """Dashboard counters."""

    batches: int
    files: int
    verifications_passed: int
    verifications_failed: int
