"""Evidence endpoints."""

from __future__ import annotations

import io
import logging
import os
import re
import zipfile

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import Response
from sqlalchemy import or_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from api.audit import audit
from api.deps import CurrentUser, get_chain, get_db, get_pipeline, require_roles
from api.models import BatchCache, FileCache
from api.schemas import (
    BatchDetail,
    BatchSummary,
    CustodyEntryOut,
    FileOut,
    SubmitResponse,
    TransferRequest,
    TransferResponse,
    VerifyResponse,
)
from core.crypto import build_tree, sha256_bytes
from core.errors import NotFoundError
from core.pipeline import EvidencePipeline
from core.types import ChainClient
from core.verify import find_file_on_chain, verify_evidence

log = logging.getLogger(__name__)
router = APIRouter(prefix="/evidence", tags=["evidence"])

ANY_ROLE = require_roles("investigator", "auditor", "admin")
INVESTIGATOR = require_roles("investigator")
VERIFIER = require_roles("investigator", "auditor", "admin")

MAX_FILE_BYTES = 25 * 1024 * 1024
MAX_FILES = 100
CASE_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def _safe_name(name: str | None, fallback: str) -> str:
    base = os.path.basename((name or "").replace("\\", "/")).strip()
    return re.sub(r"[^\w.\- ]", "_", base)[:200] or fallback


def _read_limited(f: UploadFile) -> bytes:
    data = f.file.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise HTTPException(413, f"'{f.filename}' exceeds {MAX_FILE_BYTES // (1024 * 1024)} MiB")
    return data


# ------------------------------------------------------------------------ submit
@router.post("/submit", response_model=SubmitResponse, summary="Submit evidence (investigator)")
def submit(
    case_id: str = Form(..., description="Case identifier, e.g. CASE-2026-001"),
    files: list[UploadFile] = File(...),
    user: CurrentUser = Depends(INVESTIGATOR),
    pipeline: EvidencePipeline = Depends(get_pipeline),
    db: Session = Depends(get_db),
) -> SubmitResponse:
    """Hash -> Merkle -> encrypt -> IPFS -> register on-chain -> cache in DB."""
    if not CASE_RE.match(case_id):
        raise HTTPException(422, "case_id must match [A-Za-z0-9._-]{1,64}")
    if not files or len(files) > MAX_FILES:
        raise HTTPException(422, f"provide between 1 and {MAX_FILES} files")
    payload = [
        (_safe_name(f.filename, f"file-{i}"), _read_limited(f)) for i, f in enumerate(files)
    ]
    result = pipeline.submit(case_id, payload)
    r = result.receipt
    try:
        db.add(
            BatchCache(
                batch_id=result.batch_id, case_id=case_id, merkle_root=result.merkle_root,
                tx_hash=r.tx_hash, block_number=r.block_number, timestamp=r.timestamp,
                submitter=pipeline.chain.get_batch(result.batch_id).submitter,
                file_count=len(result.files), created_by=user.username,
            )
        )
        db.flush()
        for f in result.files:
            db.add(
                FileCache(batch_id=result.batch_id, file_index=f.index, filename=f.filename,
                          size=f.size, file_hash=f.file_hash, cid=f.cid)
            )
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        log.exception("cache write failed; chain remains the source of truth")
    audit(db, user, "SUBMIT", batch_id=result.batch_id, tx_hash=r.tx_hash, result="OK",
          detail=f"case={case_id} files={[f.filename for f in result.files]}")
    return SubmitResponse(
        batch_id=result.batch_id, case_id=case_id, merkle_root=result.merkle_root,
        tx_hash=r.tx_hash, block_number=r.block_number, gas_used=r.gas_used, timestamp=r.timestamp,
        files=[
            FileOut(index=f.index, filename=f.filename, size=f.size, file_hash=f.file_hash,
                    cid=f.cid, merkle_proof=[s.to_dict() for s in f.proof])
            for f in result.files
        ],
        timings_ms=result.timings_ms,
    )




# ------------------------------------------------------------------------ verify
@router.post("/verify", response_model=VerifyResponse, summary="Verify a file (investigator, auditor)")
def verify(
    file: UploadFile = File(...),
    batch_id: int | None = Form(None, description="Optional: restrict to this batch"),
    user: CurrentUser = Depends(VERIFIER),
    chain: ChainClient = Depends(get_chain),
    db: Session = Depends(get_db),
) -> VerifyResponse:
    """Recompute SHA-256 and validate the Merkle inclusion proof against the **on-chain** root.

    The DB is used only as a hint for *where to look*; every verdict comes from chain data.
    """
    data = _read_limited(file)
    out = _locate_and_verify(db, chain, data, file.filename or "", batch_id)
    audit(db, user, "VERIFY", batch_id=out.get("batch_id"), tx_hash=out.get("tx_hash"),
          result=out["status"], detail=f"file={file.filename} sha256={out['computed_hash']}")
    return VerifyResponse(**out)


def _locate_and_verify(
    db: Session, chain: ChainClient, data: bytes, filename: str, batch_id: int | None
) -> dict:
    digest = sha256_bytes(data)
    name = _safe_name(filename, "")

    if batch_id is not None:
        res = verify_evidence(chain, data, batch_id)
        if res["status"] != "NOT_FOUND":
            return res
        hint = db.scalar(
            select(FileCache).where(FileCache.batch_id == batch_id, FileCache.filename == name)
        )
        if hint:
            return verify_evidence(chain, data, batch_id, index=hint.file_index)
        return res

    hint = db.scalar(select(FileCache).where(FileCache.file_hash == digest))
    if hint:
        res = verify_evidence(chain, data, hint.batch_id)
        if res["status"] != "NOT_FOUND":
            return res
    found = find_file_on_chain(chain, digest)
    if found:
        return verify_evidence(chain, data, found[0], index=found[1])
    if name:  # unknown content: assume it is a modified copy of a known filename
        cand = db.scalar(
            select(FileCache).where(FileCache.filename == name).order_by(FileCache.batch_id.desc())
        )
        if cand:
            return verify_evidence(chain, data, cand.batch_id, index=cand.file_index)
    return {
        "status": "NOT_FOUND",
        "detail": "No anchored file matches this content or filename.",
        "computed_hash": digest,
    }


# -------------------------------------------------------------------- list / get
@router.get("", response_model=list[BatchSummary], summary="List batches (cache)")
def list_batches(
    q: str | None = Query(None, description="Search case id, root, tx, filename, hash, CID"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    _: CurrentUser = Depends(ANY_ROLE),
    db: Session = Depends(get_db),
) -> list[BatchSummary]:
    """Newest first. Backed by the DB cache; use ``GET /evidence/{id}`` for chain-verified data."""
    stmt = select(BatchCache)
    if q:
        like = f"%{q.strip()}%"
        in_files = select(FileCache.batch_id).where(
            or_(FileCache.filename.ilike(like), FileCache.file_hash.ilike(like),
                FileCache.cid.ilike(like))
        )
        stmt = stmt.where(
            or_(BatchCache.case_id.ilike(like), BatchCache.merkle_root.ilike(like),
                BatchCache.tx_hash.ilike(like), BatchCache.batch_id.in_(in_files))
        )
    rows = db.scalars(stmt.order_by(BatchCache.batch_id.desc()).offset(offset).limit(limit))
    return [
        BatchSummary(batch_id=b.batch_id, case_id=b.case_id, merkle_root=b.merkle_root,
                     tx_hash=b.tx_hash, block_number=b.block_number, timestamp=b.timestamp,
                     file_count=b.file_count, created_by=b.created_by)
        for b in rows
    ]


@router.get("/{batch_id}", response_model=BatchDetail, summary="Batch detail (from chain)")
def get_batch(
    batch_id: int,
    _: CurrentUser = Depends(ANY_ROLE),
    chain: ChainClient = Depends(get_chain),
    db: Session = Depends(get_db),
) -> BatchDetail:
    """Authoritative batch data read from the contract; filenames come from the cache."""
    b = chain.get_batch(batch_id)
    files = chain.get_files(batch_id)
    tree = build_tree([f.file_hash for f in files])
    names = {
        fc.file_index: fc
        for fc in db.scalars(select(FileCache).where(FileCache.batch_id == batch_id))
    }
    try:
        tx_hash, block = chain.get_registration_tx(batch_id)
    except Exception:  # noqa: BLE001
        cached = db.get(BatchCache, batch_id)
        tx_hash, block = (cached.tx_hash, cached.block_number) if cached else (None, None)
    return BatchDetail(
        batch_id=batch_id, case_id=b.case_id, merkle_root=b.merkle_root, timestamp=b.timestamp,
        submitter=b.submitter, current_custodian=chain.current_custodian(batch_id),
        file_count=b.file_count, tx_hash=tx_hash, block_number=block,
        root_consistent=tree.get_root() == b.merkle_root,
        files=[
            FileOut(index=i, filename=names[i].filename if i in names else f"file-{i}",
                    size=names[i].size if i in names else None, file_hash=f.file_hash, cid=f.cid,
                    merkle_proof=[s.to_dict() for s in tree.get_proof(i)])
            for i, f in enumerate(files)
        ],
    )


@router.get("/{batch_id}/custody", response_model=list[CustodyEntryOut], summary="Chain of custody")
def get_custody(
    batch_id: int, _: CurrentUser = Depends(ANY_ROLE), chain: ChainClient = Depends(get_chain)
) -> list[CustodyEntryOut]:
    """Custody log read from the contract, oldest first."""
    return [
        CustodyEntryOut(from_addr=e.from_addr, to_addr=e.to_addr, reason=e.reason, timestamp=e.timestamp)
        for e in chain.get_custody_log(batch_id)
    ]


@router.post("/{batch_id}/transfer", response_model=TransferResponse, summary="Transfer custody")
def transfer(
    batch_id: int,
    body: TransferRequest,
    user: CurrentUser = Depends(INVESTIGATOR),
    chain: ChainClient = Depends(get_chain),
    db: Session = Depends(get_db),
) -> TransferResponse:
    """Append a custody transfer on-chain."""
    r = chain.transfer_custody(batch_id, body.new_custodian, body.reason)
    audit(db, user, "TRANSFER", batch_id=batch_id, tx_hash=r.tx_hash, result="OK",
          detail=f"to={body.new_custodian} reason={body.reason}")
    return TransferResponse(batch_id=batch_id, tx_hash=r.tx_hash, block_number=r.block_number,
                            new_custodian=body.new_custodian)


@router.get("/{batch_id}/download", summary="Download decrypted evidence (investigator)")
def download(
    batch_id: int,
    file_index: int | None = Query(None, ge=0, description="Omit for single-file batches or a ZIP"),
    user: CurrentUser = Depends(INVESTIGATOR),
    chain: ChainClient = Depends(get_chain),
    pipeline: EvidencePipeline = Depends(get_pipeline),
    db: Session = Depends(get_db),
) -> Response:
    """IPFS fetch -> decrypt -> check against the on-chain hash -> stream to the caller."""
    files = chain.get_files(batch_id)
    names = {
        fc.file_index: fc.filename
        for fc in db.scalars(select(FileCache).where(FileCache.batch_id == batch_id))
    }
    if file_index is None and len(files) == 1:
        file_index = 0
    if file_index is not None:
        if file_index >= len(files):
            raise NotFoundError(f"file index {file_index} not in batch {batch_id}")
        content = pipeline.retrieve(batch_id, file_index)
        fname = _safe_name(names.get(file_index), f"batch{batch_id}-file{file_index}")
        media = "application/octet-stream"
    else:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for i in range(len(files)):
                z.writestr(f"{i:03d}_{_safe_name(names.get(i), f'file-{i}')}", pipeline.retrieve(batch_id, i))
        content, fname, media = buf.getvalue(), f"batch-{batch_id}.zip", "application/zip"
    audit(db, user, "DOWNLOAD", batch_id=batch_id, result="OK", detail=f"file={fname}")
    return Response(content, media_type=media,
                    headers={"Content-Disposition": f'attachment; filename="{fname}"'})

