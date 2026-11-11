"""Cache reconciliation: make the DB agree with the chain (chain wins)."""

from __future__ import annotations

import logging

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from api.models import BatchCache, FileCache
from core.types import ChainClient

log = logging.getLogger(__name__)


def reconcile(db: Session, chain: ChainClient) -> None:
    """Drop cache rows the chain does not know (e.g. dev chain reset); backfill missing ones."""
    count = chain.batch_count()
    top = db.scalar(select(func.max(BatchCache.batch_id))) or 0
    if top > count:
        log.warning("cache has batch %d but chain only %d: clearing stale cache", top, count)
        db.execute(delete(FileCache))
        db.execute(delete(BatchCache))
        db.commit()
    have = set(db.scalars(select(BatchCache.batch_id)))
    for bid in range(1, count + 1):
        if bid in have:
            continue
        b = chain.get_batch(bid)
        try:
            tx, blk = chain.get_registration_tx(bid)
        except Exception:  # noqa: BLE001
            tx, blk = "", 0
        db.add(
            BatchCache(
                batch_id=bid, case_id=b.case_id, merkle_root=b.merkle_root, tx_hash=tx,
                block_number=blk, timestamp=b.timestamp, submitter=b.submitter,
                file_count=b.file_count, created_by="(rebuilt from chain)",
            )
        )
        db.flush()
        for i, f in enumerate(chain.get_files(bid)):
            db.add(
                FileCache(batch_id=bid, file_index=i, filename="(unknown: cache rebuilt)",
                          size=0, file_hash=f.file_hash, cid=f.cid)
            )
        log.info("backfilled batch %d from chain", bid)
    db.commit()
