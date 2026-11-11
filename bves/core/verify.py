"""Verification logic. Always consults the chain; the DB is never trusted here."""

from __future__ import annotations

from typing import Any

from core.crypto import build_tree
from core.crypto.merkle import compute_root
from core.crypto.hashing import sha256_bytes
from core.errors import NotFoundError
from core.types import ChainClient


def find_file_on_chain(chain: ChainClient, file_hash: str) -> tuple[int, int] | None:
    """Scan the chain for ``file_hash``; return ``(batch_id, index)`` or None.

    O(total files). Used when the DB cache has no hint; fine at demo scale.
    """
    for batch_id in range(chain.batch_count(), 0, -1):
        for i, f in enumerate(chain.get_files(batch_id)):
            if f.file_hash == file_hash:
                return batch_id, i
    return None


def verify_evidence(
    chain: ChainClient, data: bytes, batch_id: int, index: int | None = None
) -> dict[str, Any]:
    """Verify ``data`` against batch ``batch_id`` using only on-chain state.

    ``index`` identifies which file slot the upload claims to be (needed to show
    expected-vs-computed for a modified file, whose hash matches no slot).

    Returns a dict with ``status`` in {VERIFIED, TAMPERED, NOT_FOUND}.
    """
    computed = sha256_bytes(data)
    batch = chain.get_batch(batch_id)  # raises NotFoundError if absent
    files = chain.get_files(batch_id)
    leaves = [f.file_hash for f in files]

    if index is None and computed in leaves:
        index = leaves.index(computed)
    if index is None:
        return {
            "status": "NOT_FOUND",
            "batch_id": batch_id,
            "computed_hash": computed,
            "detail": "File hash is not in this batch and no file index/name was supplied.",
        }
    if not 0 <= index < len(leaves):
        raise NotFoundError(f"file index {index} not in batch {batch_id}")

    tree = build_tree(leaves)
    proof = tree.get_proof(index)
    recomputed_root = compute_root(computed, proof)
    root_consistent = tree.get_root() == batch.merkle_root
    inclusion_valid = recomputed_root == batch.merkle_root
    hash_on_chain = chain.verify_file_hash(batch_id, computed)
    root_on_chain = chain.verify_root(batch_id, batch.merkle_root)
    expected = leaves[index]
    hash_match = computed == expected

    ok = hash_match and inclusion_valid and hash_on_chain and root_on_chain and root_consistent
    try:
        tx_hash, block_number = chain.get_registration_tx(batch_id)
    except Exception:  # noqa: BLE001 - provenance is informational
        tx_hash, block_number = None, None

    if ok:
        detail = "File hash matches the on-chain record and its Merkle proof reaches the anchored root."
    elif not hash_match:
        detail = (
            "Computed SHA-256 differs from the hash anchored on-chain "
            f"(expected {expected}, computed {computed})."
        )
    else:
        detail = "On-chain data failed an internal consistency check."

    return {
        "status": "VERIFIED" if ok else "TAMPERED",
        "detail": detail,
        "batch_id": batch_id,
        "case_id": batch.case_id,
        "file_index": index,
        "cid": files[index].cid,
        "expected_hash": expected,
        "computed_hash": computed,
        "hash_match": hash_match,
        "onchain_hash_check": hash_on_chain,
        "onchain_root": batch.merkle_root,
        "recomputed_root": recomputed_root,
        "inclusion_valid": inclusion_valid,
        "root_consistent": root_consistent,
        "merkle_proof": [s.to_dict() for s in proof],
        "tx_hash": tx_hash,
        "block_number": block_number,
        "timestamp": batch.timestamp,
        "submitter": batch.submitter,
    }
