"""Evidence pipeline: hash -> Merkle -> encrypt -> IPFS -> on-chain registration.

The pipeline is storage-agnostic: it receives a ``ChainClient``, an IPFS client
and a ``KeyProvider`` and never touches the database (the API caches results).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from core.crypto import KeyProvider, ProofStep, build_tree, decrypt, encrypt, sha256_bytes
from core.errors import IntegrityError, InvalidEvidenceError
from core.types import ChainClient, TxReceipt


@dataclass
class FileResult:
    """Per-file outcome of a submission."""

    index: int
    filename: str
    size: int
    file_hash: str
    cid: str
    proof: list[ProofStep]


@dataclass
class BatchResult:
    """Outcome of a batch submission."""

    case_id: str
    merkle_root: str
    files: list[FileResult]
    receipt: TxReceipt
    timings_ms: dict[str, float] = field(default_factory=dict)

    @property
    def batch_id(self) -> int:
        """On-chain batch id."""
        assert self.receipt.batch_id is not None
        return self.receipt.batch_id


class EvidencePipeline:
    """Runs the full evidence-anchoring pipeline."""

    def __init__(self, chain: ChainClient, ipfs: Any, keys: KeyProvider) -> None:
        self.chain = chain
        self.ipfs = ipfs
        self.keys = keys

    def submit(self, case_id: str, files: list[tuple[str, bytes]]) -> BatchResult:
        """Process ``files`` (``(filename, plaintext_bytes)``) as one batch."""
        if not files:
            raise InvalidEvidenceError("at least one file is required")
        t0 = time.perf_counter()

        hashes = [sha256_bytes(data) for _, data in files]
        if len(set(hashes)) != len(hashes):
            raise InvalidEvidenceError("duplicate files (identical content) in one batch")
        t_hash = time.perf_counter()

        tree = build_tree(hashes)
        root = tree.get_root()
        t_merkle = time.perf_counter()

        blobs = [encrypt(data, self.keys) for _, data in files]
        t_enc = time.perf_counter()

        cids = [self.ipfs.add(blob) for blob in blobs]
        t_ipfs = time.perf_counter()

        receipt = self.chain.register_batch(case_id, root, hashes, cids)
        t_chain = time.perf_counter()

        results = [
            FileResult(i, name, len(data), hashes[i], cids[i], tree.get_proof(i))
            for i, (name, data) in enumerate(files)
        ]
        ms = lambda a, b: round((b - a) * 1000, 3)  # noqa: E731
        return BatchResult(
            case_id=case_id,
            merkle_root=root,
            files=results,
            receipt=receipt,
            timings_ms={
                "hash": ms(t0, t_hash),
                "merkle": ms(t_hash, t_merkle),
                "encrypt": ms(t_merkle, t_enc),
                "ipfs": ms(t_enc, t_ipfs),
                "chain": ms(t_ipfs, t_chain),
                "total": ms(t0, t_chain),
            },
        )

    def retrieve(self, batch_id: int, index: int) -> bytes:
        """Fetch + decrypt a file and confirm it matches the on-chain hash."""
        rec = self.chain.get_files(batch_id)[index]
        plaintext = decrypt(self.ipfs.cat(rec.cid), self.keys)
        if sha256_bytes(plaintext) != rec.file_hash:
            raise IntegrityError("decrypted content does not match on-chain hash")
        return plaintext
