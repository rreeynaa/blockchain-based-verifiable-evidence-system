"""In-memory stand-ins for the chain and IPFS (mirror the contract's rules)."""

from __future__ import annotations

import hashlib
import time

from core.errors import ChainError, NotFoundError
from core.types import CustodyEntry, OnChainBatch, OnChainFile, TxReceipt


class FakeIPFS:
    """Content-addressed dict."""

    def __init__(self) -> None:
        self.store: dict[str, bytes] = {}

    def add(self, data: bytes, pin: bool = True) -> str:
        cid = "bafy" + hashlib.sha256(data).hexdigest()[:40]
        self.store[cid] = data
        return cid

    def cat(self, cid: str) -> bytes:
        return self.store[cid]

    def pin(self, cid: str) -> None:
        pass


class FakeChain:
    """Append-only ledger with the same invariants as EvidenceRegistry."""

    def __init__(self, signer: str = "0xSigner") -> None:
        self.signer = signer
        self.batches: list[OnChainBatch] = []
        self.files: dict[int, list[OnChainFile]] = {}
        self.custody: dict[int, list[CustodyEntry]] = {}
        self.roots: dict[str, int] = {}
        self.txs: dict[int, tuple[str, int]] = {}
        self.block = 0

    def _tx(self, tag: str, batch_id: int | None = None) -> TxReceipt:
        self.block += 1
        h = "0x" + hashlib.sha256(f"{tag}{self.block}".encode()).hexdigest()
        return TxReceipt(h, self.block, 21000, int(time.time()), batch_id)

    def batch_count(self) -> int:
        return len(self.batches)

    def register_batch(self, case_id, merkle_root, file_hashes, cids) -> TxReceipt:
        if merkle_root in self.roots:
            raise ChainError("contract reverted: duplicate root")
        if not file_hashes or len(file_hashes) != len(cids):
            raise ChainError("contract reverted: bad input")
        bid = len(self.batches) + 1
        rc = self._tx("reg", bid)
        self.batches.append(
            OnChainBatch(bid, merkle_root, rc.timestamp, self.signer, case_id, len(file_hashes))
        )
        self.files[bid] = [OnChainFile(h, c, bid) for h, c in zip(file_hashes, cids, strict=True)]
        self.custody[bid] = [CustodyEntry("0x" + "0" * 40, self.signer, "Initial registration", rc.timestamp)]
        self.roots[merkle_root] = bid
        self.txs[bid] = (rc.tx_hash, rc.block_number)
        return rc

    def transfer_custody(self, batch_id, new_custodian, reason) -> TxReceipt:
        self.get_batch(batch_id)
        cur = self.current_custodian(batch_id)
        if new_custodian == cur:
            raise ChainError("contract reverted: already custodian")
        rc = self._tx("xfer", batch_id)
        self.custody[batch_id].append(CustodyEntry(cur, new_custodian, reason, rc.timestamp))
        return rc

    def get_batch(self, batch_id) -> OnChainBatch:
        if not 1 <= batch_id <= len(self.batches):
            raise NotFoundError("batch not found on chain")
        return self.batches[batch_id - 1]

    def get_files(self, batch_id):
        self.get_batch(batch_id)
        return list(self.files[batch_id])

    def get_custody_log(self, batch_id):
        self.get_batch(batch_id)
        return list(self.custody[batch_id])

    def current_custodian(self, batch_id) -> str:
        return self.get_custody_log(batch_id)[-1].to_addr

    def verify_file_hash(self, batch_id, file_hash) -> bool:
        try:
            return any(f.file_hash == file_hash for f in self.get_files(batch_id))
        except NotFoundError:
            return False

    def verify_root(self, batch_id, root) -> bool:
        try:
            return self.get_batch(batch_id).merkle_root == root
        except NotFoundError:
            return False

    def get_registration_tx(self, batch_id):
        return self.txs[batch_id]
