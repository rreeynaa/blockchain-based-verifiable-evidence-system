"""Plain data types and the ChainClient protocol."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class TxReceipt:
    """Result of a state-changing chain call."""

    tx_hash: str
    block_number: int
    gas_used: int
    timestamp: int
    batch_id: int | None = None


@dataclass(frozen=True)
class OnChainBatch:
    """Batch header as stored in the contract."""

    batch_id: int
    merkle_root: str  # hex, no 0x
    timestamp: int
    submitter: str
    case_id: str
    file_count: int


@dataclass(frozen=True)
class OnChainFile:
    """File record as stored in the contract."""

    file_hash: str  # hex, no 0x
    cid: str
    batch_id: int


@dataclass(frozen=True)
class CustodyEntry:
    """One link in the chain of custody."""

    from_addr: str
    to_addr: str
    reason: str
    timestamp: int


class ChainClient(Protocol):
    """What the rest of the system needs from the blockchain."""

    def batch_count(self) -> int: ...

    def register_batch(
        self, case_id: str, merkle_root: str, file_hashes: list[str], cids: list[str]
    ) -> TxReceipt: ...

    def transfer_custody(self, batch_id: int, new_custodian: str, reason: str) -> TxReceipt: ...

    def get_batch(self, batch_id: int) -> OnChainBatch: ...

    def get_files(self, batch_id: int) -> list[OnChainFile]: ...

    def get_custody_log(self, batch_id: int) -> list[CustodyEntry]: ...

    def current_custodian(self, batch_id: int) -> str: ...

    def verify_file_hash(self, batch_id: int, file_hash: str) -> bool: ...

    def verify_root(self, batch_id: int, root: str) -> bool: ...

    def get_registration_tx(self, batch_id: int) -> tuple[str, int]:
        """Return (tx_hash, block_number) of the BatchRegistered event."""
        ...
