"""web3.py v7 client for the EvidenceRegistry contract.

``web3`` is imported lazily so the rest of ``core`` (and its tests) work without it.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

from core.errors import ChainError, NotFoundError
from core.types import CustodyEntry, OnChainBatch, OnChainFile, TxReceipt

log = logging.getLogger(__name__)


def _hex32(value: str) -> bytes:
    raw = bytes.fromhex(value.removeprefix("0x"))
    if len(raw) != 32:
        raise ValueError("expected 32-byte hex value")
    return raw


class Web3Chain:
    """Signs and sends transactions with a local private key; reads via ``call``."""

    def __init__(
        self, rpc_url: str, deployment_file: str, private_key: str, wait_timeout: int = 60
    ) -> None:
        from web3 import Web3

        if not private_key:
            raise ChainError("SIGNER_PRIVATE_KEY is not set")
        info = json.loads(Path(deployment_file).read_text())
        self.w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 30}))
        self.account = self.w3.eth.account.from_key(private_key)
        self.chain_id: int = info["chainId"]
        self.address: str = info["address"]
        self.contract = self.w3.eth.contract(
            address=Web3.to_checksum_address(info["address"]), abi=info["abi"]
        )
        self.wait_timeout = wait_timeout

    @classmethod
    def wait_for_deployment(cls, path: str, timeout: int = 90) -> None:
        """Block until the deployer has written the shared deployment file."""
        deadline = time.time() + timeout
        while not Path(path).exists():
            if time.time() > deadline:
                raise ChainError(f"deployment file {path} not found after {timeout}s")
            time.sleep(1)

    # ------------------------------------------------------------------ writes
    def _send(self, fn: Any) -> Any:
        from web3.exceptions import ContractLogicError

        try:
            tx = fn.build_transaction(
                {
                    "from": self.account.address,
                    "nonce": self.w3.eth.get_transaction_count(self.account.address),
                    "chainId": self.chain_id,
                }
            )
            signed = self.account.sign_transaction(tx)
            tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=self.wait_timeout)
        except ContractLogicError as exc:
            raise ChainError(f"contract reverted: {exc}") from exc
        except Exception as exc:  # noqa: BLE001
            raise ChainError(f"transaction failed: {exc}") from exc
        if receipt["status"] != 1:
            raise ChainError("transaction reverted")
        return receipt

    def _receipt(self, receipt: Any, batch_id: int | None = None) -> TxReceipt:
        block = self.w3.eth.get_block(receipt["blockNumber"])
        return TxReceipt(
            tx_hash="0x" + receipt["transactionHash"].hex().removeprefix("0x"),
            block_number=receipt["blockNumber"],
            gas_used=receipt["gasUsed"],
            timestamp=block["timestamp"],
            batch_id=batch_id,
        )

    def register_batch(
        self, case_id: str, merkle_root: str, file_hashes: list[str], cids: list[str]
    ) -> TxReceipt:
        fn = self.contract.functions.registerBatch(
            case_id, _hex32(merkle_root), [_hex32(h) for h in file_hashes], cids
        )
        receipt = self._send(fn)
        events = self.contract.events.BatchRegistered().process_receipt(receipt)
        if not events:
            raise ChainError("BatchRegistered event missing from receipt")
        return self._receipt(receipt, int(events[0]["args"]["batchId"]))

    def transfer_custody(self, batch_id: int, new_custodian: str, reason: str) -> TxReceipt:
        from web3 import Web3

        if not Web3.is_address(new_custodian):
            raise ChainError("new custodian is not a valid address")
        fn = self.contract.functions.transferCustody(
            batch_id, Web3.to_checksum_address(new_custodian), reason
        )
        return self._receipt(self._send(fn), batch_id)

    # ------------------------------------------------------------------- reads
    def _call(self, fn: Any) -> Any:
        from web3.exceptions import ContractLogicError

        try:
            return fn.call()
        except ContractLogicError as exc:
            if "unknown batch" in str(exc):
                raise NotFoundError("batch not found on chain") from exc
            raise ChainError(f"contract call failed: {exc}") from exc
        except Exception as exc:  # noqa: BLE001
            raise ChainError(f"chain read failed: {exc}") from exc

    def batch_count(self) -> int:
        return int(self._call(self.contract.functions.batchCount()))

    def get_batch(self, batch_id: int) -> OnChainBatch:
        root, ts, submitter, case_id, count = self._call(self.contract.functions.getBatch(batch_id))
        return OnChainBatch(batch_id, bytes(root).hex(), int(ts), submitter, case_id, int(count))

    def get_files(self, batch_id: int) -> list[OnChainFile]:
        rows = self._call(self.contract.functions.getFiles(batch_id))
        return [OnChainFile(bytes(r[0]).hex(), r[1], int(r[2])) for r in rows]

    def get_custody_log(self, batch_id: int) -> list[CustodyEntry]:
        rows = self._call(self.contract.functions.getCustodyLog(batch_id))
        return [CustodyEntry(r[0], r[1], r[2], int(r[3])) for r in rows]

    def current_custodian(self, batch_id: int) -> str:
        return str(self._call(self.contract.functions.currentCustodian(batch_id)))

    def verify_file_hash(self, batch_id: int, file_hash: str) -> bool:
        return bool(self._call(self.contract.functions.verifyFileHash(batch_id, _hex32(file_hash))))

    def verify_root(self, batch_id: int, root: str) -> bool:
        return bool(self._call(self.contract.functions.verifyRoot(batch_id, _hex32(root))))

    def get_registration_tx(self, batch_id: int) -> tuple[str, int]:
        try:
            logs = self.contract.events.BatchRegistered().get_logs(
                from_block=0, argument_filters={"batchId": batch_id}
            )
        except Exception as exc:  # noqa: BLE001
            raise ChainError(f"event lookup failed: {exc}") from exc
        if not logs:
            raise NotFoundError("registration event not found")
        ev = logs[0]
        return "0x" + ev["transactionHash"].hex().removeprefix("0x"), int(ev["blockNumber"])
