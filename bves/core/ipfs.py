"""Minimal Kubo (go-ipfs) HTTP RPC client with timeouts and retries.

Uses plain ``requests`` against ``/api/v0/*`` (the deprecated ``ipfshttpclient``
package is intentionally avoided).
"""

from __future__ import annotations

import logging
import time
from typing import Any

import requests

from core.errors import IPFSError

log = logging.getLogger(__name__)


class IPFSClient:
    """Thin wrapper around Kubo's RPC API."""

    def __init__(
        self,
        api_url: str,
        timeout: float = 30.0,
        retries: int = 3,
        backoff: float = 0.5,
        session: Any | None = None,
    ) -> None:
        self.base = api_url.rstrip("/") + "/api/v0"
        self.timeout = timeout
        self.retries = retries
        self.backoff = backoff
        self.session = session or requests.Session()

    def _post(self, path: str, **kwargs: Any) -> requests.Response:
        """POST with retry on connection errors, timeouts and 5xx; fail fast on 4xx."""
        last: Exception | None = None
        for attempt in range(1, self.retries + 1):
            try:
                resp = self.session.post(f"{self.base}{path}", timeout=self.timeout, **kwargs)
                if resp.status_code < 400:
                    return resp
                if resp.status_code < 500:
                    raise IPFSError(f"IPFS {path} failed: {resp.status_code} {resp.text[:200]}")
                last = IPFSError(f"IPFS {path} server error {resp.status_code}")
            except IPFSError:
                raise
            except (requests.ConnectionError, requests.Timeout) as exc:
                last = exc
            log.warning("ipfs %s attempt %d/%d failed: %s", path, attempt, self.retries, last)
            if attempt < self.retries:
                time.sleep(self.backoff * 2 ** (attempt - 1))
        raise IPFSError(f"IPFS {path} failed after {self.retries} attempts: {last}") from last

    def add(self, data: bytes, pin: bool = True) -> str:
        """Add ``data`` and return its CID (v1)."""
        resp = self._post(
            "/add",
            params={"pin": str(pin).lower(), "cid-version": 1},
            files={"file": ("evidence.bin", data)},
        )
        try:
            return str(resp.json()["Hash"])
        except (ValueError, KeyError):
            # Kubo may stream NDJSON; the last line carries the final hash.
            try:
                import json

                return str(json.loads(resp.text.strip().splitlines()[-1])["Hash"])
            except Exception as exc:  # noqa: BLE001
                raise IPFSError("unexpected response from IPFS add") from exc

    def cat(self, cid: str) -> bytes:
        """Fetch the bytes stored under ``cid``."""
        return self._post("/cat", params={"arg": cid}).content

    def pin(self, cid: str) -> None:
        """Pin ``cid`` on the node."""
        self._post("/pin/add", params={"arg": cid})

    def is_available(self) -> bool:
        """Return True if the node answers ``/version``."""
        try:
            self._post("/version")
            return True
        except IPFSError:
            return False
