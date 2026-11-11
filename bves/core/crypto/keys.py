"""Master-key abstraction (KMS-style) with a local-file implementation.

The master key only ever *wraps* per-file data keys. Swap ``LocalFileKeyProvider``
for an AWS KMS / Vault implementation of :class:`KeyProvider` in production.
"""

from __future__ import annotations

import base64
import os
from abc import ABC, abstractmethod
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class KeyProvider(ABC):
    """Interface for wrapping/unwrapping data keys under a master key."""

    @property
    @abstractmethod
    def key_id(self) -> str:
        """Identifier of the master key (stored in the envelope; not secret)."""

    @abstractmethod
    def wrap(self, data_key: bytes) -> bytes:
        """Encrypt ``data_key`` under the master key."""

    @abstractmethod
    def unwrap(self, wrapped: bytes) -> bytes:
        """Decrypt a wrapped data key. Raises on failure."""


class LocalFileKeyProvider(KeyProvider):
    """Master key held in a 32-byte local file (or base64 env var). Dev/demo only."""

    def __init__(self, key: bytes, key_id: str = "local-1") -> None:
        if len(key) != 32:
            raise ValueError("master key must be exactly 32 bytes")
        self._aes = AESGCM(key)
        self._key_id = key_id

    @property
    def key_id(self) -> str:
        return self._key_id

    def wrap(self, data_key: bytes) -> bytes:
        nonce = os.urandom(12)
        return nonce + self._aes.encrypt(nonce, data_key, self._key_id.encode())

    def unwrap(self, wrapped: bytes) -> bytes:
        nonce, ct = wrapped[:12], wrapped[12:]
        return self._aes.decrypt(nonce, ct, self._key_id.encode())

    @classmethod
    def from_settings(cls, key_file: str, key_b64: str = "") -> LocalFileKeyProvider:
        """Load from ``MASTER_KEY_B64`` if set, else from ``key_file`` (created if absent)."""
        if key_b64:
            return cls(base64.b64decode(key_b64))
        path = Path(key_file)
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(os.urandom(32))
            path.chmod(0o600)
        return cls(path.read_bytes())
