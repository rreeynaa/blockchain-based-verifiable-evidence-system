"""AES-256-GCM envelope encryption.

Blob layout (what is stored on IPFS)::

    MAGIC(5) | header_len(4, big-endian) | header(JSON) | ciphertext+tag

The header holds only non-secret material: version, algorithm, master key id,
the GCM nonce and the *wrapped* (encrypted) data key. The plaintext data key is
never persisted. The master key id is bound as GCM associated data.
"""

from __future__ import annotations

import base64
import json
import os
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.crypto.keys import KeyProvider

MAGIC = b"BVES1"


def _aad(key_id: str) -> bytes:
    return MAGIC + key_id.encode()


def encrypt(plaintext: bytes, provider: KeyProvider) -> bytes:
    """Encrypt ``plaintext`` with a fresh random data key; return the envelope blob."""
    data_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(data_key).encrypt(nonce, plaintext, _aad(provider.key_id))
    header = json.dumps(
        {
            "v": 1,
            "alg": "AES-256-GCM",
            "key_id": provider.key_id,
            "nonce": base64.b64encode(nonce).decode(),
            "wrapped_key": base64.b64encode(provider.wrap(data_key)).decode(),
        },
        sort_keys=True,
    ).encode()
    return MAGIC + struct.pack(">I", len(header)) + header + ciphertext


def decrypt(blob: bytes, provider: KeyProvider) -> bytes:
    """Decrypt an envelope blob. Raises ``ValueError`` (format) or ``InvalidTag`` (auth)."""
    if not blob.startswith(MAGIC) or len(blob) < len(MAGIC) + 4:
        raise ValueError("not a BVES envelope")
    (hlen,) = struct.unpack(">I", blob[len(MAGIC) : len(MAGIC) + 4])
    start = len(MAGIC) + 4
    if start + hlen > len(blob):
        raise ValueError("truncated envelope header")
    try:
        header = json.loads(blob[start : start + hlen])
        nonce = base64.b64decode(header["nonce"])
        wrapped = base64.b64decode(header["wrapped_key"])
        key_id = header["key_id"]
    except (ValueError, KeyError) as exc:
        raise ValueError("malformed envelope header") from exc
    if key_id != provider.key_id:
        raise ValueError(f"envelope key id {key_id!r} does not match provider")
    data_key = provider.unwrap(wrapped)
    return AESGCM(data_key).decrypt(nonce, blob[start + hlen :], _aad(key_id))
