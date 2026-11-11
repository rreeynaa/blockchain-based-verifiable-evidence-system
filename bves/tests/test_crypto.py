"""Tests for hashing and AES-256-GCM envelope encryption."""

import os

import pytest
from cryptography.exceptions import InvalidTag

from core.crypto import LocalFileKeyProvider, decrypt, encrypt, sha256_bytes, sha256_file


@pytest.fixture
def provider():
    return LocalFileKeyProvider(os.urandom(32))


def test_sha256_file_matches_bytes(tmp_path):
    p = tmp_path / "a.json"
    p.write_bytes(b"hello")
    assert sha256_file(p) == sha256_bytes(b"hello")
    assert sha256_bytes(b"hello") == (
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    )


def test_roundtrip(provider):
    pt = b'{"Records": []}' * 100
    assert decrypt(encrypt(pt, provider), provider) == pt


def test_empty_plaintext_roundtrip(provider):
    assert decrypt(encrypt(b"", provider), provider) == b""


def test_fresh_key_and_nonce_each_time(provider):
    a, b = encrypt(b"same", provider), encrypt(b"same", provider)
    assert a != b


def test_plaintext_not_in_blob(provider):
    secret = b"TOP-SECRET-EVIDENCE"
    assert secret not in encrypt(secret, provider)


@pytest.mark.parametrize("offset", [-1, -20, 60])
def test_single_byte_tamper_detected(provider, offset):
    blob = bytearray(encrypt(b"x" * 64, provider))
    blob[offset] ^= 0x01
    with pytest.raises((InvalidTag, ValueError)):
        decrypt(bytes(blob), provider)


def test_wrong_master_key_fails(provider):
    blob = encrypt(b"data", provider)
    with pytest.raises(InvalidTag):
        decrypt(blob, LocalFileKeyProvider(os.urandom(32)))


def test_bad_magic_and_truncation(provider):
    with pytest.raises(ValueError):
        decrypt(b"nonsense", provider)
    with pytest.raises(ValueError):
        decrypt(encrypt(b"abc", provider)[:12], provider)


def test_master_key_must_be_32_bytes():
    with pytest.raises(ValueError):
        LocalFileKeyProvider(b"short")


def test_key_file_created_with_restrictive_mode(tmp_path):
    if os.name == "nt":
        pytest.skip("Windows does not report POSIX mode bits in stat().st_mode")
    f = tmp_path / "k" / "master.key"
    p1 = LocalFileKeyProvider.from_settings(str(f))
    assert f.stat().st_mode & 0o777 == 0o600
    p2 = LocalFileKeyProvider.from_settings(str(f))
    assert decrypt(encrypt(b"z", p1), p2) == b"z"
