"""End-to-end pipeline + verification against in-memory chain/IPFS."""

import os
import random

from cryptography.exceptions import InvalidTag

from core.crypto import LocalFileKeyProvider, decrypt, verify_proof
from core.errors import ChainError, InvalidEvidenceError, NotFoundError
from core.pipeline import EvidencePipeline
from core.verify import find_file_on_chain, verify_evidence
from tests.fakes import FakeChain, FakeIPFS


def make():
    chain, ipfs = FakeChain(), FakeIPFS()
    keys = LocalFileKeyProvider(os.urandom(32))
    return EvidencePipeline(chain, ipfs, keys), chain, ipfs, keys


def files(n, size=200):
    rnd = random.Random(7)
    return [(f"log{i}.json", bytes(rnd.randrange(256) for _ in range(size))) for i in range(n)]


def test_submit_anchors_root_and_hashes():
    p, chain, ipfs, _ = make()
    res = p.submit("CASE-1", files(5))
    assert res.batch_id == 1 and len(res.files) == 5
    assert chain.get_batch(1).merkle_root == res.merkle_root
    for f in res.files:
        assert verify_proof(f.file_hash, f.proof, res.merkle_root)
        assert chain.get_files(1)[f.index].cid == f.cid
    assert set(res.timings_ms) >= {"hash", "merkle", "encrypt", "ipfs", "chain", "total"}


def test_ipfs_holds_only_ciphertext():
    p, _, ipfs, _ = make()
    data = files(2)
    p.submit("c", data)
    for _, plain in data:
        assert all(plain not in blob for blob in ipfs.store.values())


def test_retrieve_roundtrip():
    p, *_ = make()
    data = files(3)
    res = p.submit("c", data)
    for i, (_, plain) in enumerate(data):
        assert p.retrieve(res.batch_id, i) == plain


def test_retrieve_detects_ciphertext_tampering():
    p, _, ipfs, _ = make()
    res = p.submit("c", files(2))
    cid = res.files[0].cid
    blob = bytearray(ipfs.store[cid])
    blob[-3] ^= 1
    ipfs.store[cid] = bytes(blob)
    try:
        p.retrieve(res.batch_id, 0)
        raise AssertionError("should fail")
    except (InvalidTag, ValueError):
        pass


def test_duplicate_content_and_empty_batch_rejected():
    p, *_ = make()
    for bad in ([], [("a", b"x"), ("b", b"x")]):
        try:
            p.submit("c", bad)
            raise AssertionError("should fail")
        except InvalidEvidenceError:
            pass


def test_duplicate_root_rejected_by_chain():
    p, *_ = make()
    f = files(2)
    p.submit("c", f)
    try:
        p.submit("c2", f)
        raise AssertionError("should fail")
    except ChainError:
        pass


def test_verify_untouched_files_for_various_batch_sizes():
    for n in (1, 2, 3, 7, 16):
        p, chain, *_ = make()
        data = files(n)
        res = p.submit("c", data)
        for i, (_, plain) in enumerate(data):
            v = verify_evidence(chain, plain, res.batch_id)
            assert v["status"] == "VERIFIED" and v["file_index"] == i
            assert v["inclusion_valid"] and v["hash_match"] and v["tx_hash"]


def test_every_single_byte_modification_is_detected():
    p, chain, *_ = make()
    data = files(5, size=64)
    res = p.submit("c", data)
    rnd = random.Random(1)
    detected = trials = 0
    for _ in range(300):
        i = rnd.randrange(len(data))
        mod = bytearray(data[i][1])
        pos = rnd.randrange(len(mod))
        mod[pos] ^= rnd.randrange(1, 256)
        v = verify_evidence(chain, bytes(mod), res.batch_id, index=i)
        trials += 1
        detected += v["status"] == "TAMPERED"
        assert v["expected_hash"] == res.files[i].file_hash
        assert v["recomputed_root"] != v["onchain_root"]
    assert detected == trials


def test_modified_file_without_index_is_not_found():
    p, chain, *_ = make()
    data = files(2)
    res = p.submit("c", data)
    v = verify_evidence(chain, data[0][1] + b"!", res.batch_id)
    assert v["status"] == "NOT_FOUND"


def test_unknown_batch_and_bad_index():
    p, chain, *_ = make()
    res = p.submit("c", files(2))
    for args in ((99, None), (res.batch_id, 9)):
        try:
            verify_evidence(chain, b"x", *args)
            raise AssertionError("should fail")
        except NotFoundError:
            pass


def test_find_file_on_chain_scans_all_batches():
    p, chain, *_ = make()
    a = p.submit("c1", files(2))
    b = p.submit("c2", [("z.json", b"unique-bytes")])
    assert find_file_on_chain(chain, a.files[1].file_hash) == (1, 1)
    assert find_file_on_chain(chain, b.files[0].file_hash) == (2, 0)
    assert find_file_on_chain(chain, "00" * 32) is None


def test_envelope_cannot_be_decrypted_with_other_key():
    p, _, ipfs, _ = make()
    res = p.submit("c", files(1))
    try:
        decrypt(ipfs.store[res.files[0].cid], LocalFileKeyProvider(os.urandom(32)))
        raise AssertionError("should fail")
    except InvalidTag:
        pass
