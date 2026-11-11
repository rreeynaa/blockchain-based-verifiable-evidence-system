"""Thorough unit tests for the Merkle module."""

import hashlib

import pytest

from core.crypto.merkle import (
    ProofStep,
    build_tree,
    compute_root,
    hash_leaf,
    hash_node,
    verify_proof,
)


def leaves(n: int) -> list[str]:
    return [hashlib.sha256(f"file-{i}".encode()).hexdigest() for i in range(n)]


def test_empty_raises():
    with pytest.raises(ValueError):
        build_tree([])


def test_single_leaf_root_is_domain_separated_leaf_hash():
    lf = leaves(1)[0]
    t = build_tree([lf])
    assert t.get_root() == hash_leaf(lf).hex()
    assert t.get_proof(0) == []
    assert verify_proof(lf, [], t.get_root())


@pytest.mark.parametrize("n", list(range(1, 34)))
def test_every_leaf_verifies_for_all_sizes(n):
    lv = leaves(n)
    t = build_tree(lv)
    for i, lf in enumerate(lv):
        assert verify_proof(lf, t.get_proof(i), t.get_root()), (n, i)


@pytest.mark.parametrize("n", [2, 3, 5, 8, 13])
def test_modified_leaf_fails(n):
    lv = leaves(n)
    t = build_tree(lv)
    bad = bytearray(bytes.fromhex(lv[0]))
    bad[0] ^= 0x01
    assert not verify_proof(bytes(bad), t.get_proof(0), t.get_root())


def test_wrong_root_fails():
    lv = leaves(4)
    t = build_tree(lv)
    other = build_tree(leaves(5)).get_root()
    assert not verify_proof(lv[0], t.get_proof(0), other)


def test_proof_for_wrong_index_fails():
    lv = leaves(8)
    t = build_tree(lv)
    assert not verify_proof(lv[1], t.get_proof(0), t.get_root())


def test_flipped_position_fails():
    lv = leaves(4)
    t = build_tree(lv)
    p = t.get_proof(0)
    flipped = [ProofStep(s.sibling, "left" if s.position == "right" else "right") for s in p]
    assert not verify_proof(lv[0], flipped, t.get_root())


def test_order_matters():
    a, b = leaves(2)
    assert build_tree([a, b]).get_root() != build_tree([b, a]).get_root()


def test_odd_count_has_no_duplicate_ambiguity():
    a, b, c = leaves(3)
    assert build_tree([a, b, c]).get_root() != build_tree([a, b, c, c]).get_root()


def test_inner_node_cannot_masquerade_as_leaf():
    a, b = leaves(2)
    t = build_tree([a, b])
    inner = hash_node(hash_leaf(a), hash_leaf(b))
    assert t.get_root() == inner.hex()
    # a one-leaf tree over the inner hash must NOT reproduce the two-leaf root
    assert build_tree([inner]).get_root() != t.get_root()


def test_deterministic_and_accepts_bytes_or_hex():
    lv = leaves(5)
    assert build_tree(lv).get_root() == build_tree([bytes.fromhex(x) for x in lv]).get_root()
    assert build_tree(lv).get_root() == build_tree(lv).get_root()


def test_index_out_of_range():
    t = build_tree(leaves(3))
    with pytest.raises(IndexError):
        t.get_proof(3)
    with pytest.raises(IndexError):
        t.get_proof(-1)


def test_proof_dict_roundtrip_and_malformed_input():
    lv = leaves(6)
    t = build_tree(lv)
    as_dicts = [s.to_dict() for s in t.get_proof(4)]
    assert verify_proof(lv[4], as_dicts, t.get_root())
    assert not verify_proof(lv[4], [{"sibling": "zz", "position": "left"}], t.get_root())
    assert not verify_proof(lv[4], [{"position": "left"}], t.get_root())


def test_compute_root_matches_tree_root():
    lv = leaves(7)
    t = build_tree(lv)
    assert compute_root(lv[6], t.get_proof(6)) == t.get_root()


def test_root_accepts_0x_prefix():
    lv = leaves(3)
    t = build_tree(lv)
    assert verify_proof(lv[1], t.get_proof(1), "0x" + t.get_root())
