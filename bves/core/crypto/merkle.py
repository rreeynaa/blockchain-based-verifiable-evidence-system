"""Merkle tree with domain separation and unpaired-node promotion.

Design choices (documented because they matter for security):

* Leaves are hashed as ``SHA256(0x00 || leaf)`` and inner nodes as
  ``SHA256(0x01 || left || right)``. The prefixes prevent a second-preimage
  attack where an inner node is presented as a leaf.
* Hashing is *index-aware*: proof steps record whether the sibling sits on the
  left or right, so ``H(a,b) != H(b,a)`` and position is bound into the root.
* An unpaired node on an odd-sized level is **promoted** unchanged instead of
  being duplicated. Duplication makes ``[a,b,c]`` and ``[a,b,c,c]`` share a
  root (CVE-2012-2459 style ambiguity); promotion does not.
* A single-leaf tree has root ``SHA256(0x00 || leaf)``.

All public inputs/outputs are hex strings so they serialise cleanly to JSON.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from core.crypto.hashing import sha256_bytes

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"

Position = Literal["left", "right"]


def _h(data: bytes) -> bytes:
    return bytes.fromhex(sha256_bytes(data))


def _to_bytes(value: str | bytes) -> bytes:
    if isinstance(value, bytes):
        return value
    return bytes.fromhex(value.removeprefix("0x"))


def hash_leaf(leaf: str | bytes) -> bytes:
    """Domain-separated leaf hash."""
    return _h(LEAF_PREFIX + _to_bytes(leaf))


def hash_node(left: bytes, right: bytes) -> bytes:
    """Domain-separated inner-node hash (order matters)."""
    return _h(NODE_PREFIX + left + right)


@dataclass(frozen=True)
class ProofStep:
    """One step of an inclusion proof: the sibling hash and which side it is on."""

    sibling: str
    position: Position

    def to_dict(self) -> dict[str, str]:
        """JSON-friendly representation."""
        return {"sibling": self.sibling, "position": self.position}

    @classmethod
    def from_dict(cls, d: dict[str, Any] | ProofStep) -> ProofStep:
        """Build a step from a dict (or pass through an existing step)."""
        if isinstance(d, ProofStep):
            return d
        if d["position"] not in ("left", "right"):
            raise ValueError("position must be 'left' or 'right'")
        return cls(sibling=d["sibling"], position=d["position"])


class MerkleTree:
    """Immutable Merkle tree built over a non-empty list of leaves."""

    def __init__(self, leaves: list[str | bytes]) -> None:
        if not leaves:
            raise ValueError("cannot build a Merkle tree with no leaves")
        self._levels: list[list[bytes]] = [[hash_leaf(x) for x in leaves]]
        level = self._levels[0]
        while len(level) > 1:
            nxt: list[bytes] = []
            for i in range(0, len(level), 2):
                if i + 1 < len(level):
                    nxt.append(hash_node(level[i], level[i + 1]))
                else:
                    nxt.append(level[i])  # promote unpaired node
            self._levels.append(nxt)
            level = nxt

    def __len__(self) -> int:
        return len(self._levels[0])

    def get_root(self) -> str:
        """Return the root as a hex string."""
        return self._levels[-1][0].hex()

    def get_proof(self, index: int) -> list[ProofStep]:
        """Return the inclusion proof (bottom-up) for the leaf at ``index``."""
        if not 0 <= index < len(self):
            raise IndexError(f"leaf index {index} out of range (0..{len(self) - 1})")
        proof: list[ProofStep] = []
        idx = index
        for level in self._levels[:-1]:
            sib = idx ^ 1
            if sib < len(level):
                proof.append(ProofStep(level[sib].hex(), "left" if sib < idx else "right"))
            idx //= 2
        return proof


def build_tree(leaves: list[str | bytes]) -> MerkleTree:
    """Build a :class:`MerkleTree` over ``leaves`` (hex strings or bytes)."""
    return MerkleTree(leaves)


def compute_root(proof_leaf: str | bytes, proof: list[ProofStep | dict[str, Any]]) -> str:
    """Fold ``proof`` over ``proof_leaf`` and return the resulting root (hex)."""
    cur = hash_leaf(proof_leaf)
    for raw in proof:
        step = ProofStep.from_dict(raw)
        sib = bytes.fromhex(step.sibling)
        cur = hash_node(sib, cur) if step.position == "left" else hash_node(cur, sib)
    return cur.hex()


def verify_proof(
    leaf: str | bytes, proof: list[ProofStep | dict[str, Any]], root: str | bytes
) -> bool:
    """Return True iff ``leaf`` + ``proof`` hashes up to ``root``."""
    try:
        return compute_root(leaf, proof) == _to_bytes(root).hex()
    except (ValueError, KeyError, TypeError):
        return False
