"""Domain exceptions shared across layers."""

from __future__ import annotations


class BVESError(Exception):
    """Base class for expected, domain-level failures."""


class ChainError(BVESError):
    """Blockchain call failed or reverted."""


class IPFSError(BVESError):
    """IPFS call failed after retries."""


class NotFoundError(BVESError):
    """Requested batch/file does not exist on chain."""


class InvalidEvidenceError(BVESError):
    """Submitted evidence is malformed (bad CloudTrail JSON, duplicates, ...)."""


class IntegrityError(BVESError):
    """Stored evidence failed an integrity check (hash mismatch / auth failure)."""
