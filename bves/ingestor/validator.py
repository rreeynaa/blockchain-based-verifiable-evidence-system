"""CloudTrail structure validation."""

from __future__ import annotations

import json
from typing import Any

from core.errors import InvalidEvidenceError

MAX_BYTES = 10 * 1024 * 1024
REQUIRED_FIELDS = ("eventTime", "eventSource", "eventName")


def validate_cloudtrail(raw: bytes) -> list[dict[str, Any]]:
    """Return the ``Records`` list if ``raw`` is a well-formed CloudTrail file.

    Raises :class:`InvalidEvidenceError` otherwise.
    """
    if len(raw) > MAX_BYTES:
        raise InvalidEvidenceError("file exceeds 10 MiB limit")
    try:
        doc = json.loads(raw)
    except (UnicodeDecodeError, ValueError) as exc:
        raise InvalidEvidenceError(f"not valid JSON: {exc}") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("Records"), list):
        raise InvalidEvidenceError("missing top-level 'Records' array")
    records = doc["Records"]
    if not records:
        raise InvalidEvidenceError("'Records' array is empty")
    for i, r in enumerate(records):
        if not isinstance(r, dict):
            raise InvalidEvidenceError(f"Records[{i}] is not an object")
        missing = [f for f in REQUIRED_FIELDS if f not in r]
        if missing:
            raise InvalidEvidenceError(f"Records[{i}] missing fields: {', '.join(missing)}")
    return records
