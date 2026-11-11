"""Ingestor: validation, batching thresholds and file routing."""

import json
from pathlib import Path

from core.errors import InvalidEvidenceError
from ingestor.validator import validate_cloudtrail
from ingestor.watcher import Batcher, IngestorService

REC = {"eventTime": "2026-01-01T00:00:00Z", "eventSource": "iam.amazonaws.com", "eventName": "X"}


def doc(n=1, **over):
    return json.dumps({"Records": [dict(REC, eventName=f"E{i}", **over) for i in range(n)]}).encode()


def rejects(raw):
    try:
        validate_cloudtrail(raw)
    except InvalidEvidenceError:
        return True
    return False


def test_validator_accepts_good_and_samples():
    assert len(validate_cloudtrail(doc(3))) == 3
    for p in Path("samples").glob("*.json"):
        assert validate_cloudtrail(p.read_bytes())


def test_validator_rejects_malformed():
    assert rejects(b"not json")
    assert rejects(b"\xff\xfe")
    assert rejects(b"[]")
    assert rejects(b'{"Records": "x"}')
    assert rejects(b'{"Records": []}')
    assert rejects(b'{"Records": [1]}')
    assert rejects(b'{"Records": [{"eventName": "x"}]}')
    assert rejects(b'{"foo": 1}')
    assert rejects(b" " * (10 * 1024 * 1024 + 1))


def test_batcher_count_threshold_and_dedup():
    b = Batcher(3, 999)
    assert b.add(Path("a"), "h1") and b.add(Path("b"), "h2")
    assert not b.add(Path("c"), "h1")  # duplicate content
    assert not b.due()
    b.add(Path("d"), "h3")
    assert b.due() and len(b.take()) == 3 and not b.due()


def test_batcher_time_window():
    t = [0.0]
    b = Batcher(10, 30, clock=lambda: t[0])
    b.add(Path("a"), "h1")
    t[0] = 29
    assert not b.due()
    t[0] = 31
    assert b.due()


def make_service(tmp_path, threshold=2):
    sent = []
    svc = IngestorService(tmp_path, lambda paths: sent.append([p.name for p in paths]), threshold, 999)
    return svc, sent


def test_service_routes_valid_invalid_and_flushes(tmp_path):
    svc, sent = make_service(tmp_path)
    (tmp_path / "a.json").write_bytes(doc(1, awsRegion="r1"))
    (tmp_path / "b.json").write_bytes(doc(2))
    (tmp_path / "bad.json").write_bytes(b"{nope")
    (tmp_path / "note.txt").write_text("ignore me")
    (tmp_path / "dup.json").write_bytes(doc(1, awsRegion="r1"))  # same content as a.json
    svc.scan_existing()
    assert svc.flush_if_due()
    assert sent == [["a.json", "b.json"]]
    assert len(list((tmp_path / "processed").iterdir())) == 2
    assert len(list((tmp_path / "rejected").iterdir())) == 2  # bad + dup
    assert (tmp_path / "note.txt").exists()


def test_failed_sink_moves_files_to_failed(tmp_path):
    def boom(paths):
        raise RuntimeError("api down")

    svc = IngestorService(tmp_path, boom, 1, 999)
    (tmp_path / "a.json").write_bytes(doc())
    svc.scan_existing()
    assert svc.flush_if_due() is False
    assert len(list((tmp_path / "failed").iterdir())) == 1
