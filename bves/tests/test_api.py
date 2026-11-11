"""API tests with in-memory chain/IPFS and SQLite. Skipped if FastAPI isn't installed."""

import os

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from api.main import create_app  # noqa: E402
from core.crypto import LocalFileKeyProvider  # noqa: E402
from tests.fakes import FakeChain, FakeIPFS  # noqa: E402

A = [("a.json", b'{"Records":[{"n":1}]}'), ("b.json", b'{"Records":[{"n":2}]}'), ("c.json", b'{"Records":[{"n":3}]}')]


@pytest.fixture
def ctx():
    os.environ.setdefault("JWT_SECRET", "test-secret")
    from sqlalchemy import create_engine  # in-memory SQLite needs one shared connection

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    chain, ipfs = FakeChain(), FakeIPFS()
    app = create_app(chain=chain, ipfs=ipfs, keys=LocalFileKeyProvider(os.urandom(32)), engine=engine)
    with TestClient(app) as client:
        yield client, chain, ipfs


def login(client, user):
    pw = {"investigator": "investigator123", "auditor": "auditor123", "admin": "admin123"}[user]
    r = client.post("/auth/login", json={"username": user, "password": pw})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def submit(client, h, files=A, case="CASE-1"):
    return client.post("/evidence/submit", headers=h, data={"case_id": case},
                       files=[("files", (n, d, "application/json")) for n, d in files])


def test_login_failure_and_unauthenticated(ctx):
    client, *_ = ctx
    assert client.post("/auth/login", json={"username": "investigator", "password": "x"}).status_code == 401
    assert client.get("/evidence").status_code == 401
    assert client.get("/evidence", headers={"Authorization": "Bearer junk"}).status_code == 401


def test_rbac(ctx):
    client, *_ = ctx
    inv, aud = login(client, "investigator"), login(client, "auditor")
    assert submit(client, aud).status_code == 403
    assert client.get("/audit-log", headers=inv).status_code == 403
    assert client.get("/audit-log", headers=aud).status_code == 200


def test_submit_verify_download_flow(ctx):
    client, chain, _ = ctx
    inv, aud = login(client, "investigator"), login(client, "auditor")
    r = submit(client, inv)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["batch_id"] == 1 and len(body["files"]) == 3 and body["tx_hash"].startswith("0x")
    assert chain.get_batch(1).merkle_root == body["merkle_root"]

    ok = client.post("/evidence/verify", headers=aud, files={"file": ("b.json", A[1][1])})
    assert ok.json()["status"] == "VERIFIED" and ok.json()["inclusion_valid"] is True

    tampered = bytearray(A[1][1]); tampered[3] ^= 1
    bad = client.post("/evidence/verify", headers=aud, files={"file": ("b.json", bytes(tampered))})
    assert bad.json()["status"] == "TAMPERED"
    assert bad.json()["expected_hash"] != bad.json()["computed_hash"]

    unknown = client.post("/evidence/verify", headers=aud, files={"file": ("zzz.json", b"never seen")})
    assert unknown.json()["status"] == "NOT_FOUND"

    d = client.get("/evidence/1/download", headers=inv, params={"file_index": 2})
    assert d.status_code == 200 and d.content == A[2][1]
    assert client.get("/evidence/1/download", headers=aud).status_code == 403
    assert client.get("/evidence/1/download", headers=inv).headers["content-type"] == "application/zip"

    s = client.get("/stats", headers=aud).json()
    assert (s["batches"], s["files"], s["verifications_passed"], s["verifications_failed"]) == (1, 3, 1, 1)


def test_verify_survives_empty_cache(ctx):
    """Chain is the source of truth: clearing the DB must not break verification."""
    client, *_ = ctx
    inv, aud = login(client, "investigator"), login(client, "auditor")
    submit(client, inv)
    from api.models import FileCache

    with client.app.state.session_factory() as db:
        db.query(FileCache).delete()
        db.commit()
    r = client.post("/evidence/verify", headers=aud, files={"file": ("x.json", A[0][1])})
    assert r.json()["status"] == "VERIFIED"


def test_detail_custody_transfer_and_audit(ctx):
    client, *_ = ctx
    inv, aud = login(client, "investigator"), login(client, "auditor")
    submit(client, inv)
    detail = client.get("/evidence/1", headers=aud).json()
    assert detail["root_consistent"] and [f["filename"] for f in detail["files"]] == ["a.json", "b.json", "c.json"]
    to = "0x" + "ab" * 20
    t = client.post("/evidence/1/transfer", headers=inv, json={"new_custodian": to, "reason": "handover"})
    assert t.status_code == 200
    log = client.get("/evidence/1/custody", headers=aud).json()
    assert [e["reason"] for e in log] == ["Initial registration", "handover"]
    assert client.post("/evidence/1/transfer", headers=aud, json={"new_custodian": to, "reason": "x"}).status_code == 403
    assert client.post("/evidence/1/transfer", headers=inv, json={"new_custodian": "nope", "reason": "x"}).status_code == 422
    actions = [r["action"] for r in client.get("/audit-log", headers=aud).json()]
    assert {"LOGIN", "SUBMIT", "TRANSFER"} <= set(actions)


def test_errors_are_structured(ctx):
    client, *_ = ctx
    inv = login(client, "investigator")
    assert client.get("/evidence/99", headers=inv).status_code == 404
    assert client.get("/evidence/99", headers=inv).json()["error"]["code"] == "not_found"
    assert submit(client, inv, case="bad case!").status_code == 422
    assert submit(client, inv).status_code == 200
    dup = submit(client, inv)  # same content => same root
    assert dup.status_code == 409 and dup.json()["error"]["code"] == "chain_error"


def test_search(ctx):
    client, *_ = ctx
    inv = login(client, "investigator")
    submit(client, inv, case="ALPHA")
    submit(client, inv, files=[("only.json", b'{"Records":[{"x":9}]}')], case="BETA")
    assert [b["case_id"] for b in client.get("/evidence", headers=inv, params={"q": "only.json"}).json()] == ["BETA"]
    assert len(client.get("/evidence", headers=inv).json()) == 2
