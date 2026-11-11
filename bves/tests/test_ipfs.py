"""IPFS client: request shape, retry and failure behaviour (HTTP mocked)."""

import requests

from core.errors import IPFSError
from core.ipfs import IPFSClient


class Resp:
    def __init__(self, status=200, json_data=None, content=b"", text=""):
        self.status_code, self._json, self.content, self.text = status, json_data, content, text

    def json(self):
        if self._json is None:
            raise ValueError("no json")
        return self._json


class Session:
    def __init__(self, script):
        self.script, self.calls = list(script), []

    def post(self, url, **kw):
        self.calls.append((url, kw))
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def client(script, retries=3):
    s = Session(script)
    return IPFSClient("http://ipfs:5001/", retries=retries, backoff=0, session=s), s


def test_add_returns_cid_and_requests_pin():
    c, s = client([Resp(json_data={"Hash": "bafyX"})])
    assert c.add(b"data") == "bafyX"
    url, kw = s.calls[0]
    assert url == "http://ipfs:5001/api/v0/add"
    assert kw["params"]["pin"] == "true" and "timeout" in kw


def test_add_parses_ndjson_fallback():
    c, _ = client([Resp(text='{"Name":"a","Hash":"bafyOLD"}\n{"Name":"b","Hash":"bafyNEW"}')])
    assert c.add(b"x") == "bafyNEW"


def test_cat_returns_bytes():
    c, s = client([Resp(content=b"hello")])
    assert c.cat("bafyX") == b"hello"
    assert s.calls[0][1]["params"] == {"arg": "bafyX"}


def test_retries_then_succeeds():
    c, s = client([requests.ConnectionError("down"), requests.Timeout("slow"), Resp(content=b"ok")])
    assert c.cat("c") == b"ok"
    assert len(s.calls) == 3


def test_retries_on_5xx():
    c, s = client([Resp(status=503), Resp(content=b"ok")])
    assert c.cat("c") == b"ok"


def test_gives_up_after_retries():
    c, s = client([requests.ConnectionError("x")] * 3)
    try:
        c.cat("c")
        raise AssertionError("should raise")
    except IPFSError:
        assert len(s.calls) == 3


def test_4xx_fails_fast_without_retry():
    c, s = client([Resp(status=400, text="bad cid")])
    try:
        c.cat("c")
        raise AssertionError("should raise")
    except IPFSError:
        assert len(s.calls) == 1


def test_pin_and_availability():
    c, s = client([Resp(), Resp()])
    c.pin("bafyX")
    assert s.calls[0][0].endswith("/pin/add")
    assert c.is_available() is True
    c2, _ = client([requests.ConnectionError("x")], retries=1)
    assert c2.is_available() is False
