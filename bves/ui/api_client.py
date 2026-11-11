"""Tiny HTTP client for the BVES API used by the Streamlit pages."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

import requests


class ApiError(Exception):
    """API returned an error response (message is already user-friendly)."""


def fmt_ts(ts: int | None) -> str:
    """Format a unix timestamp as UTC."""
    if ts is None:
        return "-"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


class ApiClient:
    """Thin wrapper that adds the bearer token and unwraps error payloads."""

    def __init__(self, base_url: str | None = None, token: str | None = None) -> None:
        self.base = (base_url or os.environ.get("API_URL", "http://localhost:8000")).rstrip("/")
        self.token = token

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    def _req(self, method: str, path: str, **kw: Any) -> requests.Response:
        try:
            r = requests.request(method, self.base + path, headers=self._headers(), timeout=120, **kw)
        except requests.RequestException as exc:
            raise ApiError(f"Cannot reach API at {self.base}: {exc}") from exc
        if r.status_code >= 400:
            try:
                msg = r.json()["error"]["message"]
            except Exception:  # noqa: BLE001
                msg = r.text[:300]
            raise ApiError(f"{r.status_code}: {msg}")
        return r

    def login(self, username: str, password: str) -> dict[str, Any]:
        return self._req("POST", "/auth/login", json={"username": username, "password": password}).json()

    def stats(self) -> dict[str, Any]:
        return self._req("GET", "/stats").json()

    def submit(self, case_id: str, files: list[tuple[str, bytes]]) -> dict[str, Any]:
        multipart = [("files", (n, d, "application/octet-stream")) for n, d in files]
        return self._req("POST", "/evidence/submit", data={"case_id": case_id}, files=multipart).json()

    def verify(self, filename: str, data: bytes, batch_id: int | None = None) -> dict[str, Any]:
        form = {"batch_id": str(batch_id)} if batch_id else {}
        return self._req("POST", "/evidence/verify", data=form, files={"file": (filename, data)}).json()

    def list_batches(self, q: str | None = None) -> list[dict[str, Any]]:
        return self._req("GET", "/evidence", params={"q": q} if q else {}).json()

    def batch(self, batch_id: int) -> dict[str, Any]:
        return self._req("GET", f"/evidence/{batch_id}").json()

    def custody(self, batch_id: int) -> list[dict[str, Any]]:
        return self._req("GET", f"/evidence/{batch_id}/custody").json()

    def transfer(self, batch_id: int, new_custodian: str, reason: str) -> dict[str, Any]:
        return self._req("POST", f"/evidence/{batch_id}/transfer",
                         json={"new_custodian": new_custodian, "reason": reason}).json()

    def download(self, batch_id: int, file_index: int) -> bytes:
        return self._req("GET", f"/evidence/{batch_id}/download", params={"file_index": file_index}).content

    def audit_log(self, action: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"limit": limit}
        if action:
            params["action"] = action
        return self._req("GET", "/audit-log", params=params).json()
