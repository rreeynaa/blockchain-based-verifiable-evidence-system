"""Folder monitor: watch ./incoming, validate, batch, and hand off to a sink."""

from __future__ import annotations

import argparse
import logging
import shutil
import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from core.config import get_settings
from core.crypto import sha256_file
from core.errors import InvalidEvidenceError
from ingestor.validator import validate_cloudtrail

log = logging.getLogger("bves.ingestor")

Sink = Callable[[list[Path]], None]


class Batcher:
    """Collects files; a batch is due on a count threshold or a time window."""

    def __init__(self, threshold: int, window_s: float, clock: Callable[[], float] = time.monotonic):
        self.threshold, self.window_s, self.clock = threshold, window_s, clock
        self._items: list[Path] = []
        self._hashes: set[str] = set()
        self._first: float | None = None
        self._lock = threading.Lock()

    def add(self, path: Path, digest: str) -> bool:
        """Queue ``path``. Returns False if identical content is already queued."""
        with self._lock:
            if digest in self._hashes:
                return False
            if not self._items:
                self._first = self.clock()
            self._items.append(path)
            self._hashes.add(digest)
            return True

    def due(self) -> bool:
        """True when the threshold is reached or the window has elapsed."""
        with self._lock:
            if not self._items:
                return False
            return len(self._items) >= self.threshold or (
                self._first is not None and self.clock() - self._first >= self.window_s
            )

    def take(self) -> list[Path]:
        """Remove and return everything queued."""
        with self._lock:
            items, self._items, self._hashes, self._first = self._items, [], set(), None
            return items


class IngestorService:
    """Validates incoming files and flushes batches to ``sink``."""

    def __init__(self, incoming: Path, sink: Sink, threshold: int, window_s: float) -> None:
        self.incoming = incoming
        self.sink = sink
        self.batcher = Batcher(threshold, window_s)
        for sub in ("processed", "rejected", "failed"):
            (incoming / sub).mkdir(parents=True, exist_ok=True)

    def _move(self, path: Path, sub: str) -> None:
        dest = self.incoming / sub / f"{int(time.time())}_{path.name}"
        shutil.move(str(path), dest)

    @staticmethod
    def _wait_stable(path: Path, timeout: float = 5.0) -> None:
        """Wait until the file size stops changing (writer finished)."""
        last, deadline = -1, time.time() + timeout
        while time.time() < deadline:
            size = path.stat().st_size
            if size == last:
                return
            last = size
            time.sleep(0.2)

    def process_file(self, path: Path) -> bool:
        """Validate and queue one file. Returns True if queued."""
        if path.suffix.lower() != ".json" or path.parent != self.incoming or not path.exists():
            return False
        self._wait_stable(path)
        try:
            validate_cloudtrail(path.read_bytes())
        except InvalidEvidenceError as exc:
            log.warning("rejected %s: %s", path.name, exc)
            self._move(path, "rejected")
            return False
        if not self.batcher.add(path, sha256_file(path)):
            log.warning("rejected %s: duplicate content already queued", path.name)
            self._move(path, "rejected")
            return False
        log.info("queued %s", path.name)
        return True

    def flush_if_due(self, force: bool = False) -> bool:
        """Send the queued batch to the sink if due (or ``force``)."""
        if not (force or self.batcher.due()):
            return False
        paths = self.batcher.take()
        if not paths:
            return False
        try:
            self.sink(paths)
        except Exception as exc:  # noqa: BLE001
            log.error("batch of %d failed: %s", len(paths), exc)
            for p in paths:
                self._move(p, "failed")
            return False
        for p in paths:
            self._move(p, "processed")
        log.info("batch of %d file(s) submitted", len(paths))
        return True

    def scan_existing(self) -> None:
        """Pick up files already sitting in the folder at start-up."""
        for p in sorted(self.incoming.glob("*.json")):
            self.process_file(p)

    def run(self) -> None:
        """Block forever, watching the folder with watchdog."""
        from watchdog.events import FileSystemEventHandler
        from watchdog.observers import Observer

        svc = self

        class Handler(FileSystemEventHandler):
            def on_created(self, event):  # type: ignore[no-untyped-def]
                if not event.is_directory:
                    svc.process_file(Path(event.src_path))

            def on_moved(self, event):  # type: ignore[no-untyped-def]
                if not event.is_directory:
                    svc.process_file(Path(event.dest_path))

        observer = Observer()
        observer.schedule(Handler(), str(self.incoming), recursive=False)
        observer.start()
        log.info("watching %s", self.incoming)
        self.scan_existing()
        try:
            while True:
                self.flush_if_due()
                time.sleep(1)
        finally:
            observer.stop()
            observer.join()


class ApiSink:
    """Submits a batch through the BVES API (keeps DB cache and audit log consistent)."""

    def __init__(self, api_url: str, username: str, password: str, case_id: str | None = None):
        self.api_url, self.username, self.password = api_url.rstrip("/"), username, password
        self.case_id = case_id

    def __call__(self, paths: list[Path]) -> None:
        import requests

        r = requests.post(
            f"{self.api_url}/auth/login",
            json={"username": self.username, "password": self.password},
            timeout=15,
        )
        r.raise_for_status()
        token = r.json()["access_token"]
        case = self.case_id or f"AUTO-{datetime.now(timezone.utc):%Y%m%d}"
        files = [("files", (p.name, p.read_bytes(), "application/json")) for p in paths]
        r = requests.post(
            f"{self.api_url}/evidence/submit",
            headers={"Authorization": f"Bearer {token}"},
            data={"case_id": case},
            files=files,
            timeout=120,
        )
        r.raise_for_status()
        log.info("batch %s anchored in tx %s", r.json()["batch_id"], r.json()["tx_hash"])


def main() -> None:
    """CLI entry point: ``python -m ingestor.watcher``."""
    import os

    s = get_settings()
    ap = argparse.ArgumentParser(description="BVES folder ingestor")
    ap.add_argument("--dir", default=s.incoming_dir)
    ap.add_argument("--batch-size", type=int, default=s.batch_size)
    ap.add_argument("--window", type=float, default=s.batch_window_seconds)
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    sink = ApiSink(
        s.api_url,
        os.environ.get("INGESTOR_USER", "investigator"),
        os.environ.get("INGESTOR_PASSWORD", s.investigator_password),
        os.environ.get("CASE_ID"),
    )
    IngestorService(Path(args.dir), sink, args.batch_size, args.window).run()


if __name__ == "__main__":
    main()
