#!/usr/bin/env python3
"""Tamper demo: submit samples, flip ONE byte of a stored file, show verification fail.

Needs the stack running (``docker compose up``). Usage::

    python scripts/tamper_demo.py [--api http://localhost:8000]

Each run stamps the sample JSON with a unique ``DemoRun`` field so it can be re-run
(the contract rejects duplicate Merkle roots by design).
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import uuid
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

G, R, Y, B, X = "\033[92m", "\033[91m", "\033[93m", "\033[1m", "\033[0m"


def step(n: int, msg: str) -> None:
    print(f"\n{B}[{n}] {msg}{X}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default=os.environ.get("API_URL", "http://localhost:8000"))
    ap.add_argument("--seed", type=int, default=None, help="seed for the random byte position")
    args = ap.parse_args()
    api = args.api.rstrip("/")
    rnd = random.Random(args.seed)

    def login(user: str, pw: str) -> dict:
        r = requests.post(f"{api}/auth/login", json={"username": user, "password": pw}, timeout=15)
        r.raise_for_status()
        return {"Authorization": f"Bearer {r.json()['access_token']}"}

    inv = login("investigator", os.environ.get("INVESTIGATOR_PASSWORD", "investigator123"))
    aud = login("auditor", os.environ.get("AUDITOR_PASSWORD", "auditor123"))

    step(1, "Submit the four sample intrusion logs as one batch")
    run = uuid.uuid4().hex[:8]
    files = []
    for p in sorted((ROOT / "samples").glob("*.json")):
        doc = json.loads(p.read_text())
        doc["DemoRun"] = run
        files.append((p.name, json.dumps(doc, indent=2, sort_keys=True).encode()))
    r = requests.post(
        f"{api}/evidence/submit", headers=inv, data={"case_id": f"DEMO-{run}"},
        files=[("files", (n, d, "application/json")) for n, d in files], timeout=120,
    )
    r.raise_for_status()
    batch = r.json()
    print(f"  batch #{batch['batch_id']}  root={batch['merkle_root']}")
    print(f"  tx={batch['tx_hash']}  block={batch['block_number']}  gas={batch['gas_used']:,}")
    for f in batch["files"]:
        print(f"    {f['index']}: {f['filename']:<28} cid={f['cid'][:20]}…")

    def verify(name: str, data: bytes) -> dict:
        r = requests.post(f"{api}/evidence/verify", headers=aud, files={"file": (name, data)}, timeout=60)
        r.raise_for_status()
        return r.json()

    step(2, "Verify the untouched originals (auditor)")
    for name, data in files:
        v = verify(name, data)
        print(f"  {name:<28} {G if v['status'] == 'VERIFIED' else R}{v['status']}{X}")

    step(3, "Retrieve a stored file from IPFS (decrypted), then flip ONE byte")
    name, _ = files[0]
    idx = next(f["index"] for f in batch["files"] if f["filename"] == name)
    d = requests.get(f"{api}/evidence/{batch['batch_id']}/download", headers=inv,
                     params={"file_index": idx}, timeout=60)
    d.raise_for_status()
    original = d.content
    pos = rnd.randrange(len(original))
    mutated = bytearray(original)
    mutated[pos] ^= 0x01
    print(f"  file={name}  size={len(original)}  byte[{pos}]: 0x{original[pos]:02x} -> 0x{mutated[pos]:02x}")

    step(4, "Verify the modified copy")
    v = verify(name, bytes(mutated))
    colour = R if v["status"] == "TAMPERED" else Y
    print(f"  result : {colour}{v['status']}{X}")
    print(f"  detail : {v['detail']}")
    print(f"  expected hash : {v['expected_hash']}")
    print(f"  computed hash : {v['computed_hash']}")
    print(f"  on-chain root : {v['onchain_root']}")
    print(f"  recomputed    : {v['recomputed_root']}  (does not match)")
    ok = v["status"] == "TAMPERED"

    step(5, "Bonus: flip one byte of the encrypted blob and try to decrypt")
    try:
        from core.config import get_settings
        from core.crypto import LocalFileKeyProvider, decrypt
        from core.ipfs import IPFSClient
        from cryptography.exceptions import InvalidTag

        s = get_settings()
        ipfs = IPFSClient(os.environ.get("IPFS_API_URL", "http://localhost:5001"), retries=1)
        blob = bytearray(ipfs.cat(batch["files"][idx]["cid"]))
        keys = LocalFileKeyProvider.from_settings(s.master_key_file, s.master_key_b64)
        assert decrypt(bytes(blob), keys) == original, "sanity check failed"
        blob[-5] ^= 0x01
        try:
            decrypt(bytes(blob), keys)
            print(f"  {R}decryption unexpectedly succeeded{X}")
            ok = False
        except InvalidTag:
            print(f"  {G}AES-GCM authentication failed: stored ciphertext tampering is detected{X}")
    except Exception as exc:  # noqa: BLE001
        print(f"  {Y}skipped ({type(exc).__name__}: {exc}); needs IPFS on localhost:5001 and shared/master.key{X}")

    print(f"\n{B}{G if ok else R}{'DEMO OK: tampering was detected.' if ok else 'DEMO FAILED.'}{X}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
