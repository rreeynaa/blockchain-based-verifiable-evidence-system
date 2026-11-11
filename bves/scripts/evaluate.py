#!/usr/bin/env python3
"""Evaluation harness. Writes CSVs and a Markdown report to ./eval_results.

Online (default; needs the docker stack up):
    python scripts/evaluate.py
Offline (in-memory chain + IPFS; no gas data, latencies are NOT representative):
    python scripts/evaluate.py --offline

Metrics:
  1. Tamper-detection accuracy over N random single-byte modifications (expect 100%).
  2. Pipeline latency per file vs batch size.
  3. On-chain gas per registration vs batch size.
  4. IPFS retrieve + decrypt round-trip success rate.
"""

from __future__ import annotations

import argparse
import csv
import os
import random
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.config import get_settings  # noqa: E402
from core.crypto import LocalFileKeyProvider  # noqa: E402
from core.pipeline import EvidencePipeline  # noqa: E402
from core.verify import verify_evidence  # noqa: E402


def make_files(rnd: random.Random, n: int, size: int) -> list[tuple[str, bytes]]:
    """Unique pseudo-CloudTrail payloads (unique => unique Merkle roots every run)."""
    out = []
    for i in range(n):
        body = ('{"Records":[{"eventName":"X","nonce":"%s"}],"pad":"%s"}'
                % (rnd.getrandbits(64), "a" * max(0, size - 80))).encode()
        out.append((f"eval-{i}.json", body))
    return out


def build(offline: bool):
    keys = LocalFileKeyProvider(os.urandom(32)) if offline else LocalFileKeyProvider.from_settings(
        get_settings().master_key_file, get_settings().master_key_b64)
    if offline:
        from tests.fakes import FakeChain, FakeIPFS

        return EvidencePipeline(FakeChain(), FakeIPFS(), keys)
    from core.chain import Web3Chain
    from core.ipfs import IPFSClient

    s = get_settings()
    return EvidencePipeline(
        Web3Chain(s.rpc_url, s.deployment_file, s.signer_private_key), IPFSClient(s.ipfs_api_url), keys)


def eval_tamper(p: EvidencePipeline, rnd: random.Random, n: int) -> dict:
    files = make_files(rnd, 8, 2048)
    res = p.submit("EVAL-TAMPER", files)
    detected = 0
    for _ in range(n):
        i = rnd.randrange(len(files))
        data = bytearray(files[i][1])
        data[rnd.randrange(len(data))] ^= rnd.randrange(1, 256)
        v = verify_evidence(p.chain, bytes(data), res.batch_id, index=i)
        detected += v["status"] == "TAMPERED"
    # control: untouched files must verify
    clean = sum(verify_evidence(p.chain, d, res.batch_id)["status"] == "VERIFIED" for _, d in files)
    return {"trials": n, "detected": detected, "accuracy_pct": 100 * detected / n,
            "clean_verified": f"{clean}/{len(files)}"}


def eval_pipeline(p: EvidencePipeline, rnd: random.Random, sizes: list[int], reps: int, fsize: int):
    rows = []
    for n in sizes:
        tot, gas, stages = [], [], {k: [] for k in ("hash", "merkle", "encrypt", "ipfs", "chain")}
        for _ in range(reps):
            r = p.submit(f"EVAL-{n}", make_files(rnd, n, fsize))
            tot.append(r.timings_ms["total"])
            gas.append(r.receipt.gas_used)
            for k in stages:
                stages[k].append(r.timings_ms[k])
        m = statistics.mean
        rows.append({
            "batch_size": n, "total_ms": round(m(tot), 1), "per_file_ms": round(m(tot) / n, 1),
            **{f"{k}_ms": round(m(v), 1) for k, v in stages.items()},
            "gas": round(m(gas)), "gas_per_file": round(m(gas) / n),
        })
    return rows


def eval_roundtrip(p: EvidencePipeline, rnd: random.Random, n: int) -> dict:
    files = make_files(rnd, n, 4096)
    res = p.submit("EVAL-RT", files)
    ok, lat = 0, []
    for i, (_, data) in enumerate(files):
        t = time.perf_counter()
        try:
            ok += p.retrieve(res.batch_id, i) == data
        except Exception:  # noqa: BLE001
            pass
        lat.append((time.perf_counter() - t) * 1000)
    return {"trials": n, "success": ok, "success_rate_pct": 100 * ok / n,
            "mean_latency_ms": round(statistics.mean(lat), 1)}


def write_csv(path: Path, rows: list[dict]) -> None:
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def md_table(rows: list[dict]) -> str:
    cols = list(rows[0])
    lines = ["| " + " | ".join(cols) + " |", "|" + "|".join("---" for _ in cols) + "|"]
    lines += ["| " + " | ".join(str(r[c]) for c in cols) + " |" for r in rows]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--n-tamper", type=int, default=1000)
    ap.add_argument("--n-roundtrip", type=int, default=50)
    ap.add_argument("--sizes", type=int, nargs="+", default=[1, 2, 4, 8, 16, 32])
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--file-size", type=int, default=10_000)
    ap.add_argument("--seed", type=int, default=1234)
    ap.add_argument("--out", default=str(ROOT / "eval_results"))
    a = ap.parse_args()

    rnd, out = random.Random(a.seed), Path(a.out)
    out.mkdir(exist_ok=True)
    p = build(a.offline)
    mode = "OFFLINE (in-memory fakes)" if a.offline else "ONLINE (Hardhat + Kubo)"
    print(f"Mode: {mode}")

    print(f"[1/3] tamper detection x{a.n_tamper} ...")
    t = eval_tamper(p, rnd, a.n_tamper)
    print(f"[2/3] pipeline latency / gas, sizes {a.sizes} x{a.reps} ...")
    pl = eval_pipeline(p, rnd, a.sizes, a.reps, a.file_size)
    print(f"[3/3] IPFS round-trip x{a.n_roundtrip} ...")
    rt = eval_roundtrip(p, rnd, a.n_roundtrip)

    write_csv(out / "tamper_detection.csv", [t])
    write_csv(out / "pipeline_gas_vs_batch.csv", pl)
    write_csv(out / "ipfs_roundtrip.csv", [rt])

    gas_note = "" if not a.offline else "\n> Offline mode: gas is a fixed placeholder (21000) and latency excludes real IPFS/chain I/O.\n"
    report = f"""# BVES Evaluation Results

Mode: **{mode}** · seed {a.seed} · file size ≈ {a.file_size:,} B · {a.reps} reps per batch size
{gas_note}
## 1. Tamper detection (single-byte modifications)

{md_table([t])}

## 2. Pipeline latency and on-chain gas vs batch size

{md_table(pl)}

`per_file_ms` = total / batch size. Stage columns are mean ms per batch.

## 3. IPFS retrieve + decrypt round trip

{md_table([rt])}
"""
    (out / "report.md").write_text(report)
    print("\n" + report)
    print(f"Wrote CSVs and report.md to {out}")
    return 0 if t["accuracy_pct"] == 100 and rt["success_rate_pct"] == 100 else 1


if __name__ == "__main__":
    raise SystemExit(main())
