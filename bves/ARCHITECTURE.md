# BVES Architecture

## Data flow (submit)

1. **Ingest**: `ingestor/` watches `./incoming`, validates CloudTrail shape (`Records[]` with
   `eventTime/eventSource/eventName`), de-duplicates identical content, and flushes a batch when
   `BATCH_SIZE` files are queued or `BATCH_WINDOW_SECONDS` elapse. Rejected files go to
   `incoming/rejected/`, failures to `incoming/failed/`. It submits through the API so the cache and
   audit log stay consistent.
2. **Hash**: SHA-256 of each file's plaintext → leaf values.
3. **Merkle**: `core/crypto/merkle.py` builds the tree and per-file proofs.
   * leaf = `SHA256(0x00‖leaf)`, node = `SHA256(0x01‖left‖right)` (domain separation, blocks
     inner-node-as-leaf second-preimage tricks);
   * proof steps record left/right (index-aware);
   * an odd node is **promoted**, not duplicated, so `[a,b,c]` and `[a,b,c,c]` differ.
4. **Encrypt**: fresh AES-256 data key + 96-bit nonce per file (AES-GCM). The data key is wrapped by
   the master key (`KeyProvider`: interface + `LocalFileKeyProvider`; swap in KMS/Vault). The blob
   `BVES1 | len | header(json: nonce, wrapped key, key id) | ciphertext+tag` is self-contained.
5. **Store**: `core/ipfs.py` adds the blob via Kubo `/api/v0/add` (retries, timeouts) → CID.
6. **Anchor**: `EvidenceRegistry.registerBatch(caseId, root, fileHashes[], cids[])`.
7. **Cache**: API stores batch/file rows (with filenames, which are *not* on-chain) and an audit row.

## Verification

`core/verify.py::verify_evidence` reads the batch and all file hashes **from the contract**, then:
recompute upload SHA-256 → compare with the on-chain hash at that slot → fold the Merkle proof from
the *uploaded* hash → compare with the on-chain root → cross-check `verifyFileHash`/`verifyRoot`
→ check that the on-chain hashes themselves reproduce the on-chain root (the contract trusts the
submitter's root at registration; verifiers recompute it).

The DB is used only to guess *which batch to look in* (hash match, else filename for modified
copies). If the cache misses, the API scans the chain by hash.

## Contract (`contracts/EvidenceRegistry.sol`)

* OpenZeppelin `AccessControl`; roles `ADMIN_ROLE`, `INVESTIGATOR_ROLE`, `AUDITOR_ROLE`.
  `ADMIN_ROLE` administers the other two.
* Append-only by construction: the only state-changing functions are `registerBatch`,
  `transferCustody` (plus standard role management). Duplicate Merkle roots revert.
* Custody log: entry 0 is registration (`from = 0x0`). Transfers by the current custodian (if still an
  investigator) or an admin; each emits `CustodyTransferred`.
* Deploy script writes `shared/deployment.json` (`address`, `abi`, `chainId`) read by the backend.

## Trust boundaries and key decisions

| Component | Trusted for | Not trusted for |
|---|---|---|
| Chain (contract state) | integrity/order of anchored records | confidentiality (public), pre-anchor authenticity |
| IPFS | availability of ciphertext (best effort) | integrity (GCM + hashes catch changes) |
| PostgreSQL | convenience (search, filenames, audit log) | any verification verdict |
| API / signer key | honest submission and role enforcement | n/a: compromise lets it anchor false data |

* **Single backend signer.** Simpler for a demo; the on-chain submitter is the service. Per-user
  wallets/signatures would bind individuals on-chain.
* **Plaintext hash on-chain.** Required so anyone with a file can verify without keys; leaks only
  "this exact file was registered".
* **Failure modes.** IPFS ok + chain fails → orphan ciphertext (encrypted, harmless). Chain ok + DB
  fails → submit still succeeds; `reconcile()` backfills the cache from chain on next start (filenames
  become "unknown" for those rows). Dev chain reset → stale cache cleared on start.

## Evaluation

`scripts/evaluate.py` measures tamper-detection accuracy, per-file pipeline latency and gas versus
batch size, and IPFS retrieve+decrypt success; it writes CSVs and a Markdown report.
Gas grows ~linearly with batch size (two storage writes of hash and CID per file); the fixed cost
is amortised, so per-file gas falls as batches grow.
