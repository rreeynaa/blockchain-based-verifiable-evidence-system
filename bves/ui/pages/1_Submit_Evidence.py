"""Investigator: submit evidence files as one batch."""

import streamlit as st

from ui.api_client import ApiError, fmt_ts
from ui.common import proof_table, require_login

api = require_login("investigator")
st.title("Submit evidence")
st.caption("Files are hashed, Merkle-batched, AES-256-GCM encrypted, stored on IPFS and anchored on-chain.")

case_id = st.text_input("Case ID", value="CASE-2026-001", help="Letters, digits, . _ - only")
uploads = st.file_uploader("CloudTrail JSON logs (or any evidence file)", accept_multiple_files=True)

if st.button("Submit batch", type="primary", disabled=not uploads):
    try:
        with st.spinner("Hashing, encrypting, uploading to IPFS, registering on-chain..."):
            res = api.submit(case_id, [(u.name, u.getvalue()) for u in uploads])
    except ApiError as exc:
        st.error(str(exc))
    else:
        st.success(f"Batch #{res['batch_id']} anchored on-chain")
        st.write("**Merkle root**", f"`{res['merkle_root']}`")
        st.write("**Tx hash**", f"`{res['tx_hash']}`", f"· block {res['block_number']} · {fmt_ts(res['timestamp'])}")
        st.write(f"**Gas used:** {res['gas_used']:,}")
        st.dataframe(
            [{"#": f["index"], "file": f["filename"], "sha256": f["file_hash"], "CID": f["cid"]} for f in res["files"]],
            use_container_width=True,
        )
        with st.expander("Merkle proofs"):
            for f in res["files"]:
                st.markdown(f"**{f['filename']}**")
                proof_table(f["merkle_proof"])
        with st.expander("Pipeline timings (ms)"):
            st.json(res["timings_ms"])
