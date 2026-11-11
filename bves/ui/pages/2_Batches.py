"""Browse/search batches, inspect files and custody, transfer custody, download."""

import streamlit as st

from ui.api_client import ApiError, fmt_ts
from ui.common import custody_timeline, proof_table, require_login

api = require_login()
role = st.session_state["role"]
st.title("Evidence batches")

q = st.text_input("Search (case ID, filename, SHA-256, CID, root, tx hash)")
try:
    rows = api.list_batches(q or None)
except ApiError as exc:
    st.error(str(exc))
    st.stop()

if not rows:
    st.info("No batches found.")
    st.stop()

st.dataframe(
    [{"batch": r["batch_id"], "case": r["case_id"], "files": r["file_count"], "when": fmt_ts(r["timestamp"]),
      "block": r["block_number"], "by": r["created_by"], "root": r["merkle_root"][:16] + "…"} for r in rows],
    use_container_width=True,
)

batch_id = st.selectbox("Open batch", [r["batch_id"] for r in rows])
try:
    b = api.batch(batch_id)
    custody = api.custody(batch_id)
except ApiError as exc:
    st.error(str(exc))
    st.stop()

st.subheader(f"Batch #{b['batch_id']} · {b['case_id']}")
if not b["root_consistent"]:
    st.error("On-chain file hashes do NOT reproduce the anchored Merkle root!")
st.write("**Merkle root (on-chain)**", f"`{b['merkle_root']}`")
st.write("**Registered**", fmt_ts(b["timestamp"]), "by", f"`{b['submitter']}`")
st.write("**Tx / block**", f"`{b['tx_hash']}`", "/", b["block_number"])
st.write("**Current custodian**", f"`{b['current_custodian']}`")

st.markdown("#### Files")
for f in b["files"]:
    with st.expander(f"{f['index']}. {f['filename']}"):
        st.write("SHA-256", f"`{f['file_hash']}`")
        st.write("CID", f"`{f['cid']}`")
        proof_table(f["merkle_proof"])
        if role == "investigator":
            if st.button("Prepare download (decrypt from IPFS)", key=f"dl{f['index']}"):
                try:
                    data = api.download(b["batch_id"], f["index"])
                    st.download_button("Save file", data, file_name=f["filename"], key=f"save{f['index']}")
                except ApiError as exc:
                    st.error(str(exc))

st.markdown("#### Chain of custody")
custody_timeline(custody)

if role == "investigator":
    st.markdown("#### Transfer custody")
    with st.form("transfer"):
        addr = st.text_input("New custodian address (0x…)")
        reason = st.text_input("Reason")
        if st.form_submit_button("Transfer on-chain"):
            try:
                res = api.transfer(b["batch_id"], addr.strip(), reason.strip())
                st.success(f"Custody transferred. Tx `{res['tx_hash']}`")
                st.rerun()
            except ApiError as exc:
                st.error(str(exc))
