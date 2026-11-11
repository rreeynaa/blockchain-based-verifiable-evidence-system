"""Drag-and-drop verification with proof path, tx info and custody timeline."""

import streamlit as st

from ui.api_client import ApiError, fmt_ts
from ui.common import custody_timeline, proof_table, require_login

api = require_login()
st.title("Verify evidence")
st.caption("The file's SHA-256 is recomputed and checked against the Merkle root stored **on the blockchain**.")

f = st.file_uploader("Drag & drop a file to verify")
batch = st.number_input("Batch ID (optional, narrows the search)", min_value=0, value=0, step=1)

if f and st.button("Verify", type="primary"):
    try:
        res = api.verify(f.name, f.getvalue(), int(batch) or None)
    except ApiError as exc:
        st.error(str(exc))
        st.stop()

    banners = {
        "VERIFIED": ("#1b8a3a", "✅ VERIFIED: file is identical to the anchored original"),
        "TAMPERED": ("#c62828", "❌ TAMPERED: file does NOT match the anchored record"),
        "NOT_FOUND": ("#ef6c00", "⚠️ NOT FOUND: no anchored file matches"),
    }
    color, text = banners[res["status"]]
    st.markdown(
        f"<div style='background:{color};color:white;padding:18px;border-radius:8px;"
        f"font-size:1.4rem;font-weight:700;text-align:center'>{text}</div>",
        unsafe_allow_html=True,
    )
    st.write(res["detail"])

    if res["status"] != "NOT_FOUND":
        c1, c2 = st.columns(2)
        c1.write("**Expected hash (on-chain)**"); c1.code(res["expected_hash"])
        c2.write("**Computed hash (uploaded file)**"); c2.code(res["computed_hash"])
        c1.write("**Anchored Merkle root**"); c1.code(res["onchain_root"])
        c2.write("**Root recomputed from upload + proof**"); c2.code(res["recomputed_root"])

        st.write(
            f"**Batch** #{res['batch_id']} · case `{res['case_id']}` · file #{res['file_index']}  \n"
            f"**Tx hash** `{res['tx_hash']}` · **Block** {res['block_number']} · **Time** {fmt_ts(res['timestamp'])}"
        )
        st.markdown("#### Merkle proof path")
        proof_table(res["merkle_proof"])
        st.markdown("#### Chain of custody")
        try:
            custody_timeline(api.custody(res["batch_id"]))
        except ApiError as exc:
            st.error(str(exc))
    else:
        st.write("Computed SHA-256:"); st.code(res["computed_hash"])
