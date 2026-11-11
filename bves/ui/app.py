"""BVES Streamlit entry point: login + dashboard. Run: streamlit run ui/app.py"""

import pandas as pd
import streamlit as st

from ui.api_client import ApiClient, ApiError

st.set_page_config(page_title="BVES", page_icon="", layout="wide")
st.title("BVES: Blockchain-Based Verifiable Evidence System")
st.caption("Tamper-evident storage and verification of cloud-intrusion logs")

if "token" not in st.session_state:
    st.subheader("Sign in")
    with st.form("login"):
        username = st.selectbox("User", ["investigator", "auditor", "admin"])
        password = st.text_input("Password", type="password")
        if st.form_submit_button("Log in"):
            try:
                res = ApiClient().login(username, password)
                st.session_state.update(token=res["access_token"], role=res["role"], username=username)
                st.rerun()
            except ApiError as exc:
                st.error(str(exc))
    st.info("Demo accounts: investigator / auditor / admin. Passwords are set in `.env`.")
    st.stop()

role = st.session_state["role"]
with st.sidebar:
    st.markdown(f"**{st.session_state['username']}** · `{role}`")
    if st.button("Log out"):
        st.session_state.clear()
        st.rerun()

st.subheader("Dashboard")
try:
    s = ApiClient(token=st.session_state["token"]).stats()
except ApiError as exc:
    st.error(str(exc))
    st.stop()

c1, c2, c3, c4 = st.columns(4)
c1.metric("Batches on-chain", s["batches"])
c2.metric("Files anchored", s["files"])
c3.metric("Verifications passed", s["verifications_passed"])
c4.metric("Verifications failed (tampered)", s["verifications_failed"])

if s["verifications_passed"] + s["verifications_failed"]:
    st.bar_chart(
        pd.DataFrame(
            {"count": [s["verifications_passed"], s["verifications_failed"]]},
            index=["VERIFIED", "TAMPERED"],
        )
    )

st.markdown(
    {
        "investigator": "Use **Submit Evidence** to anchor new logs, **Batches** to view them and transfer custody, and **Verify** to check a file.",
        "auditor": "You have read-only access: search **Batches**, **Verify** files, and review the **Audit Log**.",
        "admin": "You can view batches, verify files and review the **Audit Log**.",
    }[role]
)
