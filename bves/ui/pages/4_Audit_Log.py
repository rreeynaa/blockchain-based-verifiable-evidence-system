"""Auditor/admin: view every recorded action."""

import streamlit as st

from ui.api_client import ApiError
from ui.common import require_login

api = require_login("auditor", "admin")
st.title("Audit log")
action = st.selectbox("Action", ["(all)", "LOGIN", "LOGIN_FAILED", "SUBMIT", "VERIFY", "TRANSFER", "DOWNLOAD"])
try:
    rows = api.audit_log(None if action == "(all)" else action)
except ApiError as exc:
    st.error(str(exc))
    st.stop()
st.dataframe(rows, use_container_width=True)
