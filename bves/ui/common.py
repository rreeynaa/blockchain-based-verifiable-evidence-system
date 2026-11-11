"""Shared Streamlit helpers: session handling, role gating, custody timeline."""

from __future__ import annotations

import streamlit as st

from ui.api_client import ApiClient, fmt_ts


def client() -> ApiClient:
    """API client carrying the logged-in user's token."""
    return ApiClient(token=st.session_state.get("token"))


def require_login(*roles: str) -> ApiClient:
    """Stop the page unless the user is logged in (and has one of ``roles`` if given)."""
    st.set_page_config(page_title="BVES", page_icon="🔐", layout="wide")
    if "token" not in st.session_state:
        st.warning("Please log in on the **Home** page first.")
        st.stop()
    with st.sidebar:
        st.markdown(f"**{st.session_state['username']}** · `{st.session_state['role']}`")
        if st.button("Log out"):
            st.session_state.clear()
            st.rerun()
    if roles and st.session_state["role"] not in roles:
        st.error(f"This page is for: {', '.join(roles)}. You are signed in as {st.session_state['role']}.")
        st.stop()
    return client()


def custody_timeline(entries: list[dict]) -> None:
    """Render the chain of custody as a vertical timeline."""
    for i, e in enumerate(entries):
        origin = "∅ (registration)" if int(e["from_addr"], 16) == 0 else e["from_addr"]
        st.markdown(
            f"**{i + 1}. {fmt_ts(e['timestamp'])}**  \n"
            f"`{origin}` → `{e['to_addr']}`  \n"
            f"_{e['reason']}_"
        )


def proof_table(proof: list[dict]) -> None:
    """Show a Merkle proof path."""
    if not proof:
        st.caption("Single-file batch: the leaf hash is the root (empty proof).")
        return
    st.table(
        [{"level": i, "sibling is on": s["position"], "sibling hash": s["sibling"]} for i, s in enumerate(proof)]
    )
