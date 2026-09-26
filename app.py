import streamlit as st

st.set_page_config(
    page_title="Dashboard",
    layout="wide"
)

st.title("Vulnerability Detection & Response")

# URL link paste
target = st.text_input(
    "Target URL",
    placeholder="http://exmaple"
)

# Running DAST
if st.button("Run DAST Scan"):
    if target:
        st.info(f"Preparing scan for: {target}")
    else:
        st.warning("Enter a target URL.")
