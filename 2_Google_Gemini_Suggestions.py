import pandas as pd
import streamlit as st

st.set_page_config(page_title="Google Gemini Suggestions", layout="wide")
st.title("Google Gemini Suggestions")

if st.session_state.get("findings"):
    df = pd.DataFrame(st.session_state.findings)
    for risk_level in ["Critical", "High", "Medium", "Low", "Informational", "Info"]:
        subset = df[df["risk"] == risk_level]
        if subset.empty:
            continue
        st.markdown(f"**{risk_level} risk**")
        for _, row in subset.iterrows():
            st.write(f"- **{row['alert']}** ({row['url']}): {row['suggestion']}")
else:
    st.write("Suggestions will be displayed here based on the scan results.")
    st.caption("Go to the main page to enter a target URL and run a scan.")