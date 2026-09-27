import streamlit as st

st.set_page_config(
    page_title="Dashboard",
    layout="wide"
)

st.title("Vulnerability Detection & Response")

# URL link paste
url = st.text_input(
    "Target URL",
    placeholder="http://exmaple"
)

# Running DAST
if st.button("Run DAST Scan"):
    if url:
        st.info(f"Preparing scan for: {url}")
    else:
        st.warning("Enter a target URL.")

# Tabs for different sections
tab1, tab2, tab3, tab4 = st.tabs(["Overview","DAST Results", "Google Gemini Suggestions", "Slack Channel"])

with tab1:
    st.subheader("Overview")
    st.write("This is the vulnerability detection and response dashboard. The main purpose is to detect" \
    "any vulnerabilities present in the target application, and provide suggestions for remediation from " \
    "Google Gemini API, and facilitate communication through the Slack channel for effective collaboration and response." \
    " This project was created by Jayden Paige, Michael Pellegrino, Brittney Alexander, and Ankit Neupane using Streamlit and Google Gemini API.")

with tab2:
    st.subheader("DAST Results")
    st.write("Results will be displayed here after the scan is completed.")

with tab3:
    st.subheader("Google Gemini Suggestions")
    st.write("Suggestions will be displayed here based on the scan results.")

with tab4:
    st.subheader("Slack Channel")
    st.write("Notifications and updates will be shared here via the Slack channel.") 