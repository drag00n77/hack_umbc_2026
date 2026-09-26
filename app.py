import streamlit as st
from dast_utils import (
    get_fake_zap_log, 
    get_fake_nuclei_log, 
    parse_zap, 
    parse_nuclei, 
    suggest, 
    build_graph, 
    run_dast_scan,
    parse_proxy_json
)
import pandas as pd
import streamlit.components.v1 as components

st.set_page_config(
    page_title="Dashboard",
    layout="wide"
)

st.title("Vulnerability Detection & Response")
if "findings" not in st.session_state:
    st.session_state.findings = []
if "scanned_url" not in st.session_state:
    st.session_state.scanned_url = None

# URL link paste
url = st.text_input(
    "Target URL",
    placeholder="http://exmaple"
)

# Running DAST
if st.button("Run DAST Scan"):
    if url:
        st.info(f"Preparing scan for: {url}")

        findings = run_dast_scan(url)

        st.session_state.findings = findings

        st.success("DAST scan completed.")

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
    st.subheader("DAST Results & Log Analysis")

    # File uploader configured for JSON and CSV files
    uploaded_file = st.file_uploader("Upload Proxy Log File", type=["json", "csv"])

    if uploaded_file is not None:
        try:
            st.session_state.findings = parse_proxy_json(uploaded_file)
            st.success(f"Successfully processed {len(st.session_state.findings)} log entries from {uploaded_file.name}.")
        except Exception as e:
            st.error(f"Error parsing log file: {e}")

    # Display results if findings are loaded
    if len(st.session_state.findings) > 0:
        df = pd.DataFrame(st.session_state.findings)

        col1, col2, col3 = st.columns(3)
        col1.metric("Total Entries", len(df))
        col2.metric("Unique Endpoints", df["url"].nunique())
        col3.metric(
            "High / Medium Alert Count",
            int(df["risk"].isin(["High", "Medium", "Critical"]).sum())
        )

        st.subheader("Interactive Network Graph")
        
        # Legend Display
        col_a, col_b, col_c = st.columns(3)
        with col_a:
            st.markdown("🟢 **Hexagon**: Log Source")
        with col_b:
            st.markdown("♦️ **Diamond**: Traffic / Alert (Color = Risk Level)")
        with col_c:
            st.markdown("🟦 **Box**: Target Endpoint URL")

        # Build and render network graph
        graph_path = "dast_graph_tmp.html"
        build_graph(st.session_state.findings, graph_path)

        with open(graph_path, "r", encoding="utf-8") as f:
            components.html(f.read(), height=720, scrolling=True)

        st.subheader("Findings Data Table")
        st.dataframe(
            df[["scanner", "risk", "url", "alert", "param"]],
            use_container_width=True
        )
    else:
        st.info("Upload a proxy CSV file above to visualize and analyze your traffic data.")


with tab3:
    st.subheader("Google Gemini Suggestions")
    st.write("Suggestions will be displayed here based on the scan results.")

with tab4:
    st.subheader("Slack Channel")
    st.write("Notifications and updates will be shared here via the Slack channel.") 