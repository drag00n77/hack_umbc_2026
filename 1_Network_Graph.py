import streamlit as st
import streamlit.components.v1 as components
from dast_utils import build_graph
 
st.set_page_config(page_title="Network Graph", layout="wide")
st.title("Network Graph")
 
if st.session_state.get("findings"):
    findings = st.session_state.findings
 
    df_risks = sorted({f["risk"] for f in findings})
    df_scanners = sorted({f["scanner"] for f in findings})
 
    st.sidebar.header("Graph Filters")
    scanners = st.sidebar.multiselect("Scanner", df_scanners, default=df_scanners)
    risks = st.sidebar.multiselect("Risk / Severity", df_risks, default=df_risks)
 
    filtered = [f for f in findings if f["scanner"] in scanners and f["risk"] in risks]
 
    st.caption(f"Showing {len(filtered)} of {len(findings)} findings for **{st.session_state.scanned_url}**. Scanner → finding → URL, color-coded by severity (Critical/High/Medium/Low/Informational). Hover a node for details.")
 
    if filtered:
        graph_path = "dast_graph_tmp.html"
        build_graph(filtered, graph_path)
        with open(graph_path, "r", encoding="utf-8") as f:
            components.html(f.read(), height=750, scrolling=True)
    else:
        st.info("No findings match the current filters.")
else:
    st.write("The network graph will be displayed here after the scan is completed.")
    st.caption("Go to the main page to enter a target URL and run a scan.")
 