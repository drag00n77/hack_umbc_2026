import streamlit as st
import streamlit.components.v1 as components
import requests
from pyvis.network import Network

API_URL = "http://127.0.0.1:8000"

#graph
RISK_COLOR = {
    "Critical": "#e74c3c",
    "High": "#e67e22",
    "Medium": "#f1c40f",
    "Low": "#3498db",
    "Informational": "#95a5a6",
    "Unknown": "#95a5a6",
}


# ---------------------------------
# Page configuration
# ---------------------------------

st.set_page_config(
    page_title="DAST Security Scanner",
    page_icon="🔒",
    layout="wide"
)

st.title("DAST Security Scanner")
st.caption("Streamlit → FastAPI → DAST")

st.divider()


# ---------------------------------
# Target URL
# ---------------------------------

target_url = st.text_input(
    "Authorized Target URL",
    placeholder="http://localhost:3000"
)

scan_button = st.button(
    "Start Scan",
    type="primary"
)


# ---------------------------------
# Start scan
# ---------------------------------

if scan_button:

    if not target_url:
        st.warning("Enter a URL first.")

    else:

        try:

            with st.spinner("Scanning target..."):

                # FRONTEND -> FASTAPI
                response = requests.post(
                    f"{API_URL}/api/scans",
                    json={
                        "url": target_url
                    },
                    timeout=30
                )

                response.raise_for_status()

                data = response.json()

                # Save results so Streamlit
                # keeps them after reruns.
                st.session_state["scan_results"] = data

        except requests.exceptions.HTTPError:

            try:
                error_message = response.json()["detail"]
            except Exception:
                error_message = "Scan failed."

            st.error(error_message)

        except requests.exceptions.ConnectionError:

            st.error(
                "Could not connect to the FastAPI backend."
            )

        except requests.exceptions.Timeout:

            st.error(
                "The scan request timed out."
            )

        except requests.exceptions.RequestException as error:

            st.error(
                f"Request failed: {error}"
            )

# ---------------------------------
# Network graph builder
# ---------------------------------
 
def build_graph(target, vulnerabilities, out_path):
    """
    Generates an interactive PyVis graph connecting
    Scanner (source) -> Finding -> Target URL
    """
    net = Network(
        height="700px",
        width="100%",
        bgcolor="#1a1a1a",
        font_color="#ffffff",
        directed=True,
        cdn_resources="remote"
    )
 
    net.barnes_hut(
        gravity=-6000,
        central_gravity=0.3,
        spring_length=140,
        spring_strength=0.04,
        damping=0.09
    )
 
    scanner = "DAST Scanner"
 
    # Source node
    net.add_node(
        scanner,
        label=f"🛡️ {scanner}",
        color="#2ecc71",
        shape="hexagon",
        size=35,
        title=f"<b>Log Source:</b> {scanner}"
    )
 
    # Target endpoint node
    short_url = target.split("//")[-1] if "//" in target else target
    display_url = short_url[:35] + ("..." if len(short_url) > 35 else "")
    net.add_node(
        target,
        label=display_url,
        color="#34495e",
        shape="box",
        size=25,
        title=f"<b>Target:</b><br>{target}"
    )
 
    net.add_edge(scanner, target, color="#7f8c8d", width=1, hidden=True)
 
    for idx, vuln in enumerate(vulnerabilities):
        name = vuln.get("name", "Unknown Finding")
        severity = vuln.get("severity", "Unknown")
        description = vuln.get("description", "No description available.")
        recommendation = vuln.get("recommendation", "No recommendation available.")
        finding_id = vuln.get("id", f"finding_{idx}")
 
        color = RISK_COLOR.get(str(severity).title(), "#95a5a6")
        node_id = f"node_{idx}_{finding_id}"
 
        tooltip_html = f"""
        <div style='font-family: sans-serif; padding: 6px; max-width: 280px;'>
            <b style='color: {color};'>[{str(severity).upper()}] {name}</b><br/>
            <b>Description:</b> {description}<br/>
            <b>Recommendation:</b> {recommendation}
        </div>
        """
 
        net.add_node(
            node_id,
            label=name,
            color=color,
            shape="diamond",
            size=22,
            title=tooltip_html
        )
 
        net.add_edge(scanner, node_id, color="#7f8c8d", width=1.5)
        net.add_edge(node_id, target, color=color, width=2)
 
    net.set_options("""
    var options = {
      "nodes": {
        "borderWidth": 2,
        "font": { "size": 13, "face": "arial" },
        "shadow": true
      },
      "edges": {
        "smooth": { "type": "continuous" },
        "shadow": true
      },
      "interaction": {
        "hover": true,
        "hoverConnectedEdges": true,
        "selectConnectedEdges": true,
        "navigationButtons": true,
        "tooltipDelay": 50
      },
      "physics": {
        "enabled": true,
        "stabilization": { "iterations": 100 }
      }
    }
    """)
 
    net.write_html(out_path, notebook=False, open_browser=False)
# ---------------------------------
# Display results
# ---------------------------------

if "scan_results" in st.session_state:

    data = st.session_state["scan_results"]

    st.success("Scan completed.")

    st.write(
        "**Target:**",
        data.get("target", "Unknown")
    )

    st.write(
        "**Scan ID:**",
        data.get("scan_id", "Unknown")
    )

    st.write(
        "**Status:**",
        data.get("status", "Unknown")
    )

    st.divider()


    # ---------------------------------
    # Summary
    # ---------------------------------

    st.subheader("Security Summary")

    summary = data.get(
        "summary",
        {}
    )

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            "Critical",
            summary.get("critical", 0)
        )

    with col2:
        st.metric(
            "High",
            summary.get("high", 0)
        )

    with col3:
        st.metric(
            "Medium",
            summary.get("medium", 0)
        )

    with col4:
        st.metric(
            "Low",
            summary.get("low", 0)
        )


    st.divider()


    # ---------------------------------
    # Tabs
    # ---------------------------------

    overview_tab, vulnerabilities_tab, graph_tab, gemini_tab = st.tabs(
        [
            "Overview",
            "Vulnerabilities",
            "Graph",
            "Gemini Suggestion"
        ]
    )


    # ---------------------------------
    # Overview
    # ---------------------------------

    with overview_tab:

        st.subheader("Scan Information")

        st.write(
            "**Target URL:**",
            data.get("target", "Unknown")
        )

        st.write(
            "**Scan ID:**",
            data.get("scan_id", "Unknown")
        )

        st.write(
            "**Status:**",
            data.get("status", "Unknown")
        )


    # ---------------------------------
    # Vulnerabilities
    # ---------------------------------

    with vulnerabilities_tab:

        vulnerabilities = data.get(
            "vulnerabilities",
            []
        )

        st.subheader(
            f"Vulnerabilities ({len(vulnerabilities)})"
        )

        if not vulnerabilities:

            st.success(
                "No findings were returned by the scanner."
            )

        else:

            for vulnerability in vulnerabilities:

                name = vulnerability.get(
                    "name",
                    "Unknown Finding"
                )

                severity = vulnerability.get(
                    "severity",
                    "Unknown"
                )

                description = vulnerability.get(
                    "description",
                    "No description available."
                )

                recommendation = vulnerability.get(
                    "recommendation",
                    "No recommendation available."
                )

                finding_id = vulnerability.get(
                    "id",
                    "Unknown"
                )

                with st.expander(
                    f"{severity.upper()} — {name}"
                ):

                    st.write(
                        "**Finding ID:**",
                        finding_id
                    )

                    st.write(
                        "**Severity:**",
                        severity
                    )

                    st.write(
                        "**Description:**"
                    )

                    st.write(
                        description
                    )

                    st.write(
                        "**Recommendation:**"
                    )

                    st.write(
                        recommendation
                    )
 # ---------------------------------
    # Network Graph
    # ---------------------------------
 
    with graph_tab:
 
        vulnerabilities = data.get("vulnerabilities", [])
        target = data.get("target", "Unknown")
 
        if not vulnerabilities:
            st.info("No findings to visualize yet.")
        else:
            graph_path = "dast_graph_tmp.html"
            build_graph(target, vulnerabilities, graph_path)
 
            with open(graph_path, "r", encoding="utf-8") as f:
                components.html(f.read(), height=720, scrolling=True)

        
