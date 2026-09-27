import streamlit as st
import requests


# ==========================================
# CONFIGURATION
# ==========================================

API_URL = "http://127.0.0.1:8000"


# ==========================================
# PAGE CONFIGURATION
# ==========================================

st.set_page_config(
    page_title="DAST Security Scanner",
    page_icon="🔒",
    layout="wide"
)

st.title("DAST Security Scanner")
st.caption("Streamlit → FastAPI → Passive DAST → Gemini AI")

st.divider()


# ==========================================
# TARGET URL
# ==========================================

target_url = st.text_input(
    "Authorized Target URL",
    placeholder="https://example.com"
)

scan_button = st.button(
    "Start Scan",
    type="primary"
)


# ==========================================
# START SCAN
# ==========================================

if scan_button:

    if not target_url:
        st.warning("Enter a URL first.")

    else:

        try:
            with st.spinner(
                "Running security scan and generating AI analysis..."
            ):

                # FRONTEND -> FASTAPI
                response = requests.post(
                    f"{API_URL}/api/scans",
                    json={
                        "url": target_url
                    },
                    timeout=90
                )

                response.raise_for_status()

                data = response.json()

                # Save results so Streamlit keeps them after reruns.
                st.session_state["scan_results"] = data

        except requests.exceptions.HTTPError:

            try:
                error_message = response.json().get(
                    "detail",
                    "Scan failed."
                )
            except Exception:
                error_message = "Scan failed."

            st.error(error_message)

        except requests.exceptions.ConnectionError:

            st.error(
                "Could not connect to the FastAPI backend. "
                "Make sure main.py is running on port 8000."
            )

        except requests.exceptions.Timeout:

            st.error(
                "The scan request timed out. "
                "The target, DAST service, or Gemini analysis may have taken too long."
            )

        except requests.exceptions.RequestException as error:

            st.error(
                f"Request failed: {error}"
            )


# ==========================================
# DISPLAY RESULTS
# ==========================================

if "scan_results" in st.session_state:

    data = st.session_state["scan_results"]

    st.success("Scan completed.")

    # --------------------------------------
    # Basic scan information
    # --------------------------------------

    col1, col2, col3 = st.columns(3)

    with col1:
        st.write(
            "**Target:**",
            data.get("target", "Unknown")
        )

    with col2:
        st.write(
            "**Scan ID:**",
            data.get("scan_id", "Unknown")
        )

    with col3:
        st.write(
            "**Status:**",
            data.get("status", "Unknown")
        )

    st.divider()

    # --------------------------------------
    # Security summary
    # --------------------------------------

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

    # --------------------------------------
    # Tabs
    # --------------------------------------

    overview_tab, vulnerabilities_tab = st.tabs(
        [
            "AI Overview",
            "Vulnerabilities"
        ]
    )

    # ======================================
    # AI OVERVIEW
    # ======================================

    with overview_tab:

        st.subheader("Gemini Security Assessment")

        ai = data.get(
            "ai",
            {}
        )

        ai_status = ai.get(
            "status",
            "unavailable"
        )

        analysis = ai.get(
            "analysis"
        )

        if ai_status == "completed" and analysis:

            st.markdown(
                "### Overview"
            )

            st.write(
                analysis.get(
                    "overview",
                    "No overview was generated."
                )
            )

            st.markdown(
                "### Key Risks"
            )

            key_risks = analysis.get(
                "key_risks",
                []
            )

            if key_risks:
                for risk in key_risks:
                    st.markdown(
                        f"- {risk}"
                    )
            else:
                st.write(
                    "No key risks were identified by the AI analysis."
                )

            st.markdown(
                "### Recommended Actions"
            )

            recommendations = analysis.get(
                "recommendations",
                []
            )

            if recommendations:
                for recommendation in recommendations:
                    st.markdown(
                        f"- {recommendation}"
                    )
            else:
                st.write(
                    "No recommendations were generated."
                )

            st.caption(
                f"Analysis generated by {ai.get('model', 'Gemini')} "
                "from the DAST findings."
            )

        else:

            st.warning(
                "Gemini analysis was not available for this scan."
            )

            ai_error = ai.get(
                "error"
            )

            if ai_error:
                st.caption(
                    f"Reason: {ai_error}"
                )

        st.divider()

        # ----------------------------------
        # Scan information
        # ----------------------------------

        st.subheader("Scan Information")

        st.write(
            "**Target URL:**",
            data.get("target", "Unknown")
        )

        final_url = data.get(
            "final_url"
        )

        if final_url:
            st.write(
                "**Final URL:**",
                final_url
            )

        http_status = data.get(
            "http_status"
        )

        if http_status is not None:
            st.write(
                "**HTTP Status:**",
                http_status
            )

        st.write(
            "**Scan ID:**",
            data.get("scan_id", "Unknown")
        )

        st.write(
            "**Status:**",
            data.get("status", "Unknown")
        )

    # ======================================
    # VULNERABILITIES
    # ======================================

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

                category = vulnerability.get(
                    "category",
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
                        "**Category:**",
                        category
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
