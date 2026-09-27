import streamlit as st
import requests

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

    overview_tab, vulnerabilities_tab, gemini_tab = st.tabs(
        [
            "Overview",
            "Vulnerabilities",
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
                    '''
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
                    '''

 # ---------------------------------
    # Gemini Suggestion
 # ---------------------------------
    with gemini_tab:
        st.subheader("Gemini Security Suggestions")

    st.caption(
        "AI-generated remediation guidance based on "
        "the vulnerabilities found by the DAST scanner."
    )

    ai_analysis = data.get(
        "ai_analysis"
    )

    # No Gemini response
    if not ai_analysis:

        st.info(
            "No Gemini remediation suggestions "
            "are available for this scan."
        )

    else:

        remediations = ai_analysis.get(
            "remediations",
            []
        )

        # Gemini responded but there are no suggestions
        if not remediations:

            st.info(
                "Gemini did not return any "
                "remediation suggestions."
            )

        else:

            st.write(
                f"Gemini generated "
                f"{len(remediations)} suggestion(s)."
            )

            for remediation in remediations:

                finding_id = remediation.get(
                    "finding_id",
                    "Unknown"
                )

                vulnerability = remediation.get(
                    "vulnerability",
                    "Unknown Vulnerability"
                )

                explanation = remediation.get(
                    "explanation",
                    "No explanation available."
                )

                suggestion = remediation.get(
                    "remediation",
                    "No remediation available."
                )

                verification = remediation.get(
                    "verification",
                    "No verification steps available."
                )

                with st.expander(
                    f"{finding_id} — {vulnerability}"
                ):

                    st.markdown(
                        "#### Explanation"
                    )

                    st.write(
                        explanation
                    )

                    st.markdown(
                        "#### Suggested Remediation"
                    )

                    st.write(
                        suggestion
                    )

                    st.markdown(
                        "#### Verification"
                    )

                    st.write(
                        verification
                    )
