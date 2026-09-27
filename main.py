import json
import os
import asyncio
from typing import List

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, HttpUrl, Field
from google import genai
from google.genai import types


# ==========================================
# CONFIGURATION
# ==========================================

app = FastAPI(title="Security Scanner API")

DAST_URL = os.getenv(
    "DAST_URL",
    "http://127.0.0.1:9000"
)

GEMINI_MODEL = os.getenv(
    "GEMINI_MODEL",
    "gemini-3.8-flash"
)

GEMINI_TIMEOUT_SECONDS = float(
    os.getenv(
        "GEMINI_TIMEOUT_SECONDS",
        "30"
    )
)

# GitHub Codespaces provides this as an environment variable.
GEMINI_API_KEY = os.getenv(
    "GEMINI_API_KEY"
)

gemini_client = None

if GEMINI_API_KEY:
    gemini_client = genai.Client(
        api_key=GEMINI_API_KEY
    )


# ==========================================
# REQUEST / RESPONSE MODELS
# ==========================================

class ScanRequest(BaseModel):
    url: HttpUrl


class GeminiRemediation(BaseModel):
    finding_id: str = Field(
        description="The ID of the DAST finding."
    )

    vulnerability: str = Field(
        description="The name of the security finding."
    )

    explanation: str = Field(
        description=(
            "Explain what the finding means and "
            "its potential security impact."
        )
    )

    remediation: str = Field(
        description=(
            "Provide practical steps to remediate "
            "the security finding."
        )
    )

    verification: str = Field(
        description=(
            "Explain how to verify that the "
            "remediation was correctly applied."
        )
    )


class GeminiAnalysis(BaseModel):
    overview: str = Field(
        description=(
            "A concise overall interpretation of "
            "the DAST scan results."
        )
    )

    remediations: List[GeminiRemediation] = Field(
        description=(
            "AI-generated remediation guidance "
            "for the supplied DAST findings."
        )
    )


# ==========================================
# HEALTH CHECK
# ==========================================

@app.get("/health")
async def health():

    dast_status = "offline"

    try:

        async with httpx.AsyncClient(
            timeout=5.0
        ) as client:

            response = await client.get(
                f"{DAST_URL}/health"
            )

            response.raise_for_status()

        dast_status = "online"

    except httpx.HTTPError:

        dast_status = "offline"

    return {
        "api": "online",
        "dast": dast_status,
        "gemini": (
            "configured"
            if gemini_client
            else "not configured"
        ),
        "gemini_model": GEMINI_MODEL
    }


# ==========================================
# GEMINI ANALYSIS
# ==========================================

async def analyze_findings(
    target: str,
    findings: list
) -> GeminiAnalysis:

    """
    Sends the DAST findings to Gemini for
    interpretation and remediation guidance.

    Gemini does not directly scan the target.
    It analyzes only the findings produced
    by the DAST scanner.
    """

    if gemini_client is None:

        raise RuntimeError(
            "GEMINI_API_KEY is not configured."
        )

    findings_json = json.dumps(
        findings,
        indent=2
    )

    prompt = f"""
You are a cybersecurity analyst reviewing the results
of an authorized passive web security scan.

Target:
{target}

Scanner findings:
{findings_json}

Analyze ONLY the findings provided by the scanner.

Return:

1. A concise overall security overview.
2. A remediation object for each supplied finding.

Each remediation must contain:

- finding_id
- vulnerability
- explanation
- remediation
- verification

Rules:

- Do not invent vulnerabilities.
- Do not create findings that were not supplied.
- Use the exact finding ID provided by the scanner.
- Do not claim that a configuration issue is automatically exploitable.
- Explain potential security impact without overstating certainty.
- Keep the scanner's severity classification unchanged.
- Recommendations must be practical and technically appropriate.
- Verification should explain how a developer can confirm
  that the issue has been addressed.
- Base the response only on the supplied scanner findings.
- If there are no findings, return an overview explaining
  that no findings were returned and return an empty
  remediations list.
- Keep the overview concise enough for a security dashboard.
"""

    try:

        response = await asyncio.wait_for(
            gemini_client.aio.models.generate_content(
                model=GEMINI_MODEL,
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=GeminiAnalysis
                )
            ),
            timeout=GEMINI_TIMEOUT_SECONDS
        )

    except asyncio.TimeoutError as error:

        raise RuntimeError(
            "Gemini analysis timed out."
        ) from error

    except Exception as error:

        raise RuntimeError(
            f"Gemini API request failed: {error}"
        ) from error

    if not response.text:

        raise RuntimeError(
            "Gemini returned an empty response."
        )

    try:

        return GeminiAnalysis.model_validate_json(
            response.text
        )

    except Exception as error:

        raise RuntimeError(
            f"Gemini returned invalid structured output: {error}"
        ) from error


# ==========================================
# START DAST SCAN
# ==========================================

@app.post("/api/scans")
async def start_scan(request: ScanRequest):

    print(
        f"FastAPI: received scan request "
        f"for {request.url}"
    )

    # --------------------------------------
    # FastAPI -> DAST communication
    # --------------------------------------

    try:

        async with httpx.AsyncClient(
            timeout=35.0
        ) as client:

            response = await client.post(
                f"{DAST_URL}/scan",
                json={
                    "url": str(request.url)
                }
            )

    except httpx.ConnectError as error:

        print(
            f"Cannot connect to DAST: {error}"
        )

        raise HTTPException(
            status_code=502,
            detail=(
                "FastAPI could not connect to the DAST service "
                f"at {DAST_URL}."
            )
        )

    except httpx.TimeoutException as error:

        print(
            f"DAST timeout: {error}"
        )

        raise HTTPException(
            status_code=504,
            detail=(
                "The DAST service took too long to respond."
            )
        )

    except httpx.RequestError as error:

        print(
            f"DAST request error: {error}"
        )

        raise HTTPException(
            status_code=502,
            detail=(
                f"Error communicating with DAST service: {error}"
            )
        )

    # --------------------------------------
    # DAST RESPONDED WITH AN ERROR
    # --------------------------------------

    if response.status_code >= 400:

        try:

            error_data = response.json()

            detail = error_data.get(
                "detail",
                "DAST scan failed."
            )

        except Exception:

            detail = (
                response.text
                or "DAST scan failed."
            )

        print(
            f"DAST scan error: {detail}"
        )

        raise HTTPException(
            status_code=response.status_code,
            detail=detail
        )

    # --------------------------------------
    # READ SUCCESSFUL DAST RESPONSE
    # --------------------------------------

    try:

        dast_result = response.json()

    except ValueError as error:

        raise HTTPException(
            status_code=502,
            detail=(
                "DAST returned an invalid JSON response."
            )
        ) from error

    # --------------------------------------
    # GET FINDINGS
    # --------------------------------------

    findings = dast_result.get(
        "findings",
        []
    )

    # --------------------------------------
    # BUILD SEVERITY SUMMARY
    # --------------------------------------

    summary = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0
    }

    for finding in findings:

        severity = str(
            finding.get(
                "severity",
                ""
            )
        ).lower()

        if severity in summary:

            summary[severity] += 1

    # --------------------------------------
    # GEMINI ANALYSIS
    # --------------------------------------

    ai_analysis = None
    ai_status = "unavailable"
    ai_error = None

    try:

        ai_result = await analyze_findings(
            target=dast_result.get(
                "target",
                str(request.url)
            ),
            findings=findings
        )

        ai_analysis = ai_result.model_dump()

        ai_status = "completed"

        print(
            "FastAPI: Gemini analysis completed"
        )

    except Exception as error:

        ai_error = str(error)

        print(
            f"FastAPI: Gemini analysis failed: {error}"
        )

    # --------------------------------------
    # BUILD FRONTEND RESPONSE
    # --------------------------------------

    result = {
        "scan_id": dast_result.get(
            "scan_id"
        ),

        "target": dast_result.get(
            "target",
            str(request.url)
        ),

        "final_url": dast_result.get(
            "final_url"
        ),

        "http_status": dast_result.get(
            "http_status"
        ),

        "status": dast_result.get(
            "status",
            "completed"
        ),

        "summary": summary,

        "vulnerabilities": findings,

        # This matches your frontend.py
        "ai_analysis": ai_analysis,

        "ai_status": ai_status,

        "ai_error": ai_error,

        "ai_model": GEMINI_MODEL
    }

    print(
        f"FastAPI: sending "
        f"{len(findings)} findings "
        f"to frontend"
    )

    return result
