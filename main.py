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

DAST_URL = os.getenv("DAST_URL", "http://127.0.0.1:9000")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
GEMINI_TIMEOUT_SECONDS = float(os.getenv("GEMINI_TIMEOUT_SECONDS", "30"))

GEMINI_API_KEY = os.getenv("AQ.Ab8RN6IQlbhYTJZhwWZ0rw5CdGCk6EX8HFsveMdZcrNzUNDiGg")

gemini_client = None
if GEMINI_API_KEY:
    gemini_client = genai.Client(api_key=GEMINI_API_KEY)


# ==========================================
# REQUEST / RESPONSE MODELS
# ==========================================

class ScanRequest(BaseModel):
    url: HttpUrl


class GeminiAnalysis(BaseModel):
    overview: str = Field(
        description="A concise overall security assessment based only on the supplied findings."
    )
    key_risks: List[str] = Field(
        description="The most important security concerns represented by the findings."
    )
    recommendations: List[str] = Field(
        description="Practical remediation suggestions based only on the supplied findings."
    )


# ==========================================
# HEALTH CHECK
# ==========================================

@app.get("/health")
async def health():
    dast_status = "offline"

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(f"{DAST_URL}/health")
            response.raise_for_status()

        dast_status = "online"

    except httpx.HTTPError:
        dast_status = "offline"

    return {
        "api": "online",
        "dast": dast_status,
        "gemini": "configured" if gemini_client else "not configured",
        "gemini_model": GEMINI_MODEL
    }


# ==========================================
# GEMINI ANALYSIS
# ==========================================

async def analyze_findings(target: str, findings: list) -> GeminiAnalysis:
    """
    Sends the DAST findings to Gemini for explanation and remediation suggestions.

    Gemini is given the scanner's findings rather than direct access to the target.
    """

    if gemini_client is None:
        raise RuntimeError(
            "GEMINI_API_KEY is not configured."
        )

    findings_json = json.dumps(findings, indent=2)

    prompt = f"""
You are a cybersecurity analyst reviewing the results of an authorized,
passive web security scan.

Target:
{target}

Scanner findings:
{findings_json}

Your task is to analyze ONLY the findings supplied above.

Return:
1. A concise overall security overview.
2. The key security risks represented by the findings.
3. Practical recommendations for addressing those findings.

Rules:
- Do not invent vulnerabilities.
- Do not claim that a configuration issue is automatically exploitable.
- Do not add findings that are not present in the scanner results.
- Keep the scanner's severity classifications intact.
- Explain the potential impact without overstating certainty.
- Recommendations should be actionable and technically appropriate.
- If there are no findings, explain that no issues were returned by this scan.
- Keep the overview concise enough for a security dashboard.
"""

    response = await asyncio.wait_for(
        gemini_client.aio.models.generate_content(
            model=GEMINI_MODEL,
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=GeminiAnalysis,
            ),
        ),
        timeout=GEMINI_TIMEOUT_SECONDS,
    )

    if not response.text:
        raise RuntimeError("Gemini returned an empty response.")

    try:
        return GeminiAnalysis.model_validate_json(response.text)
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
        f"FastAPI: received scan request for {request.url}"
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
        print(f"Cannot connect to DAST: {error}")

        raise HTTPException(
            status_code=502,
            detail=(
                "FastAPI could not connect to the DAST service "
                f"at {DAST_URL}."
            )
        )

    except httpx.TimeoutException as error:
        print(f"DAST timeout: {error}")

        raise HTTPException(
            status_code=504,
            detail="The DAST service took too long to respond."
        )

    except httpx.RequestError as error:
        print(f"DAST request error: {error}")

        raise HTTPException(
            status_code=502,
            detail=f"Error communicating with DAST service: {error}"
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
            detail = response.text or "DAST scan failed."

        print(f"DAST scan error: {detail}")

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
            detail="DAST returned an invalid JSON response."
        ) from error

    # --------------------------------------
    # GET FINDINGS
    # --------------------------------------

    findings = dast_result.get("findings", [])

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
            finding.get("severity", "")
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
        "scan_id": dast_result.get("scan_id"),
        "target": dast_result.get(
            "target",
            str(request.url)
        ),
        "final_url": dast_result.get("final_url"),
        "http_status": dast_result.get("http_status"),
        "status": dast_result.get("status", "completed"),
        "summary": summary,
        "vulnerabilities": findings,
        "ai": {
            "status": ai_status,
            "model": GEMINI_MODEL,
            "analysis": ai_analysis,
            "error": ai_error
        }
    }

    print(
        f"FastAPI: sending {len(findings)} findings to frontend"
    )

    return result
