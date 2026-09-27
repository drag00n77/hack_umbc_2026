from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, HttpUrl
import httpx


app = FastAPI(title="Security Scanner API")

DAST_URL = "http://127.0.0.1:9000"


class ScanRequest(BaseModel):
    url: HttpUrl


# ==========================================
# HEALTH CHECK
# ==========================================

@app.get("/health")
async def health():

    try:

        async with httpx.AsyncClient() as client:

            response = await client.get(
                f"{DAST_URL}/health",
                timeout=5
            )

            response.raise_for_status()

        return {
            "api": "online",
            "dast": "online"
        }

    except httpx.HTTPError:

        return {
            "api": "online",
            "dast": "offline"
        }


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
            timeout=30.0
        ) as client:

            response = await client.post(
                f"{DAST_URL}/scan",
                json={
                    "url": str(request.url)
                }
            )

    # --------------------------------------
    # FastAPI cannot connect to DAST
    # --------------------------------------

    except httpx.ConnectError as error:

        print(
            f"Cannot connect to DAST: {error}"
        )

        raise HTTPException(
            status_code=502,
            detail=(
                "FastAPI could not connect to "
                "the DAST service on port 9000."
            )
        )

    # --------------------------------------
    # DAST took too long to respond
    # --------------------------------------

    except httpx.TimeoutException as error:

        print(
            f"DAST timeout: {error}"
        )

        raise HTTPException(
            status_code=504,
            detail=(
                "The DAST service took too long "
                "to respond."
            )
        )

    # --------------------------------------
    # Other HTTP communication errors
    # --------------------------------------

    except httpx.RequestError as error:

        print(
            f"DAST request error: {error}"
        )

        raise HTTPException(
            status_code=502,
            detail=(
                f"Error communicating with "
                f"DAST service: {error}"
            )
        )


    # ======================================
    # DAST RESPONDED WITH AN ERROR
    # ======================================

    if response.status_code >= 400:

        try:

            error_data = response.json()

            detail = error_data.get(
                "detail",
                "DAST scan failed."
            )

        except Exception:

            detail = response.text

        print(
            f"DAST scan error: {detail}"
        )

        raise HTTPException(
            status_code=response.status_code,
            detail=detail
        )


    # ======================================
    # READ SUCCESSFUL DAST RESPONSE
    # ======================================

    try:

        dast_result = response.json()

    except ValueError:

        raise HTTPException(
            status_code=502,
            detail=(
                "DAST returned an invalid "
                "JSON response."
            )
        )


    # ======================================
    # GET FINDINGS
    # ======================================

    findings = dast_result.get(
        "findings",
        []
    )


    # ======================================
    # NORMALIZE RESULTS FOR FRONTEND
    # ======================================

    summary = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0
    }


    for finding in findings:

        severity = finding.get(
            "severity",
            ""
        ).lower()

        if severity in summary:

            summary[severity] += 1


    # ======================================
    # BUILD FRONTEND RESPONSE
    # ======================================

    result = {
        "scan_id": dast_result["scan_id"],
        "target": dast_result["target"],
        "status": dast_result["status"],
        "summary": summary,
        "vulnerabilities": findings
    }


    print(
        f"FastAPI: sending "
        f"{len(findings)} findings "
        f"to frontend"
    )


    return result