from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, HttpUrl
from uuid import uuid4
import httpx

app = FastAPI(title="Passive DAST Backend")

scans = {}


class ScanRequest(BaseModel):
    url: HttpUrl


@app.get("/health")
async def health():

    return {
        "service": "dast",
        "status": "online"
    }


@app.post("/scan")
async def start_scan(request: ScanRequest):

    scan_id = str(uuid4())
    target = str(request.url)

    findings = []

    print(f"DAST: inspecting {target}")

    try:

        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=20.0
        ) as client:

            response = await client.get(
                target,
                headers={
                    "User-Agent":
                        "Educational-Passive-Scanner/1.0"
                }
            )

    except httpx.TimeoutException:

        raise HTTPException(
            status_code=504,
            detail="Target website timed out."
        )

    except httpx.ConnectError as error:

        raise HTTPException(
            status_code=502,
            detail=f"Could not connect to target: {error}"
        )

    except httpx.RequestError as error:

        raise HTTPException(
            status_code=502,
            detail=f"Target request failed: {error}"
        )


    # --------------------------------
    # Security header checks
    # --------------------------------

    header_checks = {
        "content-security-policy": {
            "name": "Missing Content-Security-Policy",
            "severity": "Medium",
            "recommendation":
                "Review whether a Content Security Policy "
                "should be configured."
        },

        "x-content-type-options": {
            "name": "Missing X-Content-Type-Options",
            "severity": "Low",
            "recommendation":
                "Consider configuring X-Content-Type-Options."
        },

        "referrer-policy": {
            "name": "Missing Referrer-Policy",
            "severity": "Low",
            "recommendation":
                "Review the application's referrer policy."
        },

        "permissions-policy": {
            "name": "Missing Permissions-Policy",
            "severity": "Low",
            "recommendation":
                "Review whether browser capabilities should "
                "be restricted with Permissions-Policy."
        }
    }


    for header, check in header_checks.items():

        if header not in response.headers:

            findings.append({
                "id": f"HEADER-{len(findings) + 1}",
                "category": "Security Headers",
                "name": check["name"],
                "severity": check["severity"],
                "description":
                    f"The response did not contain "
                    f"the {header} header.",
                "recommendation":
                    check["recommendation"]
            })


    # --------------------------------
    # HSTS
    # --------------------------------

    if response.url.scheme == "https":

        if (
            "strict-transport-security"
            not in response.headers
        ):

            findings.append({
                "id": f"HEADER-{len(findings) + 1}",
                "category": "Transport Security",
                "name":
                    "Missing Strict-Transport-Security",
                "severity": "Medium",
                "description":
                    "The HTTPS response did not contain "
                    "an HSTS header.",
                "recommendation":
                    "Review whether HSTS should be enabled."
            })


    # --------------------------------
    # Information disclosure
    # --------------------------------

    server = response.headers.get("server")

    if server:

        findings.append({
            "id": f"INFO-{len(findings) + 1}",
            "category": "Information Disclosure",
            "name": "Server Header Exposed",
            "severity": "Low",
            "description":
                f"The server identifies itself as: {server}",
            "recommendation":
                "Review whether exposing server information "
                "is necessary."
        })


    powered_by = response.headers.get(
        "x-powered-by"
    )

    if powered_by:

        findings.append({
            "id": f"INFO-{len(findings) + 1}",
            "category": "Information Disclosure",
            "name": "Technology Header Exposed",
            "severity": "Low",
            "description":
                f"X-Powered-By reports: {powered_by}",
            "recommendation":
                "Review whether technology information "
                "needs to be exposed."
        })


    # --------------------------------
    # Cookie configuration
    # --------------------------------

    cookies = response.headers.get_list(
        "set-cookie"
    )

    for cookie_number, cookie in enumerate(
        cookies,
        start=1
    ):

        cookie_lower = cookie.lower()


        if (
            response.url.scheme == "https"
            and "secure" not in cookie_lower
        ):

            findings.append({
                "id":
                    f"COOKIE-{cookie_number}-SECURE",

                "category":
                    "Cookie Security",

                "name":
                    "Cookie Missing Secure Attribute",

                "severity":
                    "Low",

                "description":
                    "A cookie delivered over HTTPS did "
                    "not contain the Secure attribute.",

                "recommendation":
                    "Review whether the cookie should "
                    "use the Secure attribute."
            })


        if "httponly" not in cookie_lower:

            findings.append({
                "id":
                    f"COOKIE-{cookie_number}-HTTPONLY",

                "category":
                    "Cookie Security",

                "name":
                    "Cookie Missing HttpOnly Attribute",

                "severity":
                    "Low",

                "description":
                    "A cookie did not contain "
                    "the HttpOnly attribute.",

                "recommendation":
                    "Review whether the cookie should "
                    "use HttpOnly."
            })


        if "samesite" not in cookie_lower:

            findings.append({
                "id":
                    f"COOKIE-{cookie_number}-SAMESITE",

                "category":
                    "Cookie Security",

                "name":
                    "Cookie Missing SameSite Attribute",

                "severity":
                    "Low",

                "description":
                    "A cookie did not explicitly specify "
                    "a SameSite policy.",

                "recommendation":
                    "Review the appropriate SameSite "
                    "policy for this cookie."
            })


    # --------------------------------
    # Build result
    # --------------------------------

    result = {
        "scan_id": scan_id,
        "target": target,
        "final_url": str(response.url),
        "http_status": response.status_code,
        "status": "completed",
        "finding_count": len(findings),
        "findings": findings
    }

    scans[scan_id] = result

    print(
        f"DAST: completed {target} -- "
        f"{len(findings)} findings"
    )

    return result


@app.get("/scan/{scan_id}")
async def get_scan(scan_id: str):

    scan = scans.get(scan_id)

    if scan is None:

        raise HTTPException(
            status_code=404,
            detail="Scan not found."
        )

    return scan