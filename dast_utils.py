import io
import json
import re
import pandas as pd
from pyvis.network import Network

# Risk severity color mapping
RISK_COLOR = {
    "Critical": "#e74c3c",      # Red
    "High": "#e67e22",          # Orange
    "Medium": "#f1c40f",        # Yellow
    "Low": "#3498db",           # Light Blue
    "Informational": "#95a5a6", # Grey
    "Unknown": "#7f8c8d"        # Dark Grey
}

# Pre-defined remediation suggestions
SUGGESTIONS = {
    "SQL Injection": "Use parameterized queries / prepared statements; validate and sanitize all input.",
    "Cross Site Scripting (Reflected)": "Encode output contextually; adopt a strict CSP; sanitize reflected params.",
    "CSRF Token Missing": "Add anti-CSRF tokens to all state-changing forms and verify them server-side.",
    "Sensitive Data Exposure": "Avoid returning PII in API responses; enforce field-level access control.",
    "Missing Security Headers": "Add X-Frame-Options, X-Content-Type-Options, and a Content-Security-Policy.",
    "exposed-.env": "Remove .env from the web root; rotate any leaked secrets immediately.",
    "cors-misconfig": "Restrict Access-Control-Allow-Origin to a known allow-list, never '*' with credentials.",
    "outdated-jquery-xss": "Upgrade jQuery to a patched version (>=3.5) to remove known XSS vectors.",
    "server-header-disclosure": "Suppress or genericize the Server header to reduce fingerprinting.",
    "weak-cipher-suites": "Disable weak TLS ciphers; enforce TLS 1.2+ with strong cipher suites only.",
}


def get_fake_zap_log(target_url):
    return f"""
[ZAP] 2026-09-26 10:02:11 INFO  Starting active scan on {target_url}
[ZAP] 2026-09-26 10:02:14 ALERT risk=High   confidence=Medium  url={target_url}/login        alert=SQL Injection           param=username
[ZAP] 2026-09-26 10:02:19 ALERT risk=High   confidence=High    url={target_url}/search       alert=Cross Site Scripting (Reflected)  param=q
[ZAP] 2026-09-26 10:02:25 ALERT risk=Medium confidence=Medium  url={target_url}/profile      alert=CSRF Token Missing        param=-
[ZAP] 2026-09-26 10:02:31 ALERT risk=Medium confidence=Low     url={target_url}/api/v1/users alert=Sensitive Data Exposure  param=email
[ZAP] 2026-09-26 10:02:36 ALERT risk=Low    confidence=Medium  url={target_url}/           alert=Missing Security Headers param=X-Frame-Options
[ZAP] 2026-09-26 10:02:44 INFO  Active scan completed. 5 alerts raised.
"""


def get_fake_nuclei_log(target_url):
    host = target_url.replace("https://", "").replace("http://", "").rstrip("/")
    return f"""
[nuclei] [2026-09-26 10:05:07] [critical] [http] [exposures] exposed-.env at {target_url}/.env
[nuclei] [2026-09-26 10:05:11] [medium] [http] [misconfiguration] cors-misconfig at {target_url}/api/v1/data
[nuclei] [2026-09-26 10:05:15] [high] [http] [vulnerabilities] outdated-jquery-xss at {target_url}/assets/js/jquery-1.8.js
[nuclei] [2026-09-26 10:05:20] [low] [http] [misconfiguration] server-header-disclosure at {target_url}/
[nuclei] [2026-09-26 10:05:28] [medium] [ssl] [misconfiguration] weak-cipher-suites at {host}:443
"""


def parse_zap(log):
    findings = []
    pattern = re.compile(
        r"risk=(?P<risk>\S+)\s+confidence=\S+\s+url=(?P<url>\S+)\s+alert=(?P<alert>.+?)\s+param=(?P<param>\S+)"
    )
    for line in log.splitlines():
        m = pattern.search(line)
        if m:
            findings.append({
                "scanner": "ZAP",
                "risk": m.group("risk"),
                "url": m.group("url"),
                "alert": m.group("alert").strip(),
                "param": m.group("param"),
            })
    return findings


def parse_nuclei(log):
    findings = []
    pattern = re.compile(
        r"\[nuclei\]\s+\[[^\]]+\]\s+\[(?P<severity>[^\]]+)\]\s+\[[^\]]+\]\s+\[(?P<tag>[^\]]+)\]\s+(?P<template>\S+)(?:\s+\S+)?\s+at\s+(?P<target>\S+)"
    )
    for line in log.splitlines():
        m = pattern.search(line)
        if m:
            severity = m.group("severity").capitalize()
            severity = "Informational" if severity == "Info" else severity
            findings.append({
                "scanner": "Nuclei",
                "risk": severity,
                "url": m.group("target"),
                "alert": m.group("template"),
                "param": m.group("tag"),
            })
    return findings


def suggest(alert):
    return SUGGESTIONS.get(alert, "Review finding manually; no canned suggestion available.")


def run_dast_scan(target_url):
    zap_log = get_fake_zap_log(target_url)
    nuclei_log = get_fake_nuclei_log(target_url)
    
    findings = []
    findings.extend(parse_zap(zap_log))
    findings.extend(parse_nuclei(nuclei_log))
    return findings


def parse_proxy_json(uploaded_file):
    """
    Universally parses JSON/CSV files, recursively traversing nested OWASP ZAP 
    reports or proxy log data into graph findings.
    """
    if hasattr(uploaded_file, "read"):
        content = uploaded_file.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="ignore")
    else:
        content = str(uploaded_file)

    findings = []

    def extract_zap_alerts(obj, current_site="Target Endpoint"):
        if isinstance(obj, dict):
            # Capture site context
            site_name = obj.get("@name", obj.get("site", obj.get("name", obj.get("host", current_site))))
            if not isinstance(site_name, str) or not site_name or site_name == "Target Endpoint":
                site_name = current_site

            # Check if this object is a ZAP alert node
            has_alert = any(k in obj for k in ["alert", "alertRef", "pluginId", "name"])
            has_risk = any(k in obj for k in ["riskdesc", "riskcode", "risk", "confidence"])

            if has_alert and has_risk:
                alert_name = str(obj.get("alert", obj.get("name", "Vulnerability Finding")))
                risk_raw = str(obj.get("riskdesc", obj.get("risk", "Medium"))).split(" ")[0]

                instances = obj.get("instances", obj.get("alerts", []))
                if isinstance(instances, list) and len(instances) > 0:
                    for inst in instances:
                        if isinstance(inst, dict):
                            uri = str(inst.get("uri", inst.get("url", site_name)))
                            param = str(inst.get("param", obj.get("param", "N/A")))
                            method = str(inst.get("method", "GET"))
                            findings.append({
                                "scanner": "ZAP Scanner",
                                "risk": risk_raw.capitalize(),
                                "url": uri,
                                "alert": alert_name,
                                "param": f"Param: {param}",
                                "method": method,
                                "tags": "ZAP Alert"
                            })
                else:
                    uri = str(obj.get("url", obj.get("uri", site_name)))
                    param = str(obj.get("param", "N/A"))
                    findings.append({
                        "scanner": "ZAP Scanner",
                        "risk": risk_raw.capitalize(),
                        "url": uri,
                        "alert": alert_name,
                        "param": f"Param: {param}",
                        "method": "GET",
                        "tags": "ZAP Alert"
                    })

            # Recursively check children without aborting parent traversal
            for val in obj.values():
                extract_zap_alerts(val, site_name)

        elif isinstance(obj, list):
            for item in obj:
                extract_zap_alerts(item, current_site)

    # 1. Parse JSON
    try:
        data = json.loads(content)
        extract_zap_alerts(data)
        
        if len(findings) > 0:
            return findings

        # Fallback to pandas extraction for flat/wrapped JSON lists
        if isinstance(data, list):
            df = pd.DataFrame(data)
        elif isinstance(data, dict):
            possible_lists = [v for v in data.values() if isinstance(v, list)]
            if possible_lists:
                df = pd.DataFrame(possible_lists[0])
            else:
                df = pd.DataFrame([data])
        else:
            df = pd.DataFrame()

    except Exception:
        # 2. Fallback to CSV parsing
        try:
            df = pd.read_csv(
                io.StringIO(content),
                on_bad_lines="skip",
                engine="python"
            )
        except Exception as e:
            raise ValueError(f"Unable to parse log as JSON or CSV: {e}")

    # Process flat CSV or converted DataFrame rows
    if not df.empty:
        for _, row in df.iterrows():
            risk = str(row.get("Highest Alert", row.get("risk", row.get("riskdesc", "Unknown")))).strip()
            if not risk or risk.lower() in ["nan", "none", ""]:
                risk = "Informational"

            tags = str(row.get("Tags", row.get("tags", ""))).strip()
            method = str(row.get("Method", row.get("method", "GET"))).strip()
            code = str(row.get("Code", row.get("code", "200")))
            
            if tags and tags.lower() not in ["nan", "none"]:
                alert = f"{method} [{code}] - {tags}"
            else:
                alert = str(row.get("alert", row.get("name", f"{method} [{code}] Traffic")))

            url = str(row.get("URL", row.get("url", row.get("uri", "")))).strip()
            source = str(row.get("Source", row.get("scanner", "Proxy Log"))).strip()
            req_id = str(row.get("ID", row.get("id", ""))).strip()

            if url and url.lower() not in ["nan", "none", "target endpoint"]:
                findings.append({
                    "scanner": source,
                    "risk": risk.capitalize(),
                    "url": url,
                    "alert": alert,
                    "param": f"ID:{req_id} | Code:{code}",
                    "method": method,
                    "tags": tags
                })

    return findings


def build_graph(findings, out_path):
    """
    Generates an interactive PyVis graph connecting Source -> Finding -> Target URL
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

    scanner_nodes, url_nodes = set(), set()

    for idx, f in enumerate(findings):
        scanner = f.get("scanner", "Proxy")
        url = f.get("url", "N/A")
        alert = f.get("alert", "Finding")
        risk = f.get("risk", "Informational")
        param = f.get("param", "N/A")

        color = RISK_COLOR.get(risk, "#95a5a6")

        # 1. Add Source Node
        if scanner not in scanner_nodes:
            net.add_node(
                scanner,
                label=f"🛡️ {scanner}",
                color="#2ecc71",
                shape="hexagon",
                size=35,
                title=f"<b>Log Source:</b> {scanner}"
            )
            scanner_nodes.add(scanner)

        # 2. Add Endpoint Node
        if url not in url_nodes:
            short_url = url.split("//")[-1] if "//" in url else url
            display_url = short_url[:35] + ("..." if len(short_url) > 35 else "")
            net.add_node(
                url,
                label=display_url,
                color="#34495e",
                shape="box",
                size=20,
                title=f"<b>Endpoint:</b><br>{url}"
            )
            url_nodes.add(url)

        # 3. Add Finding Node
        finding_id = f"node_{idx}_{scanner}_{url}"
        tooltip_html = f"""
        <div style='font-family: sans-serif; padding: 6px;'>
            <b style='color: {color};'>[{risk.upper()}] {alert}</b><br/>
            <b>Details:</b> {param}<br/>
            <b>URL:</b> {url}
        </div>
        """

        net.add_node(
            finding_id,
            label=alert,
            color=color,
            shape="diamond",
            size=22,
            title=tooltip_html
        )

        net.add_edge(scanner, finding_id, color="#7f8c8d", width=1.5)
        net.add_edge(finding_id, url, color=color, width=2)

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