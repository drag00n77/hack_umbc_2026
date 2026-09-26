# hack_umbc_2026 - CYBERDAWGS TRACK

Application Idea:
 -  Penetration dashboard for a website (https://juice-shop.github.io/)

Details:
 - Penetration tester can use the application dashboard to analyze a website for vulnerabilites
 - Gemini API will analyze website and give vulnerabilities

 Deliverables:
  - Design the frontend for vulnerabilities to be displayed to user (frontend) 
  - Design backend to be able to communicate with ... (between the website and the Gemini API)
  - Add tabs for explaining how it can be exploited or fixed (frontend)
  - Gemini API explains how to fix/exploit (backend)

Hopeful:
 - User can connect to slack channel to have the application send the vulnerabilites to the entire team channel
 - Work on having the application being able to handle all sorts of data

## 🚀 System Architecture
[ Frontend: React/Vue ] ◄──(REST/WebSockets)──► [ Backend: Node/Python ]│┌──────────────────────────────────────────────┴──────────────────────────────┐▼                                                                             ▼[ DAST Scanners: ZAP/Nuclei ] ──(Raw Logs)──► [ Gemini API ] ──(AI Breakdown)──► [ Slack Webhooks ]

### 1. Frontend: Tester Dashboard
* **Target Selector:** Top-bar input to submit target URLs (e.g., OWASP Juice Shop) and trigger audits instantly.
* **Metrics Ribbon:** High-level metric cards tracking total flaws grouped by severity (Critical, High, Medium, Low).
* **Vulnerability Split-Screen:** Left-side interactive alerts sidebar coupled with a right-side detailed tabs panel.
* **Three-Tab Detail Panel:** 
  * **Overview:** Displays affected endpoints, CVSS severity ratings, and raw HTTP request/response payloads.
  * **Exploitation:** Houses a step-by-step offensive walkthrough generated dynamically by the Gemini API.
  * **Remediation:** Provides production-ready code fixes and server hardening guides written by Gemini.

### 2. Backend: Orchestration Pipeline
* **Trigger Event:** Receives target URLs from frontend API requests (`/api/v1/scan`) to spin up background workers.
* **Automated Scan:** Launches headless containerized security scanners to actively map and probe application endpoints.
* **AI Enrichment:** Extracts unstructured scan alerts and streams payloads to the Gemini API using JSON Structured Outputs.
* **Data Persistence:** Caches structured vulnerability JSON objects into database storage before broadcasting to client UI clients.

### 3. Integrations & Security APIs
* **OWASP ZAP API:** Orchestrates full-scale web application vulnerability scanning and captures spider crawl data.
* **Nuclei API:** Executes rapid, template-driven active scans to check for known zero-days and misconfigurations.
* **Slack Webhooks:** Formats critical discoveries into interactive Slack Block Kit alerts for real-time team notifications.
To finish setting up your README, let me know:Do you need the exact Prerequisites and Installation steps (like Docker setup or API key variables)?Would you like a ready-to-paste markdown table for the project roadmap?Do you want the GitHub badges configuration code for your tech stack?Try without personalization

### Team Tasks
* **Jayden:** Look into DAST intergratrion
* **Brittany:** Look into Google Gemini API integration
* **Michael:** Look into frontend implementation
* **Akirit:** Look into linking the frontend and the backend


