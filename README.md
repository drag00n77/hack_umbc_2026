# 🛡️ ZAPini
Team JBAM

An automated web vulnerability dashboard that turns security scans into actionable roadmaps. 

Unlike traditional scanners that just dump a list of flaws, **ZAPini** does a **Scan ➔ Understand ➔ Prioritize ➔ Remediate ➔ Verify** workflow. It leverages **OWASP ZAP** for scanning, a **FastAPI** backend for data communication, **Gemini API** for expert intelligence, and a responsive **Streamlit** user interface integrated with Google Stitch UI.

---

## 🔄 The Closed-Loop Lifecycle

Rather than simply displaying a list of vulnerabilities, **ZAPini** creates an interactive pipeline:

1. **Scan:** OWASP ZAP scans the target application and collects raw vulnerability findings.
2. **Understand:** The backend normalizes the logs and passes them to Gemini for clear explanations, impact analysis, and practical remediation guidance.
3. **Prioritize:** Gemini analyzes the collection of findings globally and prioritizes which vulnerabilities should be addressed first based on severity, evidence, exposure, and potential impact.
4. **Remediate:** The dashboard provides testers and developers with explicit exploit walkthroughs and production-ready source code fixes.
5. **Verify:** After a remediation is applied, users can trigger a verification scan to compare new results against original findings and visually confirm that the flaw was resolved.

---

## ✨ Core Features

* **OWASP ZAP Dynamic Scanning:** Automated dynamic application security testing (DAST) mapping out the target web application attack surface.
* **Gemini-Powered Intelligence:** Automated translation of raw scanner metrics into comprehensive risk explanations and threat impact summaries.
* **Contextual Risk Prioritization:** Intelligent sorting of issues based on dynamic factors such as vulnerability exposure footprint, structural evidence, and server exposure.
* **Dual-Action Frontend Dashboard Tabs:** 
  * **Exploitation Tab:** Step-by-step offensive testing concepts and proof-of-concepts drafted by Gemini to help recreate the issue.
  * **Remediation Tab:** Production-ready code patches and server hardening templates written by Gemini to solve the issue.
* **Regression & Verification Scanner:** Side-by-side comparison engine that cross-references historic scan baselines with live testing payloads to track resolved entries.
* **Slack Collaborative Channel Sync:** Instant formatting and broadcasting of critical-path path exposures into active team notification spaces via Incoming Webhooks.

---

## 🏗️ System Architecture
[ Frontend: Streamlit Web UI ]│  ▲▼  │ (REST API Payload Exchange)[ Backend: FastAPI Engine ] ──(Trigger DAST Scans)──► [ Headless OWASP ZAP Container ]│  ▲                                                     │▼  │ (Context Injection Logs)                             ▼[ Gemini API (JSON Mode) ] ◄────────────────────────────────────┘


---

## 🛠️ Tech Stack

* **Frontend Panel:** Streamlit (Python Dashboard Component Ecosystem)
* **Orchestration Layer:** FastAPI (Python Server Framework)
* **Scan Automation:** OWASP ZAP API (Dynamic Application Security Testing Docker Image)
* **Cognitive Intelligence:** Gemini API (`gemini-2.5-flash` Core Engine Setup)

---

## 🚀 Installation & Local Environment Setup

### 📋 Prerequisites
Ensure you have the following frameworks installed on your system before setting up your workspace:
* Python 3.10+
* Docker (Required for heading headless ZAP container images locally)
* Git

### 🔧 Step 1: Clone the Project Space
```bash
git clone https://github.com
cd vulnpulse
```

### 🐍 Step 2: Establish Python Dependencies
Use separate environment contexts to prevent dependency overlap problems:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 🔑 Step 3: Define Environment Secrets
Create a `.env` configuration file in your backend application root path directory:
```env
GEMINI_API_KEY=your_google_gemini_api_key_here
SLACK_WEBHOOK_URL=https://slack.com
```

---

## 🏃 Execution Commands

### ⚡ Running the FastAPI Backend Core
Launch your orchestration engine instance first:
```bash
uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

### 🖥️ Running the Streamlit Frontend Web App
Open an alternative console terminal window layout and execute the dashboard layer interface:
```bash
streamlit run frontend/app.py
```
Your default browser will launch automatically at `http://localhost:8501`.



## Helpful Notes from Workshop to win your first Hackathon
  
### 1. UI Design 
* **Stitch:** Use Stitch platform to create UI design 
* **Appearance:** Create a polished UI. It can be minimalistic. 

### 2. Tips to winning your first Hackathon 
* **Creativity:** Make sure that your app is creative
* **Impact:** Ask yourself is your project helping only one person or multiple people (thousands).

### 3. Application Development 
* **Antigravity IDE:** Builds apps fast

### 4. Effective Prompt Writing: From Good to Powerful 
* **Give a Role**
* **Define the Goal**
* **Provide Context**
* **Does it Need AI**
* **Create the Vibe**
* **Optional: Add a visual** 

### 4. Presentation 
* **Time Limit:** Make sure that you are able to present your product and demonstrate it within 4 minutes.

### 5. ChatGPT Suggestion 
* **Elevating our Project to the next level:** (https://chatgpt.com/share/6ab83fc1-b830-83e9-9852-d22558304129)
