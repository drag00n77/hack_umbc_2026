# 🛡️ ZAPini - Run DEMO branch for testing

### Team JBAM
hackUMBC Presentation: https://canva.link/ua5kpux20kd84i3

**ZAPini** is an automated web vulnerability dashboard designed to turn security scan results into a simple, actionable workflow.

Our original goal was to create a closed-loop security platform:

**Scan → Understand → Prioritize → Remediate → Verify**

The project combines **OWASP ZAP**, **FastAPI**, **Streamlit**, and a planned **Gemini API** integration.

---

## 🔄 Project Workflow

The intended ZAPini workflow is:

```text
Target Website
      ↓
OWASP ZAP Scan
      ↓
Vulnerability Findings
      ↓
AI Analysis & Prioritization
      ↓
Remediation
      ↓
Verification Scan
```

---

## ✅ What We Completed During the Competition

Due to the limited hackathon development time, we focused on getting the core application working.

### Completed

* **OWASP ZAP scanning**

  * Automated web application vulnerability scanning.
  * Successfully connected the scanning workflow to the application.

* **FastAPI backend**

  * Handles communication between the frontend and scanning system.
  * Processes scan results for the dashboard.

* **Streamlit dashboard**

  * Displays scan information and vulnerability results.
  * Includes a **Suggestions** tab for recommended actions.

### Planned but Not Integrated

We designed several additional features but did not have enough time to complete them during the competition:

* Gemini API vulnerability explanations
* AI-powered vulnerability prioritization
* Automated remediation guidance
* Remediation verification and before/after comparison
* Slack notifications
* Full Google Stitch UI integration

These features represent the intended next stage of ZAPini.

---

## 🏗️ Architecture

```text
┌─────────────────────┐
│ Streamlit Frontend  │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│   FastAPI Backend   │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│     OWASP ZAP       │
│    DAST Scanner     │
└─────────────────────┘
```

### Planned AI Extension

```text
OWASP ZAP
    ↓
FastAPI
    ↓
Gemini API
    ↓
Explanation
Prioritization
Remediation
    ↓
Streamlit Dashboard
```

---

## 🛠️ Tech Stack

* **Frontend:** Streamlit
* **Backend:** FastAPI
* **Security Scanner:** OWASP ZAP
* **Planned AI:** Google Gemini API
* **UI Design:** Google Stitch
* **Language:** Python

---

## 🎨 Google Stitch UI Design

Our planned UI was designed using Google Stitch:

[**View the ZAPini Google Stitch Design**](https://aistudio.google.com/apps/80e8b93e-ad14-432f-86a3-63479c070f4a?showAssistant=true&showPreview=true&fullscreenApplet=true)

We did not have enough time during the competition to fully integrate the Stitch-designed interface into the application.

---

## 🚀 Installation

### 1. Clone the repository

```bash
git clone <repository-url>
cd <repository-folder>
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Create a virtual environment *(recommended)*

```bash
python -m venv venv
```

Activate it:

**Windows**

```bash
venv\Scripts\activate
```

**Mac/Linux**

```bash
source venv/bin/activate
```

---

## ▶️ Run the Application

Open **three separate terminals**.

### Terminal 1 — DAST Backend

```bash
uvicorn dast_backend:app --reload --port 9000
```

### Terminal 2 — Main FastAPI Backend

```bash
uvicorn main:app --reload --port 8000
```

### Terminal 3 — Streamlit Frontend

```bash
streamlit run frontend.py
```

Streamlit will provide a local URL, usually:

```text
http://localhost:8501
```

---

## 🧪 Competition Status

ZAPini successfully demonstrated the core security scanning workflow during the competition.

**OWASP ZAP:** Working
**FastAPI Backend:** Working
**Streamlit Dashboard:** Working
**Suggestions Tab:** Integrated
**Gemini API:** Planned, but not integrated before the competition deadline
**Stitch UI:** Designed, but not fully integrated before the competition deadline

The project was intentionally structured so that Gemini and the additional remediation features can be added in future development.

---

## 🔮 Future Development

The next major version of ZAPini would extend the existing scanning workflow with:

1. **Gemini vulnerability explanations**
2. **AI vulnerability prioritization**
3. **Remediation recommendations**
4. **Remediation verification**
5. **Before-and-after security comparisons**
6. **Slack team notifications**
7. **Full Stitch UI integration**

The long-term goal is to turn ZAPini from a vulnerability dashboard into a complete:

**Scan → Understand → Prioritize → Remediate → Verify**

security workflow.

---

## ⚠️ Responsible Use

ZAPini should only be used to test systems that you own or have explicit authorization to assess.
