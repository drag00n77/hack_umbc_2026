# FINAL HACKATHON DRAFT

AI-assisted cybersecurity vulnerability analysis and remediation platform.

## Setup

Install the required Python packages:

```bash
pip install -r requirements.txt
```

## Run the Application

Open **3 separate terminals** and run the following commands.

### Terminal 1 — DAST Backend

```bash
python -m uvicorn dast_backend:app --reload --port 9000
```

### Terminal 2 — Main FastAPI Backend

```bash
python -m uvicorn main:app --reload --port 8000
```

### Terminal 3 — Frontend

```bash
python -m streamlit run frontend.py
```

Once all three services are running, open the Streamlit URL shown in Terminal 3.

## Application Workflow

```text
Target Website
      ↓
DAST Scan
      ↓
Vulnerability Findings
      ↓
Gemini AI Analysis
      ↓
Prioritization & Remediation
      ↓
Verification Scan
```

> **Note:** Only scan systems you have explicit authorization to test.

