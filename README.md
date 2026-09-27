**DO NOT DELETE PLEASE**:
 pip install -r requirements.txt
 
Running commands on 3 separate terminals:
  (1) DAST-backend: uvicorn dast_backend:app --reload --port 9000
  (2) main.py (FastAPI): uvicorn main:app --reload --port 8000
  (3) frontend.py: streamlit run frontend.py
