# FILE: api/api.py
import os
from fastapi import FastAPI, Request, HTTPException, Depends
from celery import Celery
from sqlalchemy import create_engine, Column, String, Text, DateTime, JSON
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.orm.session import Session
from typing import List

# --- Database Setup ---
DATABASE_URL = os.environ.get("DATABASE_URL")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# This model MUST be available to the API to read the data
class AnalysisResult(Base):
    __tablename__ = "analysis_results"
    id = Column(String, primary_key=True)
    service_name = Column(String, nullable=False)
    commit_hash = Column(String, nullable=False)
    alert_summary = Column(Text)
    status = Column(String)
    findings = Column(JSON)
    created_at = Column(DateTime)

# Dependency for getting a DB session in an endpoint
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Celery Configuration ---
celery_app = Celery('tasks', broker=os.environ.get("CELERY_BROKER_URL"), backend=os.environ.get("CELERY_RESULT_BACKEND"))

app = FastAPI(title="LogiCore Correlator API")

@app.post("/webhook")
async def handle_webhook(request: Request):
    # ... (function remains the same) ...
    try:
        payload = await request.json()
        service_name = payload.get("service_name")
        commit_hash = payload.get("commit_hash")
        if not all([service_name, commit_hash]):
            raise HTTPException(status_code=400, detail="Missing required 'service_name' or 'commit_hash'.")
        print(f"INFO: Queuing analysis for {service_name} at commit {commit_hash}")
        celery_app.send_task('worker.run_analysis', args=[payload])
        return {"status": "analysis_queued"}
    except Exception as e:
        print(f"ERROR: Failed to queue task: {e}")
        raise HTTPException(status_code=500, detail="Failed to queue analysis task.")

# --- NEW API ENDPOINTS ---
@app.get("/analyses")
def get_all_analyses(db: Session = Depends(get_db)):
    """Lists all historical analysis runs."""
    results = db.query(AnalysisResult).order_by(AnalysisResult.created_at.desc()).limit(100).all()
    return results

@app.get("/analyses/{analysis_id}")
def get_analysis_by_id(analysis_id: str, db: Session = Depends(get_db)):
    """Gets the detailed result of a specific analysis run."""
    result = db.query(AnalysisResult).filter(AnalysisResult.id == analysis_id).first()
    if not result:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return result

@app.get("/health")
def health_check():
    return {"status": "api_ok"}
