# FILE: worker/worker.py
import os
import subprocess
import tempfile
import json
import uuid
import yaml # <-- IMPORT YAML
from datetime import datetime
from celery import Celery
from sqlalchemy import create_engine, Column, String, Text, DateTime, JSON
from sqlalchemy.orm import sessionmaker, declarative_base

# --- Database and Celery Setup (remains the same) ---
DATABASE_URL = os.environ.get("DATABASE_URL")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
class AnalysisResult(Base):
    __tablename__ = "analysis_results"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    service_name = Column(String, nullable=False)
    commit_hash = Column(String, nullable=False)
    alert_summary = Column(Text)
    status = Column(String, default="pending")
    findings = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
    query_suite_used = Column(String) # NEW: Track which query we ran
Base.metadata.create_all(bind=engine)
celery_app = Celery('tasks', broker=os.environ.get("CELERY_BROKER_URL"), backend=os.environ.get("CELERY_RESULT_BACKEND"))
celery_app.conf.update(task_serializer='json', result_serializer='json', accept_content=['json'])

# --- CodeQL Configuration ---
CODEQL_CLI_PATH = "codeql"
CODEQL_QUERIES_ROOT = "/opt/codeql-repo"

# --- NEW: Rules Engine Logic ---
def load_rules():
    """Loads the mapping rules from rules.yaml."""
    rules_path = os.path.join(os.path.dirname(__file__), 'rules.yaml')
    try:
        with open(rules_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"ERROR: Could not load rules.yaml: {e}", flush=True)
        return None

RULES = load_rules()

def select_query_suite(alert_summary: str) -> str:
    """Selects the best CodeQL query suite based on the alert summary."""
    if not RULES or not alert_summary:
        # Fallback to the default if rules are missing or summary is empty
        return os.path.join(CODEQL_QUERIES_ROOT, "python/ql/src/python-security-and-quality.qls")

    summary_lower = alert_summary.lower()
    
    for rule in RULES.get('mappings', []):
        for keyword in rule.get('alert_keywords', []):
            if keyword in summary_lower:
                print(f"INFO: Matched rule '{rule.get('name')}' on keyword '{keyword}'.", flush=True)
                return os.path.join(CODEQL_QUERIES_ROOT, rule.get('codeql_suite'))
    
    # If no keywords matched, use the one marked 'default'
    for rule in RULES.get('mappings', []):
        if 'default' in rule.get('alert_keywords', []):
            print(f"INFO: No specific rule matched. Using default scan: '{rule.get('name')}'.", flush=True)
            return os.path.join(CODEQL_QUERIES_ROOT, rule.get('codeql_suite'))

    # Final fallback if 'default' isn't even defined
    return os.path.join(CODEQL_QUERIES_ROOT, "python/ql/src/python-security-and-quality.qls")


def run_subprocess(command: list[str], cwd: str = ".") -> int:
    # ... (function remains the same as before) ...
    print(f"\n[COMMAND]: {' '.join(command)}", flush=True)
    process = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding='utf-8', errors='replace', cwd=cwd
    )
    for line in iter(process.stdout.readline, ''):
        print(line.strip(), flush=True)
    return process.wait()

@celery_app.task(name='worker.run_analysis')
def run_analysis(payload: dict):
    service_name = payload.get("service_name")
    commit_hash = payload.get("commit_hash")
    alert_summary = payload.get("alert_summary", "") # Default to empty string

    # --- NEW: Select the query suite dynamically ---
    query_to_run = select_query_suite(alert_summary)

    db = SessionLocal()
    new_analysis = AnalysisResult(
        service_name=service_name,
        commit_hash=commit_hash,
        alert_summary=alert_summary,
        status="running",
        query_suite_used=query_to_run # Store which query we decided to run
    )
    db.add(new_analysis)
    db.commit()
    db.refresh(new_analysis)
    analysis_id = new_analysis.id
    db.close()
    
    print(f"--- [Worker] Starting analysis (ID: {analysis_id}) for {service_name} at {commit_hash} ---", flush=True)
    print(f"--- [Worker] Using query suite: {query_to_run} ---", flush=True)

    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            # ... (git and codeql database create logic is the same) ...
            repo_url = f"https://github.com/{service_name}.git"
            repo_path = os.path.join(temp_dir, "repo")
            db_path = os.path.join(temp_dir, "codeql_db")
            run_subprocess(["git", "clone", repo_url, repo_path])
            run_subprocess(["git", "checkout", commit_hash], cwd=repo_path)
            run_subprocess([CODEQL_CLI_PATH, "database", "create", db_path, "--language=python", f"--source-root={repo_path}"])
            
            results_path = os.path.join(temp_dir, "results.sarif")
            # --- MODIFIED: Use the dynamically selected query ---
            analyze_cmd = [CODEQL_CLI_PATH, "database", "analyze", db_path, query_to_run, f"--format=sarif-latest", f"--output={results_path}"]
            run_subprocess(analyze_cmd)
            
            print("\n--- [Worker] ANALYSIS COMPLETE. SAVING RESULTS... ---", flush=True)
            with open(results_path, 'r') as f:
                results_json = json.load(f)
            
            db = SessionLocal()
            analysis_to_update = db.query(AnalysisResult).filter(AnalysisResult.id == analysis_id).first()
            analysis_to_update.status = "complete"
            analysis_to_update.findings = results_json
            db.commit()
            db.close()

    except Exception as e:
        # ... (error handling is the same) ...
        print(f"ERROR: Analysis failed: {e}", flush=True)
        db = SessionLocal()
        analysis_to_update = db.query(AnalysisResult).filter(AnalysisResult.id == analysis_id).first()
        analysis_to_update.status = "failed"
        analysis_to_update.findings = {"error": str(e)}
        db.commit()
        db.close()
        return {"status": "error", "detail": str(e)}

    return {"status": "complete", "analysis_id": analysis_id}