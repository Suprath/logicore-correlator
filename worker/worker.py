# FILE: worker/worker.py (with Git Caching Optimization)
import os
import subprocess
import tempfile
import json
import uuid
import yaml
from datetime import datetime
from celery import Celery
from sqlalchemy import create_engine, Column, String, Text, DateTime, JSON
from sqlalchemy.orm import sessionmaker, declarative_base
import shutil

# --- (Database, Celery, CodeQL, and Rules setup is the same) ---
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
    query_suite_used = Column(String)
Base.metadata.create_all(bind=engine)
celery_app = Celery('tasks', broker=os.environ.get("CELERY_BROKER_URL"), backend=os.environ.get("CELERY_RESULT_BACKEND"))
celery_app.conf.update(task_serializer='json', result_serializer='json', accept_content=['json'], task_track_started=True)
CODEQL_CLI_PATH = "codeql"
CODEQL_QUERIES_ROOT = "/opt/codeql-repo"

# --- NEW: Git Cache Configuration ---
GIT_CACHE_DIR = "/data/git_cache"

def load_rules():
    rules_path = os.path.join(os.path.dirname(__file__), 'rules.yaml')
    try:
        with open(rules_path, 'r') as f: return yaml.safe_load(f)
    except Exception as e:
        print(f"ERROR: Could not load rules.yaml: {e}", flush=True)
        return None
RULES = load_rules()
def select_query_suite(alert_summary: str) -> str:
    # ... (function is correct and remains the same) ...
    if not RULES or not alert_summary: return os.path.join(CODEQL_QUERIES_ROOT, "python/ql/src/codeql-suites/python-security-and-quality.qls")
    summary_lower = alert_summary.lower()
    for rule in RULES.get('mappings', []):
        for keyword in rule.get('alert_keywords', []):
            if keyword in summary_lower:
                print(f"INFO: Matched rule '{rule.get('name')}' on keyword '{keyword}'.", flush=True)
                return os.path.join(CODEQL_QUERIES_ROOT, rule.get('codeql_suite'))
    for rule in RULES.get('mappings', []):
        if 'default' in rule.get('alert_keywords', []):
            print(f"INFO: No specific rule matched. Using default scan: '{rule.get('name')}'.", flush=True)
            return os.path.join(CODEQL_QUERIES_ROOT, rule.get('codeql_suite'))
    return os.path.join(CODEQL_QUERIES_ROOT, "python/ql/src/codeql-suites/python-security-and-quality.qls")
def run_subprocess_shell(command_string: str, cwd: str = ".") -> int:
    """Helper function to run a command as a single string through the shell."""
    print(f"\n[SHELL_COMMAND]: {command_string}", flush=True)
    process = subprocess.Popen(
        command_string, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding='utf-8', errors='replace', cwd=cwd
    )
    for line in iter(process.stdout.readline, ''):
        print(line.strip(), flush=True)
    return process.wait()

# --- Main Celery Task (Updated with Git Caching) ---
@celery_app.task(name='worker.run_analysis')
def run_analysis(payload: dict):
    service_name = payload.get("service_name")
    commit_hash = payload.get("commit_hash")
    alert_summary = payload.get("alert_summary", "")
    query_to_run = select_query_suite(alert_summary)
    db = SessionLocal()
    new_analysis = AnalysisResult(
        service_name=service_name, commit_hash=commit_hash, 
        alert_summary=alert_summary, status="running", query_suite_used=query_to_run
    )
    db.add(new_analysis)
    db.commit()
    db.refresh(new_analysis)
    analysis_id = new_analysis.id
    db.close()
    
    print(f"--- [Worker] Starting analysis (ID: {analysis_id}) for {service_name} at {commit_hash} ---", flush=True)

    repo_url = f"https://github.com/{service_name}.git"
    # Create a unique path for the cached repo based on its name
    local_repo_path = os.path.join(GIT_CACHE_DIR, service_name.replace('/', '_'))

    try:
        # --- GIT CACHING LOGIC ---
        if os.path.isdir(local_repo_path):
            # 1. If repo exists in cache, just fetch the latest changes. This is fast.
            print(f"INFO: Found repository in cache. Fetching updates for {service_name}...", flush=True)
            run_subprocess_shell("git fetch --all", cwd=local_repo_path)
        else:
            # 2. If repo doesn't exist, clone it for the first time. This is slow.
            print(f"INFO: Cloning {service_name} into cache for the first time...", flush=True)
            os.makedirs(local_repo_path, exist_ok=True)
            if run_subprocess_shell(f"git clone {repo_url} {local_repo_path}") != 0:
                raise Exception("git clone failed")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # 3. Create a temporary, clean copy for this specific analysis.
            # This prevents conflicts if two jobs for the same repo run at once.
            work_dir = os.path.join(temp_dir, "repo")
            print(f"INFO: Creating temporary work directory from cache at {work_dir}", flush=True)
            shutil.copytree(local_repo_path, work_dir)
            
            # 4. Check out the specific commit in the temporary copy.
            if run_subprocess_shell(f"git checkout {commit_hash}", cwd=work_dir) != 0:
                raise Exception(f"git checkout of commit {commit_hash} failed")

            # --- CodeQL DATABASE CREATION (UNCHANGED) ---
            db_path = os.path.join(temp_dir, "codeql_db")
            create_db_cmd_str = f"{CODEQL_CLI_PATH} database create {db_path} --language=python --source-root={work_dir}"
            if run_subprocess_shell(create_db_cmd_str) != 0:
                raise Exception("CodeQL database creation failed")
            
            # --- CodeQL ANALYSIS (UNCHANGED) ---
            results_path = os.path.join(temp_dir, "results.sarif")
            analyze_cmd_str = (
                f"{CODEQL_CLI_PATH} database analyze {db_path} "
                f"'{query_to_run}' " # Quote the path to be safe
                f"--format=sarif-latest --output='{results_path}'"
            )
            if run_subprocess_shell(analyze_cmd_str) != 0:
                raise Exception("CodeQL analysis failed.")
            
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
        print(f"ERROR: Analysis failed: {e}", flush=True)
        db = SessionLocal()
        analysis_to_update = db.query(AnalysisResult).filter(AnalysisResult.id == analysis_id).first()
        analysis_to_update.status = "failed"
        analysis_to_update.findings = {"error": str(e)}
        db.commit()
        db.close()
        return {"status": "error", "detail": str(e)}

    return {"status": "complete", "analysis_id": analysis_id}