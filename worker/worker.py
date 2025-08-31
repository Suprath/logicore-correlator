# FILE: worker/worker.py
import os
import subprocess
import tempfile
import json
import uuid
import yaml
import re
import shlex
from datetime import datetime
from celery import Celery
from sqlalchemy import create_engine, Column, String, Text, DateTime, JSON
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.exc import OperationalError
import time

# --- Database Setup ---
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

def init_database():
    """Waits for the database to be ready and then creates the table."""
    max_retries = 10
    retry_delay_seconds = 5
    for attempt in range(max_retries):
        try:
            Base.metadata.create_all(bind=engine)
            print("INFO: Database table 'analysis_results' is ready.", flush=True)
            return
        except OperationalError:
            print(f"WARN: Database not ready yet. Waiting {retry_delay_seconds}s.", flush=True)
            time.sleep(retry_delay_seconds)
    raise Exception("Could not connect to the database after multiple retries.")

init_database()

# --- Celery Configuration ---
celery_app = Celery('tasks', broker=os.environ.get("CELERY_BROKER_URL"), backend=os.environ.get("CELERY_RESULT_BACKEND"))
celery_app.conf.update(
    task_serializer='json',
    result_serializer='json',
    accept_content=['json'],
    task_track_started=True
)

# --- CodeQL Configuration ---
CODEQL_CLI_PATH = "codeql"
CODEQL_QUERIES_ROOT = "/opt/codeql-repo"

# --- Rules Engine Logic ---
def load_rules():
    rules_path = os.path.join(os.path.dirname(__file__), 'rules.yaml')
    try:
        with open(rules_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"ERROR: Could not load rules.yaml: {e}", flush=True)
        return None
RULES = load_rules()

def select_query_suite(alert_summary: str) -> str:
    if not RULES or not alert_summary:
        return os.path.join(CODEQL_QUERIES_ROOT, "python/ql/src/codeql-suites/python-security-and-quality.qls")
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

# --- Main Celery Task for General Analysis ---
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

    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_url = f"https://github.com/{service_name}.git"
            repo_path = os.path.join(temp_dir, "repo")
            db_path = os.path.join(temp_dir, "codeql_db")

            if run_subprocess_shell(f"git clone --depth 1 {shlex.quote(repo_url)} {shlex.quote(repo_path)}") != 0:
                raise Exception("git clone failed")
            
            if run_subprocess_shell(f"git checkout {shlex.quote(commit_hash)}", cwd=repo_path) != 0:
                raise Exception("git checkout failed")

            create_db_cmd_str = (
                f"{CODEQL_CLI_PATH} database create {shlex.quote(db_path)} "
                f"--language=python --source-root={shlex.quote(repo_path)}"
            )
            if run_subprocess_shell(create_db_cmd_str) != 0:
                raise Exception("CodeQL database creation failed")
            
            results_path = os.path.join(temp_dir, "results.sarif")
            analyze_cmd_str = (
                f"{CODEQL_CLI_PATH} database analyze {shlex.quote(db_path)} "
                f"{shlex.quote(query_to_run)} "
                f"--format=sarif-latest --output={shlex.quote(results_path)}"
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


# --- NEW: Root Cause Analysis Logic ---

def parse_stack_trace_for_sink(stack_trace: str) -> dict:
    """Parses a stack trace to find a potential sink (file and line)."""
    # Example Python: "File \"/app/main.py\", line 23, in run_command"
    match = re.search(r'File "([^"]+)", line (\d+)', stack_trace)
    if match:
        full_path = match.group(1)
        file_name = os.path.basename(full_path)
        line_number = int(match.group(2))
        return {"file": file_name, "line": line_number}
    return None

def generate_taint_query(sink_file: str, sink_line: int) -> str:
    """Generates a syntactically correct CodeQL taint tracking query."""
    # This query finds data flow paths from any web request source
    # to the specific file and line number identified as the sink.
    query_template = f"""
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.web.HttpRequest

module RootCauseQuery {{
  class RootCauseConfig extends TaintTracking::Configuration {{
    RootCauseConfig() {{ this = "RootCauseConfig" }}

    override predicate isSource(DataFlow::Node source) {{
      source.asSource() instanceof RemoteFlowSource
    }}

    override predicate isSink(DataFlow::Node sink) {{
      exists(Location loc |
        loc = sink.getLocation() and
        loc.getFile().getShortName() = "{sink_file}" and
        loc.getStartLine() = {sink_line}
      )
    }}
  }}
}}

import RootCauseQuery

from RootCauseConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source.getNode(), "Dataflow path from an HTTP request to the error location at line {{0}}.", sink.getNode().getLocation().getStartLine(), ""
"""
    return query_template

@celery_app.task(name='worker.find_root_cause')
def find_root_cause(payload: dict):
    service_name = payload.get("service_name")
    commit_hash = payload.get("commit_hash")
    log_message = payload.get("log_message", "")
    stack_trace = payload.get("stack_trace", "")
    
    sink_info = parse_stack_trace_for_sink(stack_trace)
    if not sink_info:
        return {"status": "error", "detail": "Could not parse a valid sink from the stack trace."}

    db = SessionLocal()
    new_analysis = AnalysisResult(
        service_name=service_name, commit_hash=commit_hash,
        alert_summary=f"Root cause analysis for error: {log_message[:100]}...",
        status="running",
        query_suite_used="custom/root_cause_taint_track.ql"
    )
    db.add(new_analysis)
    db.commit()
    db.refresh(new_analysis)
    analysis_id = new_analysis.id
    db.close()

    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_url = f"https://github.com/{service_name}.git"
            repo_path = os.path.join(temp_dir, "repo")
            db_path = os.path.join(temp_dir, "codeql_db")
            if run_subprocess_shell(f"git clone --depth 1 {shlex.quote(repo_url)} {shlex.quote(repo_path)}") != 0: raise Exception("Git clone failed")
            if run_subprocess_shell(f"git checkout {shlex.quote(commit_hash)}", cwd=repo_path) != 0: raise Exception("Git checkout failed")
            
            create_db_cmd_str = f"{CODEQL_CLI_PATH} database create {shlex.quote(db_path)} --language=python --source-root={shlex.quote(repo_path)}"
            if run_subprocess_shell(create_db_cmd_str) != 0: raise Exception("CodeQL database creation failed")
            
            taint_query = generate_taint_query(sink_info["file"], sink_info["line"])
            query_path = os.path.join(temp_dir, "root_cause_query.ql")
            with open(query_path, 'w') as f:
                f.write(taint_query)
            
            print(f"INFO: Generated custom root cause query for sink at {sink_info['file']}:{sink_info['line']}", flush=True)

            results_path = os.path.join(temp_dir, "results.sarif")
            analyze_cmd_str = (
                f"{CODEQL_CLI_PATH} database analyze {shlex.quote(db_path)} "
                f"{shlex.quote(query_path)} "
                f"--format=sarif-latest --output={shlex.quote(results_path)}"
            )
            if run_subprocess_shell(analyze_cmd_str) != 0:
                raise Exception("CodeQL root cause analysis failed.")
            
            with open(results_path, 'r') as f:
                results_json = json.load(f)
            
            db = SessionLocal()
            analysis_to_update = db.query(AnalysisResult).filter(AnalysisResult.id == analysis_id).first()
            analysis_to_update.status = "complete"
            analysis_to_update.findings = results_json
            db.commit()
            db.close()

    except Exception as e:
        print(f"ERROR: Root cause analysis failed: {e}", flush=True)
        db = SessionLocal()
        analysis_to_update = db.query(AnalysisResult).filter(AnalysisResult.id == analysis_id).first()
        analysis_to_update.status = "failed"
        analysis_to_update.findings = {"error": str(e)}
        db.commit()
        db.close()
        return {"status": "error", "detail": str(e)}

    return {"status": "complete", "analysis_id": analysis_id}