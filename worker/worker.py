# FILE: worker/worker.py
import os
import subprocess
import tempfile
import json
from celery import Celery

# --- Celery Configuration ---
# The worker connects to the same Redis broker as the API
celery_app = Celery(
    'tasks',
    broker=os.environ.get("CELERY_BROKER_URL"),
    backend=os.environ.get("CELERY_RESULT_BACKEND")
)
celery_app.conf.update(
    task_serializer='json',
    result_serializer='json',
    accept_content=['json'],
)

# --- CodeQL Configuration ---
CODEQL_CLI_PATH = "codeql"
CODEQL_QUERIES_ROOT = "/opt/codeql-repo"
TARGET_SPECIFIC_QUERY = os.path.join(CODEQL_QUERIES_ROOT, "python/ql/src/Security/CWE-078/CommandInjection.ql")


def run_subprocess(command: list[str], cwd: str = ".") -> int:
    """Helper function to run a command and log its output."""
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
    """
    The main Celery task that performs the CodeQL analysis.
    This is the heavy-lifting part.
    """
    service_name = payload.get("service_name")
    commit_hash = payload.get("commit_hash")
    print(f"--- Starting analysis for {service_name} at {commit_hash} ---", flush=True)

    with tempfile.TemporaryDirectory() as temp_dir:
        repo_url = f"https://github.com/{service_name}.git"
        repo_path = os.path.join(temp_dir, "repo")
        db_path = os.path.join(temp_dir, "codeql_db")

        if run_subprocess(["git", "clone", repo_url, repo_path]) != 0:
            print(f"ERROR: Failed to clone {repo_url}", flush=True)
            return {"status": "error", "detail": "git clone failed"}

        if run_subprocess(["git", "checkout", commit_hash], cwd=repo_path) != 0:
            print(f"ERROR: Failed to checkout {commit_hash}", flush=True)
            return {"status": "error", "detail": "git checkout failed"}

        create_db_cmd = [CODEQL_CLI_PATH, "database", "create", db_path, "--language=python", f"--source-root={repo_path}"]
        if run_subprocess(create_db_cmd) != 0:
            print(f"ERROR: Failed to create CodeQL database", flush=True)
            return {"status": "error", "detail": "database create failed"}

        results_path = os.path.join(temp_dir, "results.sarif")
        analyze_cmd = [CODEQL_CLI_PATH, "database", "analyze", db_path, TARGET_SPECIFIC_QUERY, f"--format=sarif-latest", f"--output={results_path}"]
        if run_subprocess(analyze_cmd) != 0:
            print(f"ERROR: CodeQL analysis failed", flush=True)
            return {"status": "error", "detail": "analysis failed"}
        
        print("\n--- ANALYSIS COMPLETE. PARSING RESULTS... ---", flush=True)
        with open(results_path, 'r') as f:
            results_json = json.load(f)
            for run in results_json.get("runs", []):
                for result in run.get("results", []):
                    message = result.get("message", {}).get("text", "No message.")
                    location = result.get("locations", [{}])[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "N/A")
                    line = result.get("locations", [{}])[0].get("physicalLocation", {}).get("region", {}).get("startLine", "N/A")
                    print(f"VULNERABILITY FOUND: {message}", flush=True)
                    print(f"  -> File: {location}", flush=True)
                    print(f"  -> Line: {line}", flush=True)

    return {"status": "complete", "commit": commit_hash}

# To run the worker from the command line:
# celery -A worker.celery_app worker --loglevel=INFO