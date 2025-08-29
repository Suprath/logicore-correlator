# FILE: correlator.py
import os
import subprocess
import tempfile
from fastapi import FastAPI, Request, HTTPException
import uvicorn
import json

# --- Configuration ---
# Assumes 'codeql' is in your system PATH.
CODEQL_CLI_PATH = "codeql"

# **THE FIX**: Point to the path where we cloned the queries inside the Docker image.
CODEQL_QUERIES_ROOT = "/opt/codeql-repo"

# The full path to the specific QUERY file (.ql) for command injection.
TARGET_SPECIFIC_QUERY = os.path.join(CODEQL_QUERIES_ROOT, "python/ql/src/Security/CWE-078/CommandInjection.ql")


app = FastAPI(title="LogiCore Incident Correlator")

def run_subprocess(command: list[str], cwd: str = ".") -> int:
    """
    Helper function to run a command, print its output in real-time,
    and return its exit code.
    """
    print(f"\n[COMMAND]: {' '.join(command)}")
    print(f"[IN_DIR]:  {cwd}")
    print("-" * 40)
    
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding='utf-8',
        errors='replace',
        cwd=cwd
    )

    while True:
        output = process.stdout.readline()
        if output == '' and process.poll() is not None:
            break
        if output:
            print(output.strip())
    
    rc = process.poll()
    if rc != 0:
        print(f"--- [ERROR]: Command failed with exit code {rc} ---")
    else:
        print(f"--- [SUCCESS]: Command finished successfully ---")

    return rc

@app.post("/webhook")
async def handle_webhook(request: Request):
    """Receives the incident/deployment webhook from GitHub Actions."""
    try:
        payload = await request.json()
        service_name = payload.get("service_name")
        commit_hash = payload.get("commit_hash")
        alert = payload.get("alert_summary")

        if not all([service_name, commit_hash, alert]):
            raise HTTPException(status_code=400, detail="Missing required fields in payload.")

        print("="*50)
        print(f"Received Incident Webhook: '{alert}'")
        print(f"Service: {service_name}")
        print(f"Suspect Commit: {commit_hash}")
        print("="*50)

        with tempfile.TemporaryDirectory() as temp_dir:
            repo_url = f"https://github.com/{service_name}.git"
            repo_path = os.path.join(temp_dir, "repo")
            db_path = os.path.join(temp_dir, "codeql_db")
            
            if run_subprocess(["git", "clone", repo_url, repo_path]) != 0:
                raise HTTPException(status_code=500, detail="Failed to clone repository.")
            
            if run_subprocess(["git", "checkout", commit_hash], cwd=repo_path) != 0:
                raise HTTPException(status_code=500, detail="Failed to checkout commit.")

            create_db_cmd = [CODEQL_CLI_PATH, "database", "create", db_path, "--language=python", f"--source-root={repo_path}"]
            if run_subprocess(create_db_cmd) != 0:
                raise HTTPException(status_code=500, detail="Failed to create CodeQL database.")

            results_path = os.path.join(temp_dir, "results.sarif")
            analyze_cmd = [
                CODEQL_CLI_PATH, "database", "analyze", db_path,
                TARGET_SPECIFIC_QUERY,
                f"--format=sarif-latest",
                f"--output={results_path}"
            ]
            if run_subprocess(analyze_cmd) != 0:
                raise HTTPException(status_code=500, detail="CodeQL analysis failed.")

            print("\n" + "="*50)
            print("ANALYSIS COMPLETE. RESULTS:")
            print("="*50)
            with open(results_path, 'r') as f:
                results_json = json.load(f)
                for run in results_json.get("runs", []):
                    for result in run.get("results", []):
                        message = result.get("message", {}).get("text", "No message.")
                        location = result.get("locations", [{}])[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "N/A")
                        line = result.get("locations", [{}])[0].get("physicalLocation", {}).get("region", {}).get("startLine", "N/A")
                        print(f"VULNERABILITY FOUND: {message}")
                        print(f"  -> File: {location}")
                        print(f"  -> Line: {line}")
                        print("-" * 20)
        
        return {"status": "analysis_complete", "commit": commit_hash}

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    print("Starting LogiCore Incident Correlator on http://localhost:8001")
    # The webhook endpoint will be http://<your-ngrok-url>/webhook
    uvicorn.run(app, host="0.0.0.0", port=8001)
