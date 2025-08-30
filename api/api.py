# FILE: api/api.py
import os
from fastapi import FastAPI, Request, HTTPException
from celery import Celery
from celery.result import AsyncResult

# --- Celery Configuration ---
# Get broker and backend URLs from environment variables
CELERY_BROKER_URL = os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0")
CELERY_RESULT_BACKEND = os.environ.get("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")

# Create the Celery application instance
celery_app = Celery(
    'tasks',
    broker=CELERY_BROKER_URL,
    backend=CELERY_RESULT_BACKEND
)

# --- THE FIX: Add explicit configuration to ensure it's not lazy ---
# This tells Celery to confirm the connection and configuration is usable.
celery_app.conf.update(
    task_serializer='json',
    result_serializer='json',
    accept_content=['json'],
    # This setting is important for ensuring the broker is ready
    broker_connection_retry_on_startup=True
)

app = FastAPI(title="LogiCore Correlator API")

@app.post("/webhook")
async def handle_webhook(request: Request):
    """
    Receives a webhook, validates it, and queues a background analysis task.
    Responds instantly.
    """
    try:
        payload = await request.json()
        service_name = payload.get("service_name")
        commit_hash = payload.get("commit_hash")

        if not all([service_name, commit_hash]):
            raise HTTPException(status_code=400, detail="Missing required 'service_name' or 'commit_hash'.")

        print(f"INFO: Queuing analysis for {service_name} at commit {commit_hash}")

        # Send the analysis task to the Celery worker queue.
        celery_app.send_task('worker.run_analysis', args=[payload])

        return {"status": "analysis_queued"}
    except Exception as e:
        print(f"ERROR: Failed to queue task: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to queue analysis task: {e}")


@app.get("/health")
def health_check():
    """Checks the status of the API and its connection to the broker."""
    try:
        # This command forces a connection to the broker.
        # It's a lightweight way to check if the connection is alive.
        celery_app.control.ping()
        broker_status = "ok"
    except Exception as e:
        broker_status = f"error: {e}"

    return {"status": "api_ok", "broker_status": broker_status}