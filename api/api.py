# FILE: api/api.py
import os
from fastapi import FastAPI, Request, HTTPException
from celery import Celery

# Configure Celery
celery_app = Celery(
    'tasks',
    broker=os.environ.get("CELERY_BROKER_URL"),
    backend=os.environ.get("CELERY_RESULT_BACKEND")
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
            raise HTTPException(status_code=400, detail="Missing required fields.")

        print(f"INFO: Queuing analysis for {service_name} at commit {commit_hash}")

        # Send the analysis task to the Celery worker
        celery_app.send_task('worker.run_analysis', args=[payload])

        return {"status": "analysis_queued"}
    except Exception as e:
        print(f"ERROR: Failed to queue task: {e}")
        raise HTTPException(status_code=500, detail="Failed to queue analysis task.")

@app.get("/health")
def health_check():
    return {"status": "ok"}