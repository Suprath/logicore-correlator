# FILE: api/Dockerfile
FROM python:3.10-slim-bullseye

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY api.py .

EXPOSE 8001

# CRITICAL FIX: The command to run the API server
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8001"]