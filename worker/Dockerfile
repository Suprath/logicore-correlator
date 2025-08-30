# FILE: worker/Dockerfile (Simplified and Robust Version)

# Use a standard amd64 Python image. Emulation is necessary for the amd64 CodeQL binary.
FROM --platform=linux/amd64 python:3.10-slim-bullseye

# Set the working directory AND add it to the python path.
WORKDIR /app
ENV PYTHONPATH "${PYTHONPATH}:/app"

# [Step 1] Install all system-level dependencies in a single layer.
# This includes git, curl, and ca-certificates.
RUN apt-get update && apt-get install -y \
    ca-certificates \
    git \
    curl \
    unzip \
    zip \
    --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

# [Step 2] Download and set up CodeQL in a single layer.
# We will add the CLI to a known path.
WORKDIR /opt
ARG CODEQL_VERSION=v2.17.5
RUN curl -L -o codeql.zip https://github.com/github/codeql-cli-binaries/releases/download/${CODEQL_VERSION}/codeql-linux64.zip && \
    unzip codeql.zip && \
    rm codeql.zip && \
    mv codeql codeql-cli
# Add CodeQL to the system PATH
ENV PATH="/opt/codeql-cli:$PATH"

# [Step 3] Clone the version-matched CodeQL queries in a single layer.
ARG CODEQL_VERSION=v2.17.5
RUN git clone --depth 1 --branch codeql-cli/${CODEQL_VERSION} https://github.com/github/codeql.git /opt/codeql-repo

# [Step 4] Copy application files and install Python dependencies.
WORKDIR /app
COPY requirements.txt .
COPY worker.py .
COPY rules.yaml .

# This is the most critical step for installation.
RUN pip install --no-cache-dir -r requirements.txt

# [Step 5] **DEBUGGING STEP**: List the installed packages to verify.
# This will show us if 'requests' was actually installed.
RUN pip list

# [Step 6] Define the final command to run the container.
CMD ["celery", "-A", "worker.celery_app", "worker", "--loglevel=INFO"]