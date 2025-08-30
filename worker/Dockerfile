# FILE: worker/Dockerfile

# --- Stage 1: The "Builder" Stage ---
# Explicitly use the amd64 platform for the builder to match the CodeQL binary
FROM --platform=linux/amd64 debian:bullseye-slim AS builder

ENV DEBIAN_FRONTEND=noninteractive

# Install tools needed to download and unpack CodeQL
RUN apt-get update && apt-get install -y \
    ca-certificates \
    git \
    curl \
    unzip \
    --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt

# Use a recent, stable CodeQL CLI version
ARG CODEQL_VERSION=v2.17.5
RUN curl -L -o codeql.zip https://github.com/github/codeql-cli-binaries/releases/download/${CODEQL_VERSION}/codeql-linux64.zip && \
    unzip codeql.zip && \
    rm codeql.zip && \
    mv codeql codeql-cli


# --- Stage 2: The "Application" Stage ---
# CRITICAL FIX: Use the amd64 platform for the final image as well.
FROM --platform=linux/amd64 python:3.10-slim-bullseye

WORKDIR /app

# Copy the amd64 CodeQL CLI from the amd64 builder stage
COPY --from=builder /opt/codeql-cli /opt/codeql-cli

# Add the copied CodeQL CLI to the PATH
ENV PATH="/opt/codeql-cli:$PATH"

# Install git in the final image, which is needed to clone the queries
RUN apt-get update && apt-get install -y git --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

# CRITICAL FIX: Clone the QUERIES from the same tagged release as the CLI
# This bypasses the problematic 'codeql pack download' authentication issue
ARG CODEQL_VERSION=v2.17.5
RUN git clone --depth 1 --branch codeql-cli/${CODEQL_VERSION} https://github.com/github/codeql.git /opt/codeql-repo

# Copy and install the Python application dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the main application Python script
COPY worker.py .
COPY rules.yaml .

# Expose a port (optional for worker, but good practice)
# EXPOSE 8000 

# The command to run when the container starts. This starts the Celery worker.
CMD ["celery", "-A", "worker.celery_app", "worker", "--loglevel=INFO"]