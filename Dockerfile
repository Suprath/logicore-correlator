# FILE: Dockerfile

# --- Stage 1: The "Builder" Stage ---
FROM --platform=linux/amd64 debian:bullseye-slim AS builder

ENV DEBIAN_FRONTEND=noninteractive

# ** THE FIX: Add 'ca-certificates' to this list **
RUN apt-get update && apt-get install -y \
    ca-certificates \
    git \
    curl \
    unzip \
    --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt
# Use a recent stable CodeQL CLI version
ARG CODEQL_VERSION=v2.17.5
RUN curl -L -o codeql.zip https://github.com/github/codeql-cli-binaries/releases/download/${CODEQL_VERSION}/codeql-linux64.zip && \
    unzip codeql.zip && \
    rm codeql.zip && \
    mv codeql codeql-cli

# --- Stage 2: The "Application" Stage ---
FROM --platform=linux/amd64 python:3.10-slim-bullseye

WORKDIR /app

COPY --from=builder /opt/codeql-cli /opt/codeql-cli
ENV PATH="/opt/codeql-cli:$PATH"

# Install git in the final image to clone the queries.
# The python base image already has ca-certificates, but it's good practice to be explicit.
RUN apt-get update && apt-get install -y git --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

# Clone the QUERIES from the same tagged release as the CLI.
ARG CODEQL_VERSION=v2.17.5
RUN git clone --depth 1 --branch codeql-cli/${CODEQL_VERSION} https://github.com/github/codeql.git /opt/codeql-repo

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY correlator.py .

EXPOSE 8001

CMD ["uvicorn", "correlator:app", "--host", "0.0.0.0", "--port", "8001"]