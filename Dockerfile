# Copyright 2025 NW-Diff Contributors
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# This file was created or modified with the assistance of an AI (Large Language Model).
# Review required for correctness, security, and licensing.

# Multi-stage build for production-ready nw-diff deployment
FROM python:3.11-slim as builder

# Set working directory
WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Production stage
FROM python:3.11-slim

# Create non-root user for security
RUN useradd -m -u 1000 -s /bin/bash nwdiff

# Set working directory
WORKDIR /app

# Copy Python packages from builder
COPY --from=builder /root/.local /home/nwdiff/.local

# Copy application code
COPY --chown=nwdiff:nwdiff src/ ./src/
COPY --chown=nwdiff:nwdiff templates/ ./templates/
COPY --chown=nwdiff:nwdiff run_app.py .
COPY --chown=nwdiff:nwdiff hosts.csv.sample ./hosts.csv.sample

# Create necessary directories with correct permissions
RUN mkdir -p logs dest origin diff backup && \
    chown -R nwdiff:nwdiff logs dest origin diff backup

# Switch to non-root user
USER nwdiff

# Add user's local bin to PATH
ENV PATH=/home/nwdiff/.local/bin:$PATH
ENV PYTHONPATH=/app/src

# Expose Flask default port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/').read()" || exit 1

# Run the application
CMD ["python", "run_app.py"]
