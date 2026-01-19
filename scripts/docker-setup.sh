#!/bin/bash
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
#
# Quick start script for Docker deployment setup

set -e

echo "==================================="
echo "NW-Diff Docker Deployment Setup"
echo "==================================="
echo

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

# Check Docker is installed
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is not installed."
    echo "Please install Docker from https://docs.docker.com/get-docker/"
    exit 1
fi

if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null 2>&1; then
    echo "Error: Docker Compose is not installed."
    echo "Please install Docker Compose from https://docs.docker.com/compose/install/"
    exit 1
fi

echo "✓ Docker and Docker Compose are installed"
echo

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "Creating .env file from template..."
    cp .env.example .env
    echo "✓ Created .env file"
    echo
    echo "Please edit .env and set:"
    echo "  - DEVICE_PASSWORD (password for device connections)"
    echo "  - NW_DIFF_API_TOKEN (secure token for API)"
    echo
    read -p "Press Enter to continue after editing .env..."
fi

# Create hosts.csv if it doesn't exist
if [ ! -f hosts.csv ]; then
    echo "Creating hosts.csv from sample..."
    cp hosts.csv.sample hosts.csv
    echo "✓ Created hosts.csv"
    echo
    echo "Please edit hosts.csv with your network device information"
    echo
    read -p "Press Enter to continue after editing hosts.csv..."
fi

# Generate TLS certificates
if [ ! -f docker/certs/cert.pem ] || [ ! -f docker/certs/key.pem ]; then
    echo "Generating self-signed TLS certificates..."
    # Allow hostname override via environment variable
    CERT_HOSTNAME=${CERT_HOSTNAME:-localhost}
    bash scripts/mk-certs.sh <<EOF
$CERT_HOSTNAME
EOF
    echo "✓ Generated TLS certificates for $CERT_HOSTNAME"
else
    echo "✓ TLS certificates already exist"
fi

echo

# Generate htpasswd file
if [ ! -f docker/.htpasswd ]; then
    echo "Setting up Basic Authentication..."
    echo "You'll be prompted to create a username and password."
    bash scripts/mk-htpasswd.sh
else
    echo "✓ Basic Auth file already exists"
fi

echo
echo "==================================="
echo "Setup Complete!"
echo "==================================="
echo
echo "To start the application:"
echo "  docker-compose up -d"
echo
echo "To view logs:"
echo "  docker-compose logs -f"
echo
echo "To stop the application:"
echo "  docker-compose down"
echo
echo "Access the application at:"
echo "  https://localhost/ (accept self-signed certificate warning)"
echo
echo "You'll be prompted for Basic Auth credentials."
echo
