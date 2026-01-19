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
# Helper script to generate self-signed TLS certificates for development/testing

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="$SCRIPT_DIR/../docker/certs"
CERT_FILE="$CERT_DIR/cert.pem"
KEY_FILE="$CERT_DIR/key.pem"

echo "=== NW-Diff TLS Certificate Setup ==="
echo

# Create certs directory if it doesn't exist
mkdir -p "$CERT_DIR"

# Check if certificates already exist
if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
    read -p "Certificates already exist. Overwrite? (y/N): " OVERWRITE
    if [ "$OVERWRITE" != "y" ] && [ "$OVERWRITE" != "Y" ]; then
        echo "Keeping existing certificates."
        exit 0
    fi
fi

# Get certificate details
read -p "Enter hostname/domain (default: localhost): " HOSTNAME
HOSTNAME=${HOSTNAME:-localhost}

# Generate self-signed certificate
echo "Generating self-signed certificate for $HOSTNAME..."
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=$HOSTNAME" \
    -addext "subjectAltName=DNS:$HOSTNAME,DNS:localhost,IP:127.0.0.1"

# Set appropriate permissions
chmod 644 "$CERT_FILE"
chmod 600 "$KEY_FILE"

echo
echo "✓ Self-signed certificate generated successfully!"
echo "  Certificate: $CERT_FILE"
echo "  Private Key: $KEY_FILE"
echo "  Valid for:   365 days"
echo "  Hostname:    $HOSTNAME"
echo
echo "WARNING: This is a self-signed certificate for development/testing only."
echo "For production, use certificates from a trusted Certificate Authority (CA)"
echo "or use Let's Encrypt with Caddy or certbot."
echo
echo "To trust this certificate locally (for testing):"
echo "  - Linux:   sudo cp $CERT_FILE /usr/local/share/ca-certificates/ && sudo update-ca-certificates"
echo "  - macOS:   sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain $CERT_FILE"
echo "  - Browser: Import certificate in browser settings (accept security warnings)"
