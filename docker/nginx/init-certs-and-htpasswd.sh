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
# Automated initialization script for TLS certificates and Basic Auth
# This script is designed for containerized deployments and CI/CD pipelines.
#
# WARNING: Self-signed certificate generation is for development/demo ONLY.
# For production deployments, use certificates from:
#   - Let's Encrypt (recommended, free, automated)
#   - A trusted commercial Certificate Authority
#   - Your organization's internal PKI/CA
#
# Usage:
#   Environment variables for .htpasswd generation (optional):
#     NW_DIFF_BASIC_USER     - Username for Basic Auth
#     NW_DIFF_BASIC_PASSWORD - Password for Basic Auth
#
#   Environment variables for certificate generation (optional):
#     CERT_HOSTNAME          - Hostname/domain for certificate (default: localhost)
#     CERT_DAYS              - Certificate validity in days (default: 365)
#
#   If NW_DIFF_BASIC_USER/PASSWORD are not set, .htpasswd generation is skipped.
#   Never commit generated .htpasswd or certificates to version control.

set -euo pipefail

# Color output for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_ROOT="$(dirname "$DOCKER_DIR")"
CERT_DIR="$DOCKER_DIR/certs"
CERT_FILE="$CERT_DIR/cert.pem"
KEY_FILE="$CERT_DIR/key.pem"
HTPASSWD_FILE="$DOCKER_DIR/.htpasswd"

# Default values
CERT_HOSTNAME="${CERT_HOSTNAME:-localhost}"
CERT_DAYS="${CERT_DAYS:-365}"

log_info "=== NW-Diff Nginx Initialization Script ==="
log_info "Project root: $PROJECT_ROOT"
log_info "Certificate directory: $CERT_DIR"
log_info "htpasswd file: $HTPASSWD_FILE"
echo

# ============================================================================
# TLS Certificate Setup
# ============================================================================
log_info "Checking TLS certificates..."

mkdir -p "$CERT_DIR"

if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
    log_info "Existing certificates found:"
    log_info "  Certificate: $CERT_FILE"
    log_info "  Private Key: $KEY_FILE"
    
    # Verify certificate validity
    if openssl x509 -checkend 86400 -noout -in "$CERT_FILE" >/dev/null 2>&1; then
        EXPIRY=$(openssl x509 -enddate -noout -in "$CERT_FILE" | cut -d= -f2)
        log_info "  Status: Valid (expires: $EXPIRY)"
    else
        log_warn "  Status: Certificate expires within 24 hours or is already expired"
        log_warn "  Consider regenerating certificates"
    fi
else
    log_warn "No existing certificates found. Generating self-signed certificates..."
    log_warn "⚠️  SECURITY WARNING: Self-signed certificates are for DEVELOPMENT/DEMO only!"
    log_warn "⚠️  For PRODUCTION, use certificates from Let's Encrypt or a trusted CA"
    
    # Check if openssl is available
    if ! command -v openssl &> /dev/null; then
        log_error "openssl command not found. Cannot generate certificates."
        log_error "Please install openssl or provide pre-generated certificates in $CERT_DIR"
        exit 1
    fi
    
    # Generate self-signed certificate
    log_info "Generating self-signed certificate for hostname: $CERT_HOSTNAME"
    log_info "Certificate validity: $CERT_DAYS days"
    
    if openssl req -x509 -nodes -days "$CERT_DAYS" -newkey rsa:2048 \
        -keyout "$KEY_FILE" \
        -out "$CERT_FILE" \
        -subj "/C=US/ST=State/L=City/O=Dev/CN=$CERT_HOSTNAME" \
        -addext "subjectAltName=DNS:$CERT_HOSTNAME,DNS:localhost,IP:127.0.0.1" \
        >/dev/null 2>&1; then
        
        # Set appropriate permissions
        chmod 644 "$CERT_FILE"
        chmod 600 "$KEY_FILE"
        
        log_info "✓ Self-signed certificate generated successfully"
        log_info "  Certificate: $CERT_FILE"
        log_info "  Private Key: $KEY_FILE"
        log_info "  Hostname: $CERT_HOSTNAME"
        log_info "  Valid for: $CERT_DAYS days"
    else
        log_error "Failed to generate self-signed certificate"
        log_error "Please check openssl installation and permissions"
        exit 1
    fi
fi

echo

# ============================================================================
# Basic Authentication Setup
# ============================================================================
log_info "Checking Basic Authentication configuration..."

if [ -n "${NW_DIFF_BASIC_USER:-}" ] && [ -n "${NW_DIFF_BASIC_PASSWORD:-}" ]; then
    log_info "Environment variables NW_DIFF_BASIC_USER and NW_DIFF_BASIC_PASSWORD are set"
    log_info "Generating .htpasswd file for user: $NW_DIFF_BASIC_USER"
    
    # Check if htpasswd is available
    if ! command -v htpasswd &> /dev/null; then
        log_error "htpasswd command not found. Cannot generate .htpasswd file."
        log_error "Please install apache2-utils (Debian/Ubuntu) or httpd-tools (RHEL/CentOS)"
        log_error "  Ubuntu/Debian: apt-get install apache2-utils"
        log_error "  RHEL/CentOS:   yum install httpd-tools"
        log_error "  Alpine:        apk add apache2-utils"
        exit 1
    fi
    
    # Create .htpasswd file
    # Use -b for batch mode (password from command line)
    # Use -c to create/overwrite file
    if htpasswd -cb "$HTPASSWD_FILE" "$NW_DIFF_BASIC_USER" "$NW_DIFF_BASIC_PASSWORD" >/dev/null 2>&1; then
        chmod 644 "$HTPASSWD_FILE"
        log_info "✓ .htpasswd file generated successfully"
        log_info "  File: $HTPASSWD_FILE"
        log_info "  User: $NW_DIFF_BASIC_USER"
        log_warn "⚠️  IMPORTANT: Never commit .htpasswd to version control!"
    else
        log_error "Failed to generate .htpasswd file"
        log_error "Please check htpasswd installation and permissions"
        exit 1
    fi
elif [ -f "$HTPASSWD_FILE" ]; then
    log_info "Existing .htpasswd file found:"
    log_info "  File: $HTPASSWD_FILE"
    log_info "  NW_DIFF_BASIC_USER/PASSWORD not set, keeping existing file"
    
    # Count number of users
    USER_COUNT=$(wc -l < "$HTPASSWD_FILE")
    log_info "  Users configured: $USER_COUNT"
else
    log_warn "No .htpasswd file found and NW_DIFF_BASIC_USER/PASSWORD not set"
    log_warn "Basic Authentication will not be available"
    log_info "To enable Basic Auth, either:"
    log_info "  1. Set NW_DIFF_BASIC_USER and NW_DIFF_BASIC_PASSWORD environment variables"
    log_info "  2. Manually create .htpasswd file using: htpasswd -c $HTPASSWD_FILE <username>"
fi

echo

# ============================================================================
# Validation and Final Checks
# ============================================================================
log_info "Running final validation checks..."

# Check certificate permissions
if [ -f "$CERT_FILE" ]; then
    CERT_PERMS=$(stat -c "%a" "$CERT_FILE" 2>/dev/null || stat -f "%OLp" "$CERT_FILE" 2>/dev/null)
    if [ "$CERT_PERMS" != "644" ]; then
        log_warn "Certificate file has permissions $CERT_PERMS (expected 644)"
        chmod 644 "$CERT_FILE" && log_info "  Fixed certificate permissions"
    fi
fi

if [ -f "$KEY_FILE" ]; then
    KEY_PERMS=$(stat -c "%a" "$KEY_FILE" 2>/dev/null || stat -f "%OLp" "$KEY_FILE" 2>/dev/null)
    if [ "$KEY_PERMS" != "600" ]; then
        log_warn "Private key has permissions $KEY_PERMS (expected 600)"
        chmod 600 "$KEY_FILE" && log_info "  Fixed private key permissions"
    fi
fi

# Check .gitignore
GITIGNORE_FILE="$PROJECT_ROOT/.gitignore"
if [ -f "$GITIGNORE_FILE" ]; then
    if ! grep -q "docker/\.htpasswd" "$GITIGNORE_FILE" 2>/dev/null; then
        log_warn ".gitignore does not include docker/.htpasswd"
        log_warn "Consider adding sensitive files to .gitignore to prevent accidental commits"
    fi
    if ! grep -q "docker/certs/" "$GITIGNORE_FILE" 2>/dev/null; then
        log_warn ".gitignore does not include docker/certs/"
        log_warn "Consider adding sensitive files to .gitignore to prevent accidental commits"
    fi
fi

log_info "✓ Initialization complete"
echo

# ============================================================================
# Security Reminders
# ============================================================================
log_warn "════════════════════════════════════════════════════════════════"
log_warn "SECURITY REMINDERS:"
log_warn "════════════════════════════════════════════════════════════════"
log_warn "1. Self-signed certificates are for DEVELOPMENT/DEMO ONLY"
log_warn "   For production: Use Let's Encrypt, commercial CA, or org PKI"
log_warn ""
log_warn "2. Never commit these files to version control:"
log_warn "   - docker/.htpasswd (contains password hashes)"
log_warn "   - docker/certs/* (contains private keys)"
log_warn ""
log_warn "3. When using trusted certificates in production:"
log_warn "   - Enable HSTS in nginx.conf by uncommenting the header"
log_warn "   - Use strong, unique passwords for Basic Auth"
log_warn "   - Regularly rotate certificates and credentials"
log_warn ""
log_warn "4. Review nginx.conf security settings before production deployment"
log_warn "════════════════════════════════════════════════════════════════"

exit 0
