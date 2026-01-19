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
# Helper script to generate htpasswd file for Basic Authentication

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HTPASSWD_FILE="$SCRIPT_DIR/../docker/.htpasswd"

echo "=== NW-Diff Basic Auth Setup ==="
echo

# Check if htpasswd is available
if ! command -v htpasswd &> /dev/null; then
    echo "Error: htpasswd command not found."
    echo "Please install apache2-utils (Debian/Ubuntu) or httpd-tools (RHEL/CentOS)"
    echo "  Ubuntu/Debian: sudo apt-get install apache2-utils"
    echo "  RHEL/CentOS:   sudo yum install httpd-tools"
    echo "  macOS:         htpasswd should be pre-installed"
    exit 1
fi

# Get username
read -p "Enter username for Basic Auth: " USERNAME
if [ -z "$USERNAME" ]; then
    echo "Error: Username cannot be empty"
    exit 1
fi

# Create .htpasswd file (will create new or append if exists)
if [ -f "$HTPASSWD_FILE" ]; then
    read -p "File $HTPASSWD_FILE already exists. Overwrite? (y/N): " OVERWRITE
    if [ "$OVERWRITE" = "y" ] || [ "$OVERWRITE" = "Y" ]; then
        htpasswd -c "$HTPASSWD_FILE" "$USERNAME"
        echo "Created new .htpasswd file with user: $USERNAME"
    else
        htpasswd "$HTPASSWD_FILE" "$USERNAME"
        echo "Added user $USERNAME to existing .htpasswd file"
    fi
else
    # Create directory if it doesn't exist
    mkdir -p "$(dirname "$HTPASSWD_FILE")"
    htpasswd -c "$HTPASSWD_FILE" "$USERNAME"
    echo "Created new .htpasswd file with user: $USERNAME"
fi

echo
echo "✓ Basic Auth configuration complete!"
echo "  File: $HTPASSWD_FILE"
echo
echo "To add more users, run this script again or use:"
echo "  htpasswd $HTPASSWD_FILE <username>"
echo
echo "To disable Basic Auth, comment out the following lines in docker/nginx.conf:"
echo "  auth_basic \"NW-Diff Access\";"
echo "  auth_basic_user_file /etc/nginx/.htpasswd;"
