"""
Copyright 2025 NW-Diff Contributors
SPDX-License-Identifier: Apache-2.0

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

This file was created or modified with the assistance of an AI (Large Language Model).
Review required for correctness, security, and licensing.
"""

import hmac
import logging
import os
from functools import wraps

from flask import jsonify, request

logger = logging.getLogger("nw-diff")


def require_api_token(f):
    """
    Decorator to require API token authentication for sensitive endpoints.
    Token is checked from Authorization: Bearer <token> header.
    The expected token is read from NW_DIFF_API_TOKEN environment variable.
    Returns 401 for missing or invalid tokens without leaking internal details.
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        expected_token = os.environ.get("NW_DIFF_API_TOKEN")

        # If no token is configured, authentication is not enforced
        if not expected_token:
            logger.warning(
                "NW_DIFF_API_TOKEN not set - authentication not enforced for %s",
                request.path,
            )
            return f(*args, **kwargs)

        # Check Authorization header
        auth_header = request.headers.get("Authorization")

        if not auth_header:
            logger.warning(
                "Unauthorized access attempt to %s - missing Authorization header",
                request.path,
            )
            return jsonify({"error": "Authentication required"}), 401

        # Check for Bearer token format with at least one character after
        # "Bearer " is 7 characters, so we need at least 8 characters total
        if not auth_header.startswith("Bearer ") or len(auth_header) < 8:
            logger.warning(
                "Unauthorized access attempt to %s - invalid Authorization format",
                request.path,
            )
            return jsonify({"error": "Authentication required"}), 401

        # Extract token (everything after "Bearer ")
        token = auth_header[7:]  # Remove "Bearer " prefix

        # Use constant-time comparison to prevent timing attacks
        # hmac.compare_digest safely handles tokens of different lengths
        if not hmac.compare_digest(token, expected_token):
            logger.warning(
                "Unauthorized access attempt to %s - invalid token", request.path
            )
            return jsonify({"error": "Authentication required"}), 401

        # Token is valid, proceed with the request
        return f(*args, **kwargs)

    return decorated_function
