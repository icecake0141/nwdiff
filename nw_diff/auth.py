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

import base64
import binascii
import hmac
import logging
import os
from functools import wraps

try:
    import bcrypt

    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False

from flask import jsonify, request

logger = logging.getLogger("nw-diff")


def _verify_basic_auth(username: str, password: str) -> bool:
    """
    Verify Basic authentication credentials against environment variables.

    Args:
        username: Username from Basic auth header
        password: Password from Basic auth header

    Returns:
        True if credentials are valid, False otherwise
    """
    expected_user = os.environ.get("NW_DIFF_BASIC_USER")
    password_hash = os.environ.get("NW_DIFF_BASIC_PASSWORD_HASH")
    plaintext_password = os.environ.get("NW_DIFF_BASIC_PASSWORD")

    # If no Basic auth credentials configured, deny access
    if not expected_user:
        return False

    # Check username first (constant-time comparison)
    if not hmac.compare_digest(username, expected_user):
        return False

    # Prefer hashed password verification
    if password_hash:
        if not BCRYPT_AVAILABLE:
            logger.error(
                "bcrypt not available but NW_DIFF_BASIC_PASSWORD_HASH is set. "
                "Install bcrypt for hashed password support."
            )
            return False
        try:
            # bcrypt.checkpw expects bytes
            return bcrypt.checkpw(
                password.encode("utf-8"), password_hash.encode("utf-8")
            )
        except (ValueError, TypeError) as e:
            logger.error("Error verifying password hash: %s", e)
            return False

    # Fall back to plaintext password comparison
    if plaintext_password:
        return hmac.compare_digest(password, plaintext_password)

    # No password configured
    return False


def require_api_token(f):
    """
    Decorator to require authentication for sensitive endpoints.
    Supports both Bearer token and Basic authentication.

    Bearer Token:
    - Token is checked from Authorization: Bearer <token> header
    - Expected token from NW_DIFF_API_TOKEN environment variable

    Basic Authentication:
    - Credentials checked from Authorization: Basic <base64> header
    - Expected username from NW_DIFF_BASIC_USER environment variable
    - Expected password hash from NW_DIFF_BASIC_PASSWORD_HASH (preferred)
    - Or plaintext password from NW_DIFF_BASIC_PASSWORD (fallback)

    If NW_DIFF_API_TOKEN is not set, authentication is not enforced
    (backward compatibility).
    Returns 401 for missing or invalid credentials without leaking
    internal details.
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

        # Check for Basic authentication
        if auth_header.startswith("Basic "):
            # Extract and decode Basic auth credentials
            try:
                # Remove "Basic " prefix (6 characters)
                encoded_credentials = auth_header[6:].strip()
                if not encoded_credentials:
                    logger.warning(
                        "Unauthorized access attempt to %s - "
                        "empty Basic auth credentials",
                        request.path,
                    )
                    return jsonify({"error": "Authentication required"}), 401

                decoded_bytes = base64.b64decode(encoded_credentials)
                decoded_str = decoded_bytes.decode("utf-8")

                # Split on first colon only (password may contain colons)
                if ":" not in decoded_str:
                    logger.warning(
                        "Unauthorized access attempt to %s - "
                        "invalid Basic auth format",
                        request.path,
                    )
                    return jsonify({"error": "Authentication required"}), 401

                username, password = decoded_str.split(":", 1)

                # Verify credentials
                if _verify_basic_auth(username, password):
                    # Basic auth successful
                    return f(*args, **kwargs)

                logger.warning(
                    "Unauthorized access attempt to %s - "
                    "invalid Basic auth credentials",
                    request.path,
                )
                return jsonify({"error": "Authentication required"}), 401

            except (ValueError, UnicodeDecodeError, binascii.Error) as e:
                logger.warning(
                    "Unauthorized access attempt to %s - malformed Basic auth: %s",
                    request.path,
                    e,
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
