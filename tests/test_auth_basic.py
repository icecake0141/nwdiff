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

from __future__ import annotations

import base64
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

import app  # pylint: disable=wrong-import-position,import-error
from nw_diff import (
    devices,
    logging_config,
    storage,
)  # pylint: disable=wrong-import-position

# Check if bcrypt is available
try:
    import bcrypt  # pylint: disable=unused-import

    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False


def _make_basic_auth_header(username: str, password: str) -> str:
    """Helper to create Basic auth header."""
    credentials = f"{username}:{password}"
    encoded = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")
    return f"Basic {encoded}"


# --- Basic Authentication Tests ---


def test_basic_auth_with_plaintext_password_success(
    tmp_path: Path, monkeypatch
) -> None:
    """Test Basic auth succeeds with valid plaintext password."""
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    log_file = logs_dir / "nw-diff.log"
    log_file.write_text("Test log\n", encoding="utf-8")
    monkeypatch.setattr(logging_config, "LOGS_DIR", str(logs_dir))

    # Configure API token to enable auth
    monkeypatch.setenv("NW_DIFF_API_TOKEN", "test_token")
    # Configure Basic auth credentials
    monkeypatch.setenv("NW_DIFF_BASIC_USER", "testuser")
    monkeypatch.setenv("NW_DIFF_BASIC_PASSWORD", "testpass")

    with app.app.test_client() as client:
        response = client.get(
            "/logs",
            headers={"Authorization": _make_basic_auth_header("testuser", "testpass")},
        )

    assert response.status_code == 200
    assert b"Test log" in response.data


def test_basic_auth_with_plaintext_password_wrong_password(monkeypatch) -> None:
    """Test Basic auth fails with wrong password."""
    monkeypatch.setenv("NW_DIFF_API_TOKEN", "test_token")
    monkeypatch.setenv("NW_DIFF_BASIC_USER", "testuser")
    monkeypatch.setenv("NW_DIFF_BASIC_PASSWORD", "testpass")

    with app.app.test_client() as client:
        response = client.get(
            "/logs",
            headers={"Authorization": _make_basic_auth_header("testuser", "wrongpass")},
        )

    assert response.status_code == 401
    assert response.json is not None
    assert response.json["error"] == "Authentication required"


def test_basic_auth_with_plaintext_password_wrong_username(monkeypatch) -> None:
    """Test Basic auth fails with wrong username."""
    monkeypatch.setenv("NW_DIFF_API_TOKEN", "test_token")
    monkeypatch.setenv("NW_DIFF_BASIC_USER", "testuser")
    monkeypatch.setenv("NW_DIFF_BASIC_PASSWORD", "testpass")

    with app.app.test_client() as client:
        response = client.get(
            "/logs",
            headers={"Authorization": _make_basic_auth_header("wronguser", "testpass")},
        )

    assert response.status_code == 401
    assert response.json is not None
    assert response.json["error"] == "Authentication required"


@pytest.mark.skipif(not BCRYPT_AVAILABLE, reason="bcrypt not installed")
def test_basic_auth_with_hashed_password_success(tmp_path: Path, monkeypatch) -> None:
    """Test Basic auth succeeds with valid hashed password."""
    import bcrypt  # pylint: disable=import-outside-toplevel

    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    log_file = logs_dir / "nw-diff.log"
    log_file.write_text("Test log\n", encoding="utf-8")
    monkeypatch.setattr(logging_config, "LOGS_DIR", str(logs_dir))

    # Generate bcrypt hash for "testpass"
    password_hash = bcrypt.hashpw(b"testpass", bcrypt.gensalt()).decode("utf-8")

    monkeypatch.setenv("NW_DIFF_API_TOKEN", "test_token")
    monkeypatch.setenv("NW_DIFF_BASIC_USER", "testuser")
    monkeypatch.setenv("NW_DIFF_BASIC_PASSWORD_HASH", password_hash)

    with app.app.test_client() as client:
        response = client.get(
            "/logs",
            headers={"Authorization": _make_basic_auth_header("testuser", "testpass")},
        )

    assert response.status_code == 200
    assert b"Test log" in response.data


@pytest.mark.skipif(not BCRYPT_AVAILABLE, reason="bcrypt not installed")
def test_basic_auth_with_hashed_password_wrong_password(monkeypatch) -> None:
    """Test Basic auth fails with wrong password when using hash."""
    import bcrypt  # pylint: disable=import-outside-toplevel

    password_hash = bcrypt.hashpw(b"testpass", bcrypt.gensalt()).decode("utf-8")

    monkeypatch.setenv("NW_DIFF_API_TOKEN", "test_token")
    monkeypatch.setenv("NW_DIFF_BASIC_USER", "testuser")
    monkeypatch.setenv("NW_DIFF_BASIC_PASSWORD_HASH", password_hash)

    with app.app.test_client() as client:
        response = client.get(
            "/logs",
            headers={"Authorization": _make_basic_auth_header("testuser", "wrongpass")},
        )

    assert response.status_code == 401
    assert response.json is not None
    assert response.json["error"] == "Authentication required"


@pytest.mark.skipif(not BCRYPT_AVAILABLE, reason="bcrypt not installed")
def test_basic_auth_prefers_hash_over_plaintext(tmp_path: Path, monkeypatch) -> None:
    """Test that hashed password takes precedence over plaintext."""
    import bcrypt  # pylint: disable=import-outside-toplevel

    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    log_file = logs_dir / "nw-diff.log"
    log_file.write_text("Test log\n", encoding="utf-8")
    monkeypatch.setattr(logging_config, "LOGS_DIR", str(logs_dir))

    # Hash for "correctpass"
    password_hash = bcrypt.hashpw(b"correctpass", bcrypt.gensalt()).decode("utf-8")

    monkeypatch.setenv("NW_DIFF_API_TOKEN", "test_token")
    monkeypatch.setenv("NW_DIFF_BASIC_USER", "testuser")
    monkeypatch.setenv("NW_DIFF_BASIC_PASSWORD_HASH", password_hash)
    # Set plaintext to different password (should be ignored)
    monkeypatch.setenv("NW_DIFF_BASIC_PASSWORD", "wrongpass")

    with app.app.test_client() as client:
        # Should succeed with hashed password
        response = client.get(
            "/logs",
            headers={
                "Authorization": _make_basic_auth_header("testuser", "correctpass")
            },
        )
        assert response.status_code == 200

        # Should fail with plaintext password
        response = client.get(
            "/logs",
            headers={"Authorization": _make_basic_auth_header("testuser", "wrongpass")},
        )
        assert response.status_code == 401


def test_basic_auth_empty_credentials(monkeypatch) -> None:
    """Test Basic auth fails with empty Basic header."""
    monkeypatch.setenv("NW_DIFF_API_TOKEN", "test_token")
    monkeypatch.setenv("NW_DIFF_BASIC_USER", "testuser")
    monkeypatch.setenv("NW_DIFF_BASIC_PASSWORD", "testpass")

    with app.app.test_client() as client:
        response = client.get(
            "/logs",
            headers={"Authorization": "Basic "},
        )

    assert response.status_code == 401


def test_basic_auth_malformed_base64(monkeypatch) -> None:
    """Test Basic auth fails with malformed base64."""
    monkeypatch.setenv("NW_DIFF_API_TOKEN", "test_token")
    monkeypatch.setenv("NW_DIFF_BASIC_USER", "testuser")
    monkeypatch.setenv("NW_DIFF_BASIC_PASSWORD", "testpass")

    with app.app.test_client() as client:
        response = client.get(
            "/logs",
            headers={"Authorization": "Basic not-valid-base64!!!"},
        )

    assert response.status_code == 401


def test_basic_auth_missing_colon_separator(monkeypatch) -> None:
    """Test Basic auth fails when credentials don't contain colon separator."""
    monkeypatch.setenv("NW_DIFF_API_TOKEN", "test_token")
    monkeypatch.setenv("NW_DIFF_BASIC_USER", "testuser")
    monkeypatch.setenv("NW_DIFF_BASIC_PASSWORD", "testpass")

    # Encode "username" without colon separator
    encoded = base64.b64encode(b"username").decode("utf-8")

    with app.app.test_client() as client:
        response = client.get(
            "/logs",
            headers={"Authorization": f"Basic {encoded}"},
        )

    assert response.status_code == 401


def test_basic_auth_password_with_colon(tmp_path: Path, monkeypatch) -> None:
    """Test Basic auth works with passwords containing colon."""
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    log_file = logs_dir / "nw-diff.log"
    log_file.write_text("Test log\n", encoding="utf-8")
    monkeypatch.setattr(logging_config, "LOGS_DIR", str(logs_dir))

    monkeypatch.setenv("NW_DIFF_API_TOKEN", "test_token")
    monkeypatch.setenv("NW_DIFF_BASIC_USER", "testuser")
    monkeypatch.setenv("NW_DIFF_BASIC_PASSWORD", "pass:with:colons")

    with app.app.test_client() as client:
        response = client.get(
            "/logs",
            headers={
                "Authorization": _make_basic_auth_header("testuser", "pass:with:colons")
            },
        )

    assert response.status_code == 200


def test_basic_auth_no_user_configured_fails(monkeypatch) -> None:
    """Test Basic auth fails when NW_DIFF_BASIC_USER not configured."""
    monkeypatch.setenv("NW_DIFF_API_TOKEN", "test_token")
    # Don't set NW_DIFF_BASIC_USER
    monkeypatch.setenv("NW_DIFF_BASIC_PASSWORD", "testpass")

    with app.app.test_client() as client:
        response = client.get(
            "/logs",
            headers={"Authorization": _make_basic_auth_header("testuser", "testpass")},
        )

    assert response.status_code == 401


def test_basic_auth_no_password_configured_fails(monkeypatch) -> None:
    """Test Basic auth fails when no password configured."""
    monkeypatch.setenv("NW_DIFF_API_TOKEN", "test_token")
    monkeypatch.setenv("NW_DIFF_BASIC_USER", "testuser")
    # Don't set password or hash

    with app.app.test_client() as client:
        response = client.get(
            "/logs",
            headers={"Authorization": _make_basic_auth_header("testuser", "testpass")},
        )

    assert response.status_code == 401


def test_bearer_token_still_works_with_basic_configured(
    tmp_path: Path, monkeypatch
) -> None:
    """Test Bearer token authentication still works when Basic auth is configured."""
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    log_file = logs_dir / "nw-diff.log"
    log_file.write_text("Test log\n", encoding="utf-8")
    monkeypatch.setattr(logging_config, "LOGS_DIR", str(logs_dir))

    monkeypatch.setenv("NW_DIFF_API_TOKEN", "test_token")
    monkeypatch.setenv("NW_DIFF_BASIC_USER", "testuser")
    monkeypatch.setenv("NW_DIFF_BASIC_PASSWORD", "testpass")

    with app.app.test_client() as client:
        # Bearer token should still work
        response = client.get(
            "/logs",
            headers={"Authorization": "Bearer test_token"},
        )

    assert response.status_code == 200
    assert b"Test log" in response.data


def test_basic_auth_on_capture_endpoint(tmp_path: Path, monkeypatch) -> None:
    """Test Basic auth works on capture endpoint."""
    hosts_csv = tmp_path / "hosts.csv"
    hosts_csv.write_text(
        """host,ip,username,port,model\nrouter1,10.0.0.1,admin,22,cisco\n""",
        encoding="utf-8",
    )
    monkeypatch.setattr(devices, "HOSTS_CSV", str(hosts_csv))

    monkeypatch.setenv("NW_DIFF_API_TOKEN", "test_token")
    monkeypatch.setenv("NW_DIFF_BASIC_USER", "admin")
    monkeypatch.setenv("NW_DIFF_BASIC_PASSWORD", "secret")

    with app.app.test_client() as client:
        response = client.post(
            "/capture/origin/router1",
            headers={"Authorization": _make_basic_auth_header("admin", "secret")},
        )

    # Should not be 401 (will be 404 or 500 due to missing device)
    assert response.status_code != 401


def test_basic_auth_on_export_endpoint(tmp_path: Path, monkeypatch) -> None:
    """Test Basic auth works on export endpoint."""
    hosts_csv = tmp_path / "hosts.csv"
    hosts_csv.write_text(
        """host,ip,username,port,model\nrouter1,10.0.0.1,admin,22,cisco\n""",
        encoding="utf-8",
    )
    monkeypatch.setattr(devices, "HOSTS_CSV", str(hosts_csv))
    monkeypatch.setattr(storage, "ORIGIN_DIR", str(tmp_path / "origin"))
    monkeypatch.setattr(storage, "DEST_DIR", str(tmp_path / "dest"))

    monkeypatch.setenv("NW_DIFF_API_TOKEN", "test_token")
    monkeypatch.setenv("NW_DIFF_BASIC_USER", "admin")
    monkeypatch.setenv("NW_DIFF_BASIC_PASSWORD", "secret")

    with app.app.test_client() as client:
        response = client.get(
            "/api/export/router1",
            headers={"Authorization": _make_basic_auth_header("admin", "secret")},
        )

    # Should not be 401
    assert response.status_code != 401
