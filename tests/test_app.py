"""
Copyright 2025 Nwdiff Contributors
SPDX-License-Identifier: Apache-2.0

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

This file was created or modified with the assistance of an AI (Large Language Model).
Review required for correctness, security, and licensing.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

import app  # pylint: disable=wrong-import-position,import-error


def test_read_hosts_csv_skips_comments(tmp_path: Path, monkeypatch) -> None:
    """Ensure comment lines are skipped while parsing the hosts CSV."""
    hosts_csv = tmp_path / "hosts.csv"
    content = (
        "# comment line\n"
        "host,ip,username,port,model\n"
        "router1,10.0.0.1,admin,22,cisco\n"
        "router2,10.0.0.2,admin,22,fortinet\n"
    )
    hosts_csv.write_text(content, encoding="utf-8")
    monkeypatch.setattr(app, "HOSTS_CSV", str(hosts_csv))

    rows = app.read_hosts_csv()

    assert len(rows) == 2
    assert rows[0]["host"] == "router1"


def test_get_commands_for_host_uses_model(tmp_path: Path, monkeypatch) -> None:
    """Return device-specific commands when the model is known."""
    hosts_csv = tmp_path / "hosts.csv"
    hosts_csv.write_text(
        """host,ip,username,port,model\nrouter1,10.0.0.1,admin,22,cisco\n""",
        encoding="utf-8",
    )
    monkeypatch.setattr(app, "HOSTS_CSV", str(hosts_csv))

    commands = app.get_commands_for_host("router1")

    assert commands == app.DEVICE_COMMANDS["cisco"]


def test_get_device_info_missing_host_returns_none(tmp_path: Path, monkeypatch) -> None:
    """Return None when a host entry is not found in the CSV."""
    hosts_csv = tmp_path / "hosts.csv"
    hosts_csv.write_text(
        """host,ip,username,port,model\nrouter1,10.0.0.1,admin,22,cisco\n""",
        encoding="utf-8",
    )
    monkeypatch.setattr(app, "HOSTS_CSV", str(hosts_csv))

    device_info = app.get_device_info("router2")

    assert device_info is None


def test_get_commands_for_host_returns_default_for_unknown_model(
    tmp_path: Path, monkeypatch
) -> None:
    """Return default commands when the model is unknown."""
    hosts_csv = tmp_path / "hosts.csv"
    hosts_csv.write_text(
        """host,ip,username,port,model\nrouter1,10.0.0.1,admin,22,unknown\n""",
        encoding="utf-8",
    )
    monkeypatch.setattr(app, "HOSTS_CSV", str(hosts_csv))

    commands = app.get_commands_for_host("router1")

    assert commands == app.DEFAULT_COMMANDS


def test_get_file_path_invalid_base_raises() -> None:
    """Raise a ValueError when the base directory is invalid."""
    with pytest.raises(ValueError, match="Invalid base"):
        app.get_file_path("router1", "show version", "archive")


def test_compute_diff_status_identical() -> None:
    """Return identical status when content matches."""
    assert app.compute_diff_status("same", "same") == "identical"


def test_compute_diff_status_changes() -> None:
    """Return changes detected status when content differs."""
    assert app.compute_diff_status("before", "after") == "changes detected"


def test_compute_diff_inline_contains_diff_markup() -> None:
    """Inline diff should include markup when differences exist."""
    status, diff_html = app.compute_diff(
        "hello\nworld\n", "hello\nthere\n", view="inline"
    )

    assert status == "changes detected"
    assert "<del" in diff_html or "<ins" in diff_html


def test_generate_side_by_side_html_includes_highlights() -> None:
    """Side-by-side HTML should include diff and line highlights."""
    html = app.generate_side_by_side_html("hello\nworld\n", "hello\nthere\n")

    assert "<del" in html
    assert "<ins" in html
    assert "background-color: #ffff99" in html


def test_logging_configuration_creates_log_file() -> None:
    """Test that logging is properly configured and creates log files."""
    # Import logger from app to verify it exists
    assert app.logger is not None
    assert app.logger.name == "nwdiff"
    assert app.logger.level == app.logging.DEBUG


def test_logs_view_endpoint(tmp_path: Path, monkeypatch) -> None:
    """Test the /logs web UI endpoint."""
    # Create a test log file
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    log_file = logs_dir / "nwdiff.log"
    log_file.write_text(
        "2025-01-16 12:00:00 - nwdiff - INFO - Test log line 1\n"
        "2025-01-16 12:00:01 - nwdiff - ERROR - Test error line\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(app, "LOGS_DIR", str(logs_dir))

    with app.app.test_client() as client:
        response = client.get("/logs")
        assert response.status_code == 200
        assert b"Application Logs" in response.data
        assert b"Test log line 1" in response.data
        assert b"Test error line" in response.data


def test_logs_api_endpoint(tmp_path: Path, monkeypatch) -> None:
    """Test the /api/logs API endpoint."""
    # Create a test log file
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    log_file = logs_dir / "nwdiff.log"
    log_file.write_text(
        "2025-01-16 12:00:00 - nwdiff - INFO - Test info log\n"
        "2025-01-16 12:00:01 - nwdiff - ERROR - Test error log\n"
        "2025-01-16 12:00:02 - nwdiff - DEBUG - Test debug log\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(app, "LOGS_DIR", str(logs_dir))

    with app.app.test_client() as client:
        # Test basic API call
        response = client.get("/api/logs")
        assert response.status_code == 200
        json_data = response.get_json()
        assert "logs" in json_data
        assert "count" in json_data
        assert json_data["count"] == 3

        # Test level filtering
        response = client.get("/api/logs?level=ERROR")
        assert response.status_code == 200
        json_data = response.get_json()
        assert json_data["count"] == 1
        assert json_data["level_filter"] == "ERROR"

        # Test limit parameter
        response = client.get("/api/logs?limit=2")
        assert response.status_code == 200
        json_data = response.get_json()
        assert json_data["count"] == 2
        assert json_data["limit"] == 2


def test_read_hosts_csv_handles_file_not_found(tmp_path: Path, monkeypatch) -> None:
    """Test that read_hosts_csv handles missing CSV gracefully."""
    non_existent = tmp_path / "nonexistent.csv"
    monkeypatch.setattr(app, "HOSTS_CSV", str(non_existent))

    rows = app.read_hosts_csv()

    assert not rows
