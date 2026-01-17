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

import os
import re
import sys
import time
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

import app  # pylint: disable=wrong-import-position,import-error


def test_read_hosts_csv_skips_comments(tmp_path: Path, monkeypatch) -> None:
    """Ensure comment lines are skipped while parsing the hosts CSV."""
    hosts_csv = tmp_path / "hosts.csv"
    csv_content = (
        "# comment line\n"
        "host,ip,username,port,model\n"
        "router1,10.0.0.1,admin,22,cisco\n"
        "router2,10.0.0.2,admin,22,fortinet\n"
    )
    hosts_csv.write_text(csv_content, encoding="utf-8")
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


def test_get_backup_filename_format(tmp_path: Path, monkeypatch) -> None:
    """Ensure backup filename follows the correct format."""
    monkeypatch.setattr(app, "BACKUP_DIR", str(tmp_path / "backup"))
    filepath = "/home/runner/work/nwdiff/nwdiff/origin/router1-show_version.txt"

    backup_filename = app.get_backup_filename(filepath)

    # Check that backup filename includes timestamp and original filename
    assert "router1-show_version.txt" in backup_filename
    assert str(tmp_path / "backup") in backup_filename
    # Verify timestamp format YYYYMMDD_HHMMSS
    pattern = r"\d{8}_\d{6}_router1-show_version\.txt"
    assert re.search(pattern, backup_filename)


def test_create_backup_when_file_exists(tmp_path: Path, monkeypatch) -> None:
    """Backup should be created when file exists."""
    backup_dir = tmp_path / "backup"
    backup_dir.mkdir()
    monkeypatch.setattr(app, "BACKUP_DIR", str(backup_dir))

    # Create a test file
    test_file = tmp_path / "test.txt"
    test_file.write_text("original content", encoding="utf-8")

    app.create_backup(str(test_file))

    # Check that backup was created
    backup_files = list(backup_dir.glob("*_test.txt"))
    assert len(backup_files) == 1
    assert backup_files[0].read_text(encoding="utf-8") == "original content"


def test_create_backup_when_file_does_not_exist(tmp_path: Path, monkeypatch) -> None:
    """No backup should be created when file does not exist."""
    backup_dir = tmp_path / "backup"
    backup_dir.mkdir()
    monkeypatch.setattr(app, "BACKUP_DIR", str(backup_dir))

    # Try to backup a non-existent file
    test_file = tmp_path / "nonexistent.txt"

    app.create_backup(str(test_file))

    # Check that no backup was created
    backup_files = list(backup_dir.glob("*_nonexistent.txt"))
    assert len(backup_files) == 0


def test_rotate_backups_keeps_last_10(tmp_path: Path, monkeypatch) -> None:
    """Rotation should keep only the last 10 backups."""
    backup_dir = tmp_path / "backup"
    backup_dir.mkdir()
    monkeypatch.setattr(app, "BACKUP_DIR", str(backup_dir))

    test_file = tmp_path / "test.txt"
    test_file.write_text("content", encoding="utf-8")

    # Create 15 backups with different timestamps
    for i in range(15):
        backup_path = backup_dir / f"backup_{i:02d}_test.txt"
        backup_path.write_text(f"content {i}", encoding="utf-8")
        # Set modification time to ensure proper ordering
        mtime = time.time() - (15 - i)
        os.utime(str(backup_path), (mtime, mtime))

    app.rotate_backups(str(test_file))

    # Check that only 10 backups remain
    backup_files = list(backup_dir.glob("*_test.txt"))
    assert len(backup_files) == 10

    # Verify that the oldest ones were deleted
    remaining_names = sorted([f.name for f in backup_files])
    for i in range(5, 15):
        assert f"backup_{i:02d}_test.txt" in remaining_names


def test_export_json_returns_404_for_missing_hostname(
    tmp_path: Path, monkeypatch
) -> None:
    """Return 404 error when hostname is not found in CSV."""
    hosts_csv = tmp_path / "hosts.csv"
    hosts_csv.write_text(
        """host,ip,username,port,model\nrouter1,10.0.0.1,admin,22,cisco\n""",
        encoding="utf-8",
    )
    monkeypatch.setattr(app, "HOSTS_CSV", str(hosts_csv))

    with app.app.test_client() as client:
        response = client.get("/api/export/nonexistent")

    assert response.status_code == 404
    assert response.json is not None
    assert response.json["error"] == "Hostname not found in hosts configuration"


def test_export_json_returns_valid_structure(tmp_path: Path, monkeypatch) -> None:
    """Return valid JSON structure with hostname, IP, model, and commands."""
    hosts_csv = tmp_path / "hosts.csv"
    hosts_csv.write_text(
        """host,ip,username,port,model\nrouter1,10.0.0.1,admin,22,cisco\n""",
        encoding="utf-8",
    )
    monkeypatch.setattr(app, "HOSTS_CSV", str(hosts_csv))
    monkeypatch.setattr(app, "ORIGIN_DIR", str(tmp_path / "origin"))
    monkeypatch.setattr(app, "DEST_DIR", str(tmp_path / "dest"))

    with app.app.test_client() as client:
        response = client.get("/api/export/router1")

    assert response.status_code == 200
    data = response.json
    assert data is not None
    assert data["hostname"] == "router1"
    assert data["ip"] == "10.0.0.1"
    assert data["model"] == "cisco"
    assert "commands" in data
    assert isinstance(data["commands"], list)


def test_export_json_includes_command_data(tmp_path: Path, monkeypatch) -> None:
    """Return command data with timestamps and diff status."""
    hosts_csv = tmp_path / "hosts.csv"
    hosts_csv.write_text(
        """host,ip,username,port,model\nrouter1,10.0.0.1,admin,22,cisco\n""",
        encoding="utf-8",
    )
    monkeypatch.setattr(app, "HOSTS_CSV", str(hosts_csv))

    origin_dir = tmp_path / "origin"
    dest_dir = tmp_path / "dest"
    origin_dir.mkdir()
    dest_dir.mkdir()
    monkeypatch.setattr(app, "ORIGIN_DIR", str(origin_dir))
    monkeypatch.setattr(app, "DEST_DIR", str(dest_dir))

    # Create test files for one command
    origin_file = origin_dir / "router1-show_version.txt"
    dest_file = dest_dir / "router1-show_version.txt"
    origin_file.write_text("Version 1.0", encoding="utf-8")
    dest_file.write_text("Version 1.0", encoding="utf-8")

    with app.app.test_client() as client:
        response = client.get("/api/export/router1")

    assert response.status_code == 200
    data = response.json
    assert data is not None
    assert len(data["commands"]) > 0

    # Check first command structure
    cmd = data["commands"][0]
    assert "command" in cmd
    assert "origin" in cmd
    assert "dest" in cmd
    assert "diff_status" in cmd
    assert "timestamp" in cmd["origin"]
    assert "exists" in cmd["origin"]
    assert "timestamp" in cmd["dest"]
    assert "exists" in cmd["dest"]


def test_export_json_detects_identical_files(tmp_path: Path, monkeypatch) -> None:
    """Return identical diff status when origin and dest files match."""
    hosts_csv = tmp_path / "hosts.csv"
    hosts_csv.write_text(
        """host,ip,username,port,model\nrouter1,10.0.0.1,admin,22,cisco\n""",
        encoding="utf-8",
    )
    monkeypatch.setattr(app, "HOSTS_CSV", str(hosts_csv))

    origin_dir = tmp_path / "origin"
    dest_dir = tmp_path / "dest"
    origin_dir.mkdir()
    dest_dir.mkdir()
    monkeypatch.setattr(app, "ORIGIN_DIR", str(origin_dir))
    monkeypatch.setattr(app, "DEST_DIR", str(dest_dir))

    # Create identical test files
    origin_file = origin_dir / "router1-show_version.txt"
    dest_file = dest_dir / "router1-show_version.txt"
    origin_file.write_text("Same content", encoding="utf-8")
    dest_file.write_text("Same content", encoding="utf-8")

    with app.app.test_client() as client:
        response = client.get("/api/export/router1")

    assert response.status_code == 200
    data = response.json
    assert data is not None
    cmd = data["commands"][0]
    assert cmd["diff_status"] == "identical"


def test_export_json_detects_changes(tmp_path: Path, monkeypatch) -> None:
    """Return changes detected status when origin and dest files differ."""
    hosts_csv = tmp_path / "hosts.csv"
    hosts_csv.write_text(
        """host,ip,username,port,model\nrouter1,10.0.0.1,admin,22,cisco\n""",
        encoding="utf-8",
    )
    monkeypatch.setattr(app, "HOSTS_CSV", str(hosts_csv))

    origin_dir = tmp_path / "origin"
    dest_dir = tmp_path / "dest"
    origin_dir.mkdir()
    dest_dir.mkdir()
    monkeypatch.setattr(app, "ORIGIN_DIR", str(origin_dir))
    monkeypatch.setattr(app, "DEST_DIR", str(dest_dir))

    # Create different test files
    origin_file = origin_dir / "router1-show_version.txt"
    dest_file = dest_dir / "router1-show_version.txt"
    origin_file.write_text("Version 1.0", encoding="utf-8")
    dest_file.write_text("Version 2.0", encoding="utf-8")

    with app.app.test_client() as client:
        response = client.get("/api/export/router1")

    assert response.status_code == 200
    data = response.json
    assert data is not None
    cmd = data["commands"][0]
    assert cmd["diff_status"] == "changes detected"


def test_logging_configuration_creates_log_file() -> None:
    """Test that logging is properly configured and creates log files."""
    # Import logger from app to verify it exists
    assert app.logger is not None
    assert app.logger.name == "nw-diff"
    assert app.logger.level == app.logging.DEBUG


def test_logs_view_endpoint(tmp_path: Path, monkeypatch) -> None:
    """Test the /logs web UI endpoint."""
    # Create a test log file
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    log_file = logs_dir / "nw-diff.log"
    log_file.write_text(
        "2025-01-16 12:00:00 - nw-diff - INFO - Test log line 1\n"
        "2025-01-16 12:00:01 - nw-diff - ERROR - Test error line\n",
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
    log_file = logs_dir / "nw-diff.log"
    log_file.write_text(
        "2025-01-16 12:00:00 - nw-diff - INFO - Test info log\n"
        "2025-01-16 12:00:01 - nw-diff - ERROR - Test error log\n"
        "2025-01-16 12:00:02 - nw-diff - DEBUG - Test debug log\n",
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


def test_debug_mode_disabled_by_default(monkeypatch) -> None:
    """Test that Flask debug mode is disabled by default."""
    # Ensure APP_DEBUG is not set
    monkeypatch.delenv("APP_DEBUG", raising=False)

    # The debug mode should be False when APP_DEBUG is not set
    debug_mode = os.environ.get("APP_DEBUG", "false").lower() in {"true", "1", "yes"}
    assert debug_mode is False


def test_debug_mode_enabled_with_env_var(monkeypatch) -> None:
    """Test that Flask debug mode can be enabled via APP_DEBUG environment variable."""
    # Test with "true"
    monkeypatch.setenv("APP_DEBUG", "true")
    debug_mode = os.environ.get("APP_DEBUG", "false").lower() in {"true", "1", "yes"}
    assert debug_mode is True

    # Test with "1"
    monkeypatch.setenv("APP_DEBUG", "1")
    debug_mode = os.environ.get("APP_DEBUG", "false").lower() in {"true", "1", "yes"}
    assert debug_mode is True

    # Test with "yes"
    monkeypatch.setenv("APP_DEBUG", "yes")
    debug_mode = os.environ.get("APP_DEBUG", "false").lower() in {"true", "1", "yes"}
    assert debug_mode is True

    # Test with "false"
    monkeypatch.setenv("APP_DEBUG", "false")
    debug_mode = os.environ.get("APP_DEBUG", "false").lower() in {"true", "1", "yes"}
    assert debug_mode is False


# --- Security tests for path traversal protection ---


def test_validate_hostname_rejects_parent_directory() -> None:
    """Test that hostname validation rejects parent directory references."""
    assert app.validate_hostname("..") is False
    assert app.validate_hostname("../etc") is False
    assert app.validate_hostname("test/../etc") is False


def test_validate_hostname_rejects_path_separators() -> None:
    """Test that hostname validation rejects path separators."""
    assert app.validate_hostname("/etc/passwd") is False
    assert app.validate_hostname("test/file") is False
    assert app.validate_hostname("test\\file") is False
    assert app.validate_hostname("\\windows\\system32") is False


def test_validate_hostname_rejects_invalid_characters() -> None:
    """Test that hostname validation rejects special characters."""
    assert app.validate_hostname("test;rm -rf") is False
    assert app.validate_hostname("test|cat") is False
    assert app.validate_hostname("test&ls") is False
    assert app.validate_hostname("test$var") is False
    assert app.validate_hostname("test`whoami`") is False


def test_validate_hostname_accepts_valid_names() -> None:
    """Test that hostname validation accepts valid hostnames."""
    assert app.validate_hostname("router1") is True
    assert app.validate_hostname("switch-01") is True
    assert app.validate_hostname("fw_main") is True
    assert app.validate_hostname("host.example.com") is True
    assert app.validate_hostname("router-123_backup") is True


def test_validate_hostname_rejects_empty() -> None:
    """Test that hostname validation rejects empty strings."""
    assert app.validate_hostname("") is False
    assert app.validate_hostname(None) is False


def test_validate_command_rejects_parent_directory() -> None:
    """Test that command validation rejects parent directory references."""
    assert app.validate_command("..") is False
    assert app.validate_command("../etc/passwd") is False
    assert app.validate_command("show ../../../etc/passwd") is False


def test_validate_command_rejects_path_separators() -> None:
    """Test that command validation rejects path separators."""
    assert app.validate_command("/etc/passwd") is False
    assert app.validate_command("show /etc/passwd") is False
    assert app.validate_command("show\\file") is False


def test_validate_command_rejects_invalid_characters() -> None:
    """Test that command validation rejects special characters."""
    assert app.validate_command("show version; rm -rf") is False
    assert app.validate_command("show|cat") is False
    assert app.validate_command("show&ls") is False


def test_validate_command_accepts_valid_commands() -> None:
    """Test that command validation accepts valid commands."""
    assert app.validate_command("show version") is True
    assert app.validate_command("show running-config") is True
    assert app.validate_command("get system status") is True
    assert app.validate_command("diag_switch_ports") is True


def test_validate_command_rejects_empty() -> None:
    """Test that command validation rejects empty strings."""
    assert app.validate_command("") is False
    assert app.validate_command(None) is False


def test_validate_base_directory_accepts_valid() -> None:
    """Test that base directory validation accepts only origin and dest."""
    assert app.validate_base_directory("origin") is True
    assert app.validate_base_directory("dest") is True


def test_validate_base_directory_rejects_invalid() -> None:
    """Test that base directory validation rejects other values."""
    assert app.validate_base_directory("backup") is False
    assert app.validate_base_directory("../origin") is False
    assert app.validate_base_directory("/tmp") is False
    assert app.validate_base_directory("") is False


def test_get_file_path_rejects_traversal_in_hostname() -> None:
    """Test that get_file_path rejects path traversal in hostname."""
    with pytest.raises(ValueError, match="Invalid hostname"):
        app.get_file_path("../etc", "show version", "origin")
    with pytest.raises(ValueError, match="Invalid hostname"):
        app.get_file_path("../../etc/passwd", "show version", "origin")


def test_get_file_path_rejects_traversal_in_command() -> None:
    """Test that get_file_path rejects path traversal in command."""
    with pytest.raises(ValueError, match="Invalid command"):
        app.get_file_path("router1", "../etc/passwd", "origin")
    with pytest.raises(ValueError, match="Invalid command"):
        app.get_file_path("router1", "show ../../etc/passwd", "origin")


def test_get_file_path_rejects_invalid_base() -> None:
    """Test that get_file_path rejects invalid base directory."""
    with pytest.raises(ValueError, match="Invalid base"):
        app.get_file_path("router1", "show version", "backup")
    with pytest.raises(ValueError, match="Invalid base"):
        app.get_file_path("router1", "show version", "../origin")


def test_get_file_path_returns_normalized_path() -> None:
    """Test that get_file_path returns properly normalized paths."""
    path = app.get_file_path("router1", "show version", "origin")
    assert ".." not in path
    assert path.startswith("origin")
    assert "router1-show_version.txt" in path


def test_get_diff_file_path_rejects_traversal() -> None:
    """Test that get_diff_file_path rejects path traversal attempts."""
    with pytest.raises(ValueError, match="Invalid hostname"):
        app.get_diff_file_path("../etc", "show version")
    with pytest.raises(ValueError, match="Invalid command"):
        app.get_diff_file_path("router1", "../etc/passwd")


def test_compare_files_rejects_invalid_hostname(tmp_path: Path, monkeypatch) -> None:
    """Test that /compare_files endpoint rejects invalid hostnames."""
    hosts_csv = tmp_path / "hosts.csv"
    hosts_csv.write_text(
        """host,ip,username,port,model\nrouter1,10.0.0.1,admin,22,cisco\n""",
        encoding="utf-8",
    )
    monkeypatch.setattr(app, "HOSTS_CSV", str(hosts_csv))

    with app.app.test_client() as client:
        response = client.post(
            "/compare_files",
            data={
                "host1": "../etc",
                "host2": "router1",
                "base": "origin",
                "command": "show version",
                "view": "inline",
            },
        )
        assert response.status_code == 200
        assert b"Invalid hostname" in response.data


def test_compare_files_rejects_invalid_command(tmp_path: Path, monkeypatch) -> None:
    """Test that /compare_files endpoint rejects invalid commands."""
    hosts_csv = tmp_path / "hosts.csv"
    hosts_csv.write_text(
        """host,ip,username,port,model\nrouter1,10.0.0.1,admin,22,cisco\n""",
        encoding="utf-8",
    )
    monkeypatch.setattr(app, "HOSTS_CSV", str(hosts_csv))

    with app.app.test_client() as client:
        response = client.post(
            "/compare_files",
            data={
                "host1": "router1",
                "host2": "router1",
                "base": "origin",
                "command": "../etc/passwd",
                "view": "inline",
            },
        )
        assert response.status_code == 200
        assert b"Invalid command" in response.data


def test_compare_files_rejects_invalid_base(tmp_path: Path, monkeypatch) -> None:
    """Test that /compare_files endpoint rejects invalid base directory."""
    hosts_csv = tmp_path / "hosts.csv"
    hosts_csv.write_text(
        """host,ip,username,port,model\nrouter1,10.0.0.1,admin,22,cisco\n""",
        encoding="utf-8",
    )
    monkeypatch.setattr(app, "HOSTS_CSV", str(hosts_csv))

    with app.app.test_client() as client:
        response = client.post(
            "/compare_files",
            data={
                "host1": "router1",
                "host2": "router1",
                "base": "../backup",
                "command": "show version",
                "view": "inline",
            },
        )
        assert response.status_code == 200
        assert b"Invalid base" in response.data


def test_capture_endpoint_rejects_invalid_hostname(tmp_path: Path, monkeypatch) -> None:
    """Test that /capture endpoint rejects invalid hostnames."""
    hosts_csv = tmp_path / "hosts.csv"
    hosts_csv.write_text(
        """host,ip,username,port,model\nrouter1,10.0.0.1,admin,22,cisco\n""",
        encoding="utf-8",
    )
    monkeypatch.setattr(app, "HOSTS_CSV", str(hosts_csv))

    with app.app.test_client() as client:
        # Test with hostname containing semicolon (invalid character)
        response = client.get("/capture/origin/test;rm")
        assert response.status_code == 400
        assert b"Invalid hostname" in response.data


def test_capture_endpoint_rejects_invalid_base(tmp_path: Path, monkeypatch) -> None:
    """Test that /capture endpoint rejects invalid base directory."""
    hosts_csv = tmp_path / "hosts.csv"
    hosts_csv.write_text(
        """host,ip,username,port,model\nrouter1,10.0.0.1,admin,22,cisco\n""",
        encoding="utf-8",
    )
    monkeypatch.setattr(app, "HOSTS_CSV", str(hosts_csv))

    with app.app.test_client() as client:
        # Test with invalid base directory name
        response = client.get("/capture/backup/router1")
        assert response.status_code == 400
        assert b"Invalid capture type" in response.data


def test_host_detail_rejects_invalid_hostname(tmp_path: Path, monkeypatch) -> None:
    """Test that /host/<hostname> endpoint rejects invalid hostnames."""
    hosts_csv = tmp_path / "hosts.csv"
    hosts_csv.write_text(
        """host,ip,username,port,model\nrouter1,10.0.0.1,admin,22,cisco\n""",
        encoding="utf-8",
    )
    monkeypatch.setattr(app, "HOSTS_CSV", str(hosts_csv))

    with app.app.test_client() as client:
        # Test with hostname containing invalid character
        response = client.get("/host/test;command")
        assert response.status_code == 400
        assert b"Invalid hostname" in response.data


def test_export_diff_rejects_invalid_hostname(tmp_path: Path, monkeypatch) -> None:
    """Test that /export/<hostname> endpoint rejects invalid hostnames."""
    hosts_csv = tmp_path / "hosts.csv"
    hosts_csv.write_text(
        """host,ip,username,port,model\nrouter1,10.0.0.1,admin,22,cisco\n""",
        encoding="utf-8",
    )
    monkeypatch.setattr(app, "HOSTS_CSV", str(hosts_csv))

    with app.app.test_client() as client:
        # Test with hostname containing invalid character
        response = client.get("/export/test$var")
        assert response.status_code == 400
        assert b"Invalid hostname" in response.data


def test_export_json_rejects_invalid_hostname(tmp_path: Path, monkeypatch) -> None:
    """Test that /api/export/<hostname> endpoint rejects invalid hostnames."""
    hosts_csv = tmp_path / "hosts.csv"
    hosts_csv.write_text(
        """host,ip,username,port,model\nrouter1,10.0.0.1,admin,22,cisco\n""",
        encoding="utf-8",
    )
    monkeypatch.setattr(app, "HOSTS_CSV", str(hosts_csv))

    with app.app.test_client() as client:
        # Test with hostname containing invalid character
        response = client.get("/api/export/test|cat")
        assert response.status_code == 400
        json_data = response.get_json()
        assert json_data is not None
        assert "Invalid hostname" in json_data["error"]


# --- XSS Prevention Tests ---


def test_generate_side_by_side_html_escapes_script_tags() -> None:
    """Test that script tags in diff content are escaped in side-by-side view."""
    malicious_origin = "Safe content\n"
    malicious_dest = "Safe content\n<script>alert(1)</script>\n"

    html_output = app.generate_side_by_side_html(malicious_origin, malicious_dest)

    # Script tags should be escaped
    assert "&lt;script&gt;" in html_output
    assert "&lt;/script&gt;" in html_output
    # Raw script tags should NOT be present
    assert "<script>alert" not in html_output


def test_generate_side_by_side_html_escapes_html_entities() -> None:
    """Test that HTML entities are properly escaped in side-by-side view."""
    origin = "Normal text"
    dest = '<img src=x onerror="alert(1)">'

    html_output = app.generate_side_by_side_html(origin, dest)

    # HTML should be escaped
    assert "&lt;img" in html_output
    assert "&quot;" in html_output or "&#x27;" in html_output
    # Raw HTML should NOT be present
    assert "<img src=x onerror=" not in html_output


def test_generate_side_by_side_html_escapes_common_text() -> None:
    """Test that common text is also escaped in side-by-side view."""
    malicious = "<script>alert('XSS')</script>"

    html_output = app.generate_side_by_side_html(malicious, malicious)

    # Even identical text should be escaped
    assert "&lt;script&gt;" in html_output
    assert "&lt;/script&gt;" in html_output
    assert "<script>alert" not in html_output


def test_compute_diff_inline_escapes_script_tags() -> None:
    """Test that script tags are escaped in inline diff view."""
    origin = "Safe content"
    dest = "Safe content\n<script>alert(1)</script>"

    status, diff_html = app.compute_diff(origin, dest, view="inline")

    assert status == "changes detected"
    # Script tags should be escaped
    assert "&lt;script&gt;" in diff_html
    assert "&lt;/script&gt;" in diff_html
    # Raw script tags should NOT be present
    assert "<script>alert" not in diff_html


def test_compute_diff_identical_escapes_html() -> None:
    """Test that identical content with HTML is escaped in inline view."""
    content = "<script>alert('XSS')</script>\n<img src=x>"

    status, diff_html = app.compute_diff(content, content, view="inline")

    assert status == "identical"
    # HTML should be escaped in the <pre> tag
    assert "&lt;script&gt;" in diff_html
    assert "&lt;img" in diff_html
    # Raw HTML should NOT be present
    assert "<script>alert" not in diff_html
    assert "<img src=x>" not in diff_html


def test_compute_diff_sidebyside_escapes_html() -> None:
    """Test that HTML is escaped in side-by-side view via compute_diff."""
    origin = "Normal\n<script>bad()</script>"
    dest = "Normal\n<script>bad()</script>"

    status, diff_html = app.compute_diff(origin, dest, view="sidebyside")

    assert status == "identical"
    # HTML should be escaped
    assert "&lt;script&gt;" in diff_html
    assert "<script>bad()" not in diff_html


def test_host_detail_response_escapes_xss(tmp_path: Path, monkeypatch) -> None:
    """Test that XSS payloads in host detail page response are escaped."""
    hosts_csv = tmp_path / "hosts.csv"
    hosts_csv.write_text(
        """host,ip,username,port,model\nrouter1,10.0.0.1,admin,22,cisco\n""",
        encoding="utf-8",
    )
    monkeypatch.setattr(app, "HOSTS_CSV", str(hosts_csv))

    origin_dir = tmp_path / "origin"
    dest_dir = tmp_path / "dest"
    diff_dir = tmp_path / "diff"
    origin_dir.mkdir()
    dest_dir.mkdir()
    diff_dir.mkdir()
    monkeypatch.setattr(app, "ORIGIN_DIR", str(origin_dir))
    monkeypatch.setattr(app, "DEST_DIR", str(dest_dir))
    monkeypatch.setattr(app, "DIFF_DIR", str(diff_dir))

    # Create files with XSS payload
    origin_file = origin_dir / "router1-show_version.txt"
    dest_file = dest_dir / "router1-show_version.txt"
    xss_payload = "Version 1.0\n<script>alert('XSS')</script>"
    origin_file.write_text(xss_payload, encoding="utf-8")
    dest_file.write_text(xss_payload, encoding="utf-8")

    with app.app.test_client() as client:
        response = client.get("/host/router1")
        assert response.status_code == 200
        html_content = response.data.decode("utf-8")

        # Script tags should be escaped in the response
        assert "&lt;script&gt;" in html_content
        # Raw script should NOT be in response
        assert "<script>alert('XSS')</script>" not in html_content


def test_compare_files_response_escapes_xss(tmp_path: Path, monkeypatch) -> None:
    """Test that XSS payloads in compare files response are escaped."""
    hosts_csv = tmp_path / "hosts.csv"
    csv_content = (
        "host,ip,username,port,model\n"
        "router1,10.0.0.1,admin,22,cisco\n"
        "router2,10.0.0.2,admin,22,cisco\n"
    )
    hosts_csv.write_text(csv_content, encoding="utf-8")
    monkeypatch.setattr(app, "HOSTS_CSV", str(hosts_csv))

    origin_dir = tmp_path / "origin"
    origin_dir.mkdir()
    monkeypatch.setattr(app, "ORIGIN_DIR", str(origin_dir))
    monkeypatch.setattr(app, "DEST_DIR", str(tmp_path / "dest"))

    # Create files with XSS payload
    file1 = origin_dir / "router1-show_version.txt"
    file2 = origin_dir / "router2-show_version.txt"
    xss_payload1 = "Config line\n<img src=x onerror='alert(1)'>"
    xss_payload2 = "Config line\n<img src=x onerror='alert(2)'>"
    file1.write_text(xss_payload1, encoding="utf-8")
    file2.write_text(xss_payload2, encoding="utf-8")

    with app.app.test_client() as client:
        response = client.post(
            "/compare_files",
            data={
                "host1": "router1",
                "host2": "router2",
                "base": "origin",
                "command": "show version",
                "view": "sidebyside",
            },
        )
        assert response.status_code == 200
        html_content = response.data.decode("utf-8")

        # HTML should be escaped
        assert "&lt;img" in html_content
        # Raw HTML should NOT be in response
        assert "<img src=x onerror=" not in html_content
        assert "alert(1)" not in html_content or "&quot;alert(1)&quot;" in html_content
