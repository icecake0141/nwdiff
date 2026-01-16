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
    hosts_csv.write_text(
        """# comment line\nhost,ip,username,port,model\nrouter1,10.0.0.1,admin,22,cisco\nrouter2,10.0.0.2,admin,22,fortinet\n""",
        encoding="utf-8",
    )
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
