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
