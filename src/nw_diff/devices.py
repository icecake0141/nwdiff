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

import csv
import logging
import os

# Read HOSTS_CSV path from environment variable at module load time.
# This is intentional - the path is expected to be configured once at application
# startup and not changed during runtime. For testing with different paths,
# use monkeypatch to set the HOSTS_CSV attribute directly or reload the module.
HOSTS_CSV = os.environ.get("HOSTS_CSV", "hosts.csv")

logger = logging.getLogger("nw-diff")

# Device model specific command lists
DEVICE_COMMANDS = {
    "fortinet": (
        "get system status",
        "diag switch physical-ports summary",
        "diag switch trunk summary",
        "diag switch trunk list",
        "diag stp vlan list",
    ),
    "cisco": (
        "show version",
        "show running-config",
    ),
    "junos": (
        "show chassis hardware",
        "show route",
    ),
}
# Default commands if model does not match
DEFAULT_COMMANDS = ("show version",)


def read_hosts_csv():
    """
    Reads the CSV file while ignoring lines that start with '#' (comments).
    Returns a list of dictionaries (CSV rows).
    """
    try:
        logger.info("Reading hosts CSV from: %s", HOSTS_CSV)
        with open(HOSTS_CSV, newline="", encoding="utf-8") as csvfile:
            filtered = (line for line in csvfile if not line.lstrip().startswith("#"))
            reader = csv.DictReader(filtered)
            rows = list(reader)
            logger.debug("Successfully read %d host(s) from CSV", len(rows))
            return rows
    except FileNotFoundError:
        logger.error("Hosts CSV file not found: %s", HOSTS_CSV)
        return []
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.error("Error reading hosts CSV file: %s", exc)
        return []


def get_device_info(host):
    """
    Retrieves the device info dictionary from CSV for the given host.
    Returns None if the host is not found.
    """
    rows = read_hosts_csv()
    for row in rows:
        if row["host"] == host:
            logger.debug("Found device info for host: %s", host)
            return row
    logger.warning("Device info not found for host: %s", host)
    return None


def get_commands_for_host(host):
    """
    Retrieves the device's model from CSV and returns the corresponding command tuple.
    If not found, returns DEFAULT_COMMANDS.
    """
    rows = read_hosts_csv()
    for row in rows:
        if row["host"] == host:
            model = row.get("model", "").lower()
            return DEVICE_COMMANDS.get(model, DEFAULT_COMMANDS)
    return DEFAULT_COMMANDS
