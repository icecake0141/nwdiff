#!/usr/bin/env python3
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
import datetime
import logging
import logging.handlers
import os
import re

from flask import (
    Flask,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
)
from diff_match_patch import diff_match_patch
from netmiko import ConnectHandler

app = Flask(__name__)

# Configure logging
LOGS_DIR = "logs"
os.makedirs(LOGS_DIR, exist_ok=True)

# Create logger
logger = logging.getLogger("nw-diff")
logger.setLevel(logging.DEBUG)

# Create rotating file handler (10MB max, keep 5 backup files)
log_file = os.path.join(LOGS_DIR, "nw-diff.log")
file_handler = logging.handlers.RotatingFileHandler(
    log_file, maxBytes=10 * 1024 * 1024, backupCount=5
)
file_handler.setLevel(logging.DEBUG)

# Create console handler for development
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

# Create formatter using lazy % formatting
formatter = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# Add handlers to logger
logger.addHandler(file_handler)
logger.addHandler(console_handler)

logger.info("NW-Diff application starting")

# Directories and CSV file settings
ORIGIN_DIR = "origin"
DEST_DIR = "dest"  # Changed from "dear" to "dest"
DIFF_DIR = "diff"  # Directory to store diff HTML files
BACKUP_DIR = "backup"  # Directory to store backup files
HOSTS_CSV = "hosts.csv"

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

# Create required directories if they do not exist
os.makedirs(ORIGIN_DIR, exist_ok=True)
os.makedirs(DEST_DIR, exist_ok=True)
os.makedirs(DIFF_DIR, exist_ok=True)
os.makedirs(BACKUP_DIR, exist_ok=True)


# --- Backup helper functions ---
def get_backup_filename(filepath):
    """
    Generates a backup filename with timestamp.
    Format: YYYYMMDD_HHMMSS_hostname-command.txt
    """
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.basename(filepath)
    return os.path.join(BACKUP_DIR, f"{timestamp}_{filename}")


def rotate_backups(filepath):
    """
    Keeps only the last 10 backups for a given file.
    Deletes older backups beyond the 10 most recent.
    """
    if not os.path.exists(BACKUP_DIR):
        return

    filename = os.path.basename(filepath)
    # Find all backups for this file
    backup_files = []
    for backup_file in os.listdir(BACKUP_DIR):
        if backup_file.endswith(f"_{filename}"):
            backup_path = os.path.join(BACKUP_DIR, backup_file)
            backup_files.append((backup_path, os.path.getmtime(backup_path)))

    # Sort by modification time (newest first)
    backup_files.sort(key=lambda x: x[1], reverse=True)

    # Keep only the 10 most recent, delete the rest
    for backup_path, _ in backup_files[10:]:
        try:
            os.remove(backup_path)
        except OSError:
            pass


def create_backup(filepath):
    """
    Creates a backup of the file before it is overwritten.
    Only creates backup if the file exists.
    After backup creation, rotates backups to keep only the last 10.
    """
    if os.path.exists(filepath):
        backup_path = get_backup_filename(filepath)
        try:
            with open(filepath, "r", encoding="utf-8") as src:
                content = src.read()
            with open(backup_path, "w", encoding="utf-8") as dst:
                dst.write(content)
            rotate_backups(filepath)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            print(f"Warning: Failed to create backup for {filepath}: {exc}")


# --- Helper function to read CSV and skip comment lines ---
def read_hosts_csv():
    """
    Reads the CSV file while ignoring lines that start with '#' (comments).
    Returns a list of dictionaries (CSV rows).
    """
    try:
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


# --- Helper function to get device info from CSV ---
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


# --- Helper function to get command list based on device model ---
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


# --- Helper function to get file modification time ---
def get_file_mtime(filepath):
    """
    Returns the modification time of the file in a formatted string,
    or 'file not found' if the file does not exist.
    """
    if os.path.exists(filepath):
        return datetime.datetime.fromtimestamp(os.path.getmtime(filepath)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    return "file not found"


# --- Helper functions for file paths ---
def get_file_path(host, command, base):
    """
    base: "origin" or "dest"
    Constructs the filename using the host and command
    (spaces replaced with underscores).
    """
    safe_command = command.replace(" ", "_")
    filename = f"{host}-{safe_command}.txt"
    if base == "origin":
        return os.path.join(ORIGIN_DIR, filename)
    if base == "dest":
        return os.path.join(DEST_DIR, filename)
    raise ValueError("Invalid base")


def get_diff_file_path(host, command):
    """
    Constructs the path for the diff file.
    """
    safe_command = command.replace(" ", "_")
    filename = f"{host}-{safe_command}-diff.html"
    return os.path.join(DIFF_DIR, filename)


# --- Helper function to compute diff status only ---
def compute_diff_status(origin_data, dest_data):
    """
    Uses diff_match_patch to compute the diff between origin and dest data,
    and returns "identical" if there are no differences, otherwise "changes detected".
    """
    dmp = diff_match_patch()
    diffs = dmp.diff_main(origin_data, dest_data)
    dmp.diff_cleanupSemantic(diffs)
    if len(diffs) == 1 and diffs[0][0] == 0:
        return "identical"
    return "changes detected"


# --- Helper function to compute diff HTML and status ---
def compute_diff(origin_data, dest_data, view="inline"):
    """
    Computes diff information using diff_match_patch.
    For inline view:
      - If a line contains any diff tags, the entire line is
        highlighted with a yellow background.
      - Additionally, text within <del> tags gets a red background
        and text within <ins> tags gets a blue background.
    """
    dmp = diff_match_patch()
    diffs = dmp.diff_main(origin_data, dest_data)
    dmp.diff_cleanupSemantic(diffs)

    if all(op == 0 for op, text in diffs):
        status = "identical"
        if view == "sidebyside":
            diff_html = generate_side_by_side_html(origin_data, dest_data)
        else:
            diff_html = f"<pre>{origin_data}</pre>"
    else:
        status = "changes detected"
        if view == "sidebyside":
            diff_html = generate_side_by_side_html(origin_data, dest_data)
        else:
            raw_diff_html = dmp.diff_prettyHtml(diffs)
            # Replace ¶ and &para; with line breaks
            inline_html = raw_diff_html.replace("¶", "<br>").replace("&para;", "")

            # Update at character level: add inline background color for diff tags
            inline_html = inline_html.replace(
                "<del>", '<del style="background-color: #ffcccc;">'
            )
            inline_html = inline_html.replace(
                "<ins>", '<ins style="background-color: #cce5ff;">'
            )

            # Highlight entire lines that contain diff tags with a yellow background
            lines = inline_html.split("<br>")
            new_lines = []
            for line in lines:
                if "<del" in line or "<ins" in line:
                    new_lines.append(
                        f'<div style="background-color: #ffff99;">{line}</div>'
                    )
                else:
                    new_lines.append(line)
            diff_html = "<br>".join(new_lines)
    return status, diff_html


# --- Function to generate side-by-side diff HTML ---
def generate_side_by_side_html(origin_data, dest_data):
    """
    Generates side-by-side HTML displaying the origin content
    (common parts plus deletions) on the left and the destination
    content (common parts plus insertions) on the right.
    For each column:
      - At the character level, text in <del> tags is highlighted
        with a red background and text in <ins> tags with a blue
        background.
      - At the line level, any line containing diff tags is wrapped
        with a yellow background.
    """
    dmp = diff_match_patch()
    diffs = dmp.diff_main(origin_data, dest_data)
    dmp.diff_cleanupSemantic(diffs)

    origin_parts = []
    dest_parts = []
    for op, text in diffs:
        if op == 0:
            origin_parts.append(text)
            dest_parts.append(text)
        elif op == -1:
            # Highlight deleted text with a red background
            origin_parts.append(f"<del style='background-color: #ffcccc;'>{text}</del>")
        elif op == 1:
            # Highlight added text with a blue background
            dest_parts.append(f"<ins style='background-color: #cce5ff;'>{text}</ins>")
    origin_html = "".join(origin_parts)
    dest_html = "".join(dest_parts)

    # Replace newlines with <br> to preserve formatting
    origin_html = origin_html.replace("\n", "<br>")
    dest_html = dest_html.replace("\n", "<br>")

    # Origin side: wrap lines containing diff tags with a yellow background
    new_origin_lines = []
    for line in origin_html.split("<br>"):
        if "<del" in line or "<ins" in line:
            new_origin_lines.append(
                f"<div style='background-color: #ffff99;'>{line}</div>"
            )
        else:
            new_origin_lines.append(line)
    origin_html = "<br>".join(new_origin_lines)

    # Destination side: wrap lines containing diff tags with a yellow background
    new_dest_lines = []
    for line in dest_html.split("<br>"):
        if "<del" in line or "<ins" in line:
            new_dest_lines.append(
                f"<div style='background-color: #ffff99;'>{line}</div>"
            )
        else:
            new_dest_lines.append(line)
    dest_html = "<br>".join(new_dest_lines)

    html = (
        '<table class="table table-bordered" '
        'style="width:100%; border-collapse: collapse;">\n'
        "  <tr>\n"
        f'    <td style="vertical-align: top; width:50%; '
        f'white-space: pre-wrap;">{origin_html}</td>\n'
        f'    <td style="vertical-align: top; width:50%; '
        f'white-space: pre-wrap;">{dest_html}</td>\n'
        "  </tr>\n"
        "</table>"
    )
    # Build the side-by-side table HTML
    table_class = "table table-bordered"
    table_style = "width:100%; border-collapse: collapse;"
    td_style = "vertical-align: top; width:50%; white-space: pre-wrap;"
    html = f"""<table class="{table_class}" style="{table_style}">
  <tr>
    <td style="{td_style}">{origin_html}</td>
    <td style="{td_style}">{dest_html}</td>
  </tr>
</table>"""
    return html


# --- Capture endpoint for individual host ---
@app.route("/capture/<base>/<hostname>")
def capture(base, hostname):
    """
    Triggered when clicking the "Capture Origin" or "Capture Dest"
    button on the host list page.
    Establishes a single connection to the target device and retrieves
    output for each command (based on the device's model) before
    disconnecting. CSV reading ignores comment lines.
    """
    logger.info("Capture request received for host=%s, base=%s", hostname, base)

    if base not in ["origin", "dest"]:
        logger.error("Invalid capture type requested: %s", base)
        return "Invalid capture type", 400

    commands = get_commands_for_host(hostname)
    device_info = get_device_info(hostname)
    if not device_info:
        logger.error("Could not find device info in CSV for host: %s", hostname)
        return "Could not find device info in CSV for host: " + hostname

    device = {
        "device_type": device_info["model"],
        "host": device_info["ip"],
        "username": device_info["username"],
        "port": device_info["port"],
        "password": os.environ.get("DEVICE_PASSWORD", "your_password"),
    }

    logger.info(
        "Connecting to device: %s (IP: %s, Type: %s)",
        hostname,
        device_info["ip"],
        device_info["model"],
    )

    try:
        connection = ConnectHandler(**device)
        logger.debug("Connection established to %s", hostname)
        connection.enable()

        # Execute all commands in a single session
        for command in commands:
            logger.debug("Executing command on %s: %s", hostname, command)
            output = connection.send_command(command)
            filepath = get_file_path(hostname, command, base)
            create_backup(filepath)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(output)
            logger.debug("Saved output for %s to: %s", command, filepath)

        connection.disconnect()
        logger.info(
            "Successfully captured data for %s (%d commands)", hostname, len(commands)
        )
        return redirect(url_for("host_list"))
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.error("Failed to capture data from %s: %s", hostname, exc, exc_info=True)
        return f"Failed to capture data: {exc}", 500


# --- New endpoint: Capture for all devices ---
@app.route("/capture_all/<base>")
def capture_all(base):
    """
    Captures data for all devices registered in hosts.csv.
    Establishes a connection for each device and retrieves the output for each command.
    CSV reading ignores comment lines.
    """
    logger.info("Capture all request received for base=%s", base)

    if base not in ["origin", "dest"]:
        logger.error("Invalid capture type requested: %s", base)
        return "Invalid capture type", 400

    rows = read_hosts_csv()
    total_hosts = len(rows)
    success_count = 0
    failure_count = 0

    logger.info("Starting capture for %d device(s)", total_hosts)

    for row in rows:
        hostname = row["host"]
        commands = get_commands_for_host(hostname)
        device_info = get_device_info(hostname)
        if not device_info:
            logger.warning("Skipping host %s - device info not found", hostname)
            failure_count += 1
            continue

        device = {
            "device_type": device_info["model"],
            "host": device_info["ip"],
            "username": device_info["username"],
            "port": device_info["port"],
            "password": os.environ.get("DEVICE_PASSWORD", "your_password"),
        }

        logger.info(
            "Connecting to device: %s (IP: %s, Type: %s)",
            hostname,
            device_info["ip"],
            device_info["model"],
        )

        try:
            connection = ConnectHandler(**device)
            logger.debug("Connection established to %s", hostname)
            connection.enable()

            for command in commands:
                logger.debug("Executing command on %s: %s", hostname, command)
                output = connection.send_command(command)
                filepath = get_file_path(hostname, command, base)
                create_backup(filepath)
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(output)
                logger.debug("Saved output for %s to: %s", command, filepath)

            connection.disconnect()
            logger.info(
                "Successfully captured data for %s (%d commands)",
                hostname,
                len(commands),
            )
            success_count += 1
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.error(
                "Error capturing data for %s: %s", hostname, exc, exc_info=True
            )
            failure_count += 1
            # Continue with next device

    logger.info(
        "Capture all completed: %d successful, %d failed, %d total",
        success_count,
        failure_count,
        total_hosts,
    )
    return redirect(url_for("host_list"))


# --- Host List page ---
@app.route("/")
def host_list():
    """
    Displays the main host list page showing all devices and their status.
    """
    logger.debug("Host list page requested")
    hosts = []
    rows = read_hosts_csv()  # CSV reading ignores comment lines
    for row in rows:
        host = row["host"]
        ip = row["ip"]
        commands = get_commands_for_host(host)
        origin_info = []
        dest_info = []
        diff_info = []
        for command in commands:
            origin_path = get_file_path(host, command, "origin")
            dest_path = get_file_path(host, command, "dest")
            origin_info.append(
                {"command": command, "mtime": get_file_mtime(origin_path)}
            )
            dest_info.append({"command": command, "mtime": get_file_mtime(dest_path)})
            if os.path.exists(origin_path) and os.path.exists(dest_path):
                with open(origin_path, encoding="utf-8") as f:
                    origin_data = f.read()
                with open(dest_path, encoding="utf-8") as f:
                    dest_data = f.read()
                status = compute_diff_status(origin_data, dest_data)
            else:
                status = "file not found"
            diff_info.append({"command": command, "status": status})
        hosts.append(
            {
                "host": host,
                "ip": ip,
                "origin_info": origin_info,
                "dest_info": dest_info,
                "diff_info": diff_info,
            }
        )
    logger.debug("Rendered host list with %d host(s)", len(hosts))
    return render_template("host_list.html", hosts=hosts)


# --- Host Detail page ---
@app.route("/host/<hostname>")
def host_detail(hostname):
    """
    Displays detailed diff view for a specific host.
    """
    logger.info("Host detail page requested for: %s", hostname)
    view = request.args.get("view", "inline")
    command_results = []
    commands = get_commands_for_host(hostname)
    for command in commands:
        origin_path = get_file_path(hostname, command, "origin")
        dest_path = get_file_path(hostname, command, "dest")
        if os.path.exists(origin_path):
            origin_mtime = get_file_mtime(origin_path)
            with open(origin_path, encoding="utf-8") as f:
                origin_data = f.read()
        else:
            origin_mtime = "file not found"
            origin_data = None

        if os.path.exists(dest_path):
            dest_mtime = get_file_mtime(dest_path)
            with open(dest_path, encoding="utf-8") as f:
                dest_data = f.read()
        else:
            dest_mtime = "file not found"
            dest_data = None

        if origin_data is None or dest_data is None:
            diff_status = "file not found"
            diff_html = ""
            logger.warning(
                "Missing files for diff comparison on %s - command: %s",
                hostname,
                command,
            )
        else:
            diff_status, diff_html = compute_diff(origin_data, dest_data, view)
            logger.debug(
                "Computed diff for %s - command: %s, status: %s",
                hostname,
                command,
                diff_status,
            )
        # Save the diff file for later review
        diff_file_path = get_diff_file_path(hostname, command)
        try:
            with open(diff_file_path, "w", encoding="utf-8") as diff_file:
                diff_file.write(diff_html)
            logger.debug("Saved diff file: %s", diff_file_path)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.error(
                "Error writing diff file for %s %s: %s",
                hostname,
                command,
                exc,
            )

        command_results.append(
            {
                "command": command,
                "origin_mtime": origin_mtime,
                "dest_mtime": dest_mtime,
                "diff_status": diff_status,
                "diff_html": diff_html,
            }
        )
    toggle_view = "sidebyside" if view == "inline" else "inline"
    logger.debug(
        "Rendered host detail for %s with %d command(s)", hostname, len(command_results)
    )
    return render_template(
        "host_detail.html",
        hostname=hostname,
        command_results=command_results,
        view=view,
        toggle_view=toggle_view,
    )


# --- Compare files between two hosts (origin/dest) ---
@app.route("/compare_files", methods=["GET", "POST"])
def compare_files():
    """
    Renders a form to select two hosts, directory (origin/dest), and command.
    When submitted, reads corresponding files for both hosts and computes diff.
    """
    hosts = list({row["host"] for row in read_hosts_csv()})
    error = None
    diff_html = None
    status = None
    if request.method == "POST":
        logger.info("File comparison requested")
        host1 = request.form.get("host1")
        host2 = request.form.get("host2")
        base = request.form.get("base")
        command = request.form.get("command")
        view = request.form.get("view", "sidebyside")

        if not host1 or not host2 or not base or not command:
            error = "All fields are required."
            logger.warning("File comparison failed: missing required fields")
        else:
            path1 = get_file_path(host1, command, base)
            path2 = get_file_path(host2, command, base)
            if not os.path.exists(path1):
                error = f"File for {host1} not found: {path1}"
                logger.error("File not found for comparison: %s", path1)
            elif not os.path.exists(path2):
                error = f"File for {host2} not found: {path2}"
                logger.error("File not found for comparison: %s", path2)
            else:
                with open(path1, encoding="utf-8") as f:
                    data1 = f.read()
                with open(path2, encoding="utf-8") as f:
                    data2 = f.read()
                if view == "sidebyside":
                    diff_html = generate_side_by_side_html(data1, data2)
                    status = compute_diff_status(data1, data2)
                else:
                    status, diff_html = compute_diff(data1, data2, view)
                logger.info(
                    "File comparison completed: %s vs %s, status: %s",
                    host1,
                    host2,
                    status,
                )
    return render_template(
        "compare_files.html",
        hosts=hosts,
        error=error,
        diff_html=diff_html,
        status=status,
    )


# --- Export diff HTML for a host ---
@app.route("/export/<hostname>")
def export_diff(hostname):
    """
    Generates and returns a downloadable HTML file containing all diff results
    for the specified hostname.
    """
    commands = get_commands_for_host(hostname)
    device_info = get_device_info(hostname)
    if not device_info:
        return "Host not found", 404

    # Sanitize hostname for filename - prevent path traversal
    safe_hostname = re.sub(r"[^\w\-]", "_", hostname)

    # Generate HTML content
    bootstrap_css = (
        "https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css"
    )
    html_parts = [
        "<!DOCTYPE html>",
        "<html lang='en'>",
        "<head>",
        "<meta charset='UTF-8'>",
        f"<title>Diff Export - {hostname}</title>",
        f"<link rel='stylesheet' href='{bootstrap_css}'>",
        "</head>",
        "<body>",
        "<div class='container mt-4'>",
        f"<h1>Diff Export for Host: {hostname}</h1>",
        f"<p><strong>IP Address:</strong> {device_info['ip']}</p>",
        "<hr>",
    ]

    for command in commands:
        origin_path = get_file_path(hostname, command, "origin")
        dest_path = get_file_path(hostname, command, "dest")

        if os.path.exists(origin_path) and os.path.exists(dest_path):
            try:
                with open(origin_path, encoding="utf-8") as f:
                    origin_data = f.read()
                with open(dest_path, encoding="utf-8") as f:
                    dest_data = f.read()

                origin_mtime = get_file_mtime(origin_path)
                dest_mtime = get_file_mtime(dest_path)
                status, diff_html = compute_diff(origin_data, dest_data, "inline")

                html_parts.append("<div class='card mb-3'>")
                cmd_header = (
                    f"<div class='card-header'>"
                    f"<strong>Command:</strong> {command}</div>"
                )
                html_parts.append(cmd_header)
                html_parts.append("<div class='card-body'>")
                html_parts.append(
                    f"<p><strong>Origin Modified:</strong> {origin_mtime}</p>"
                )
                html_parts.append(
                    f"<p><strong>Dest Modified:</strong> {dest_mtime}</p>"
                )
                if status == "changes detected":
                    status_span = (
                        f"<span style='background-color: #ffff99; "
                        f"font-weight:bold; padding: 5px; "
                        f"color:black;'>{status}</span>"
                    )
                    html_parts.append(status_span)
                elif status == "identical":
                    status_span = (
                        f"<span style='background-color: #add8e6; "
                        f"font-weight:bold; padding: 5px; "
                        f"color:black;'>{status}</span>"
                    )
                    html_parts.append(status_span)
                else:
                    html_parts.append(f"<span class='badge badge-info'>{status}</span>")
                html_parts.append(f"<div class='mt-3'>{diff_html}</div>")
                html_parts.append("</div></div>")
            except (IOError, OSError) as exc:  # pylint: disable=broad-exception-caught
                html_parts.append("<div class='card mb-3'>")
                cmd_header = (
                    f"<div class='card-header'>"
                    f"<strong>Command:</strong> {command}</div>"
                )
                html_parts.append(cmd_header)
                html_parts.append("<div class='card-body'>")
                html_parts.append(
                    f"<p class='text-danger'>Error reading files: {exc}</p>"
                )
                html_parts.append("</div></div>")
        else:
            html_parts.append("<div class='card mb-3'>")
            cmd_header = (
                f"<div class='card-header'>"
                f"<strong>Command:</strong> {command}</div>"
            )
            html_parts.append(cmd_header)
            html_parts.append("<div class='card-body'>")
            html_parts.append(
                "<p class='text-danger'>Files not found for this command</p>"
            )
            html_parts.append("</div></div>")

    html_parts.extend(["</div>", "</body>", "</html>"])
    html_content = "\n".join(html_parts)

    response = make_response(html_content)
    response.headers["Content-Type"] = "text/html"
    response.headers["Content-Disposition"] = (
        f"attachment; filename={safe_hostname}-diff-export.html"
    )
    return response


# --- JSON Export API endpoint ---
@app.route("/api/export/<hostname>")
def export_json(hostname):
    """
    JSON export endpoint that returns all command results, timestamps, and diff status
    for the specified hostname. Validates hostname to prevent security issues.
    """
    # Validate hostname exists in CSV
    device_info = get_device_info(hostname)
    if not device_info:
        return (
            jsonify({"error": "Hostname not found in hosts configuration"}),
            404,
        )

    commands = get_commands_for_host(hostname)
    export_data = {
        "hostname": hostname,
        "ip": device_info["ip"],
        "model": device_info.get("model", ""),
        "commands": [],
    }

    for command in commands:
        origin_path = get_file_path(hostname, command, "origin")
        dest_path = get_file_path(hostname, command, "dest")

        if os.path.exists(origin_path) and os.path.exists(dest_path):
            try:
                with open(origin_path, encoding="utf-8") as f:
                    origin_data = f.read()
                with open(dest_path, encoding="utf-8") as f:
                    dest_data = f.read()

                origin_mtime = get_file_mtime(origin_path)
                dest_mtime = get_file_mtime(dest_path)
                status = compute_diff_status(origin_data, dest_data)

                command_data = {
                    "command": command,
                    "origin": {"exists": True, "timestamp": origin_mtime},
                    "dest": {"exists": True, "timestamp": dest_mtime},
                    "diff_status": status,
                }
                export_data["commands"].append(command_data)
            except (IOError, OSError) as exc:  # pylint: disable=broad-exception-caught
                logger.warning("Error reading files for command %s: %s", command, exc)
                command_data = {
                    "command": command,
                    "origin": {"exists": False, "timestamp": None},
                    "dest": {"exists": False, "timestamp": None},
                    "diff_status": "error",
                    "error": str(exc),
                }
                export_data["commands"].append(command_data)
        else:
            command_data = {
                "command": command,
                "origin": {
                    "exists": os.path.exists(origin_path),
                    "timestamp": (
                        get_file_mtime(origin_path)
                        if os.path.exists(origin_path)
                        else None
                    ),
                },
                "dest": {
                    "exists": os.path.exists(dest_path),
                    "timestamp": (
                        get_file_mtime(dest_path) if os.path.exists(dest_path) else None
                    ),
                },
                "diff_status": "file not found",
            }
            export_data["commands"].append(command_data)

    return jsonify(export_data)


# --- Logs Web UI ---
@app.route("/logs")
def logs_view():
    """
    Web UI for viewing logs.
    Displays the most recent log entries with real-time updates.
    """
    logger.debug("Logs view page requested")
    # Read the last 1000 lines from the log file
    log_file_path = os.path.join(LOGS_DIR, "nw-diff.log")
    lines = []
    try:
        if os.path.exists(log_file_path):
            with open(log_file_path, "r", encoding="utf-8") as f:
                all_lines = f.readlines()
                lines = all_lines[-1000:]  # Get last 1000 lines
        else:
            logger.warning("Log file does not exist yet: %s", log_file_path)
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.error("Error reading log file: %s", exc)
        lines = [f"Error reading log file: {exc}"]

    return render_template("logs.html", log_lines=lines)


# --- Logs API Endpoint ---
@app.route("/api/logs")
def logs_api():
    """
    API endpoint for programmatic access to logs.
    Returns logs in JSON format.

    Query parameters:
    - level: Filter by log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    - limit: Maximum number of lines to return (default: 1000, max: 10000)
    - tail: If true, return the last N lines (default: true)
    """
    logger.debug("Logs API endpoint requested")

    # Get query parameters
    level_filter = request.args.get("level", "").upper()
    try:
        limit = int(request.args.get("limit", "1000"))
        limit = min(limit, 10000)  # Max 10000 lines
    except ValueError:
        limit = 1000

    tail = request.args.get("tail", "true").lower() == "true"

    log_file_path = os.path.join(LOGS_DIR, "nw-diff.log")
    log_entries = []

    try:
        if os.path.exists(log_file_path):
            with open(log_file_path, "r", encoding="utf-8") as f:
                all_lines = f.readlines()

                # Get lines based on tail parameter
                if tail:
                    lines = all_lines[-limit:]
                else:
                    lines = all_lines[:limit]

                # Filter by level if specified
                for line in lines:
                    if level_filter and level_filter not in line:
                        continue
                    log_entries.append(line.rstrip())
        else:
            logger.warning("Log file does not exist yet: %s", log_file_path)

    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.error("Error reading log file for API: %s", exc)
        return jsonify({"error": f"Error reading log file: {exc}", "logs": []}), 500

    return jsonify(
        {
            "logs": log_entries,
            "count": len(log_entries),
            "level_filter": level_filter if level_filter else None,
            "limit": limit,
        }
    )


if __name__ == "__main__":
    # Read debug mode from environment variable, default to False for security
    debug_mode = os.environ.get("APP_DEBUG", "false").lower() in {"true", "1", "yes"}
    app.run(debug=debug_mode)
