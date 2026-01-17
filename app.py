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
from netmiko import ConnectHandler

# Import from nw_diff modules
from nw_diff.logging_config import logger
from nw_diff.auth import require_api_token
from nw_diff.security import (
    validate_hostname,
    validate_command,
    validate_base_directory,
)
from nw_diff.storage import (
    get_file_path,
    get_diff_file_path,
    get_file_mtime,
    create_backup,
)
from nw_diff.diff import compute_diff_status, compute_diff, generate_side_by_side_html
from nw_diff.devices import (
    read_hosts_csv,
    get_device_info,
    get_commands_for_host,
)

app = Flask(__name__)


# --- Capture endpoint for individual host ---
@app.route("/capture/<base>/<hostname>", methods=["POST"])
@require_api_token
def capture(base, hostname):
    """
    Triggered when clicking the "Capture Origin" or "Capture Dest"
    button on the host list page.
    Establishes a single connection to the target device and retrieves
    output for each command (based on the device's model) before
    disconnecting. CSV reading ignores comment lines.
    Validates inputs to prevent path traversal attacks.
    """
    logger.info("Capture request received for host=%s, base=%s", hostname, base)

    if not validate_base_directory(base):
        logger.error("Invalid capture type requested: %s", base)
        return "Invalid capture type", 400

    if not validate_hostname(hostname):
        logger.error("Invalid hostname for capture: %s", hostname)
        return "Invalid hostname", 400

    commands = get_commands_for_host(hostname)
    device_info = get_device_info(hostname)
    if not device_info:
        logger.error("Could not find device info in CSV for host: %s", hostname)
        return f"Could not find device info in CSV for host: {hostname}", 404

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
        return "Failed to capture data from device", 500


# --- New endpoint: Capture for all devices ---
@app.route("/capture_all/<base>", methods=["POST"])
@require_api_token
def capture_all(base):
    """
    Captures data for all devices registered in hosts.csv.
    Establishes a connection for each device and retrieves the output for each command.
    CSV reading ignores comment lines.
    Validates inputs to prevent path traversal attacks.
    """
    logger.info("Capture all request received for base=%s", base)

    if not validate_base_directory(base):
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
    Validates hostname to prevent path traversal attacks.
    """
    logger.info("Host detail page requested for: %s", hostname)

    if not validate_hostname(hostname):
        logger.error("Invalid hostname for host detail: %s", hostname)
        return "Invalid hostname", 400

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
    Validates all inputs to prevent path traversal attacks.
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
        # Validate inputs before processing
        elif not validate_hostname(host1):
            error = f"Invalid hostname: {host1}"
            logger.warning("File comparison failed: invalid host1: %s", host1)
        elif not validate_hostname(host2):
            error = f"Invalid hostname: {host2}"
            logger.warning("File comparison failed: invalid host2: %s", host2)
        elif not validate_base_directory(base):
            error = f"Invalid base directory: {base}"
            logger.warning("File comparison failed: invalid base: %s", base)
        elif not validate_command(command):
            error = f"Invalid command: {command}"
            logger.warning("File comparison failed: invalid command: %s", command)
        else:
            try:
                path1 = get_file_path(host1, command, base)
                path2 = get_file_path(host2, command, base)
                if not os.path.exists(path1):
                    error = f"File for {host1} not found"
                    logger.error("File not found for comparison: %s", path1)
                elif not os.path.exists(path2):
                    error = f"File for {host2} not found"
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
            except ValueError as exc:
                error = f"Security validation failed: {exc}"
                logger.error("File comparison failed: %s", exc)
    return render_template(
        "compare_files.html",
        hosts=hosts,
        error=error,
        diff_html=diff_html,
        status=status,
    )


# --- Export diff HTML for a host ---
@app.route("/export/<hostname>")
@require_api_token
def export_diff(hostname):
    """
    Generates and returns a downloadable HTML file containing all diff results
    for the specified hostname.
    Validates hostname to prevent path traversal attacks.
    """
    if not validate_hostname(hostname):
        logger.error("Invalid hostname for export: %s", hostname)
        return "Invalid hostname", 400

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
@require_api_token
def export_json(hostname):
    """
    JSON export endpoint that returns all command results, timestamps, and diff status
    for the specified hostname. Validates hostname to prevent security issues.
    """
    # Validate hostname format
    if not validate_hostname(hostname):
        logger.error("Invalid hostname for JSON export: %s", hostname)
        return jsonify({"error": "Invalid hostname"}), 400

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
@require_api_token
def logs_view():
    """
    Web UI for viewing logs.
    Displays the most recent log entries with real-time updates.
    Supports limit parameter to control the number of lines displayed.
    """
    logger.debug("Logs view page requested")

    # Get limit from query parameter, default to 1000
    try:
        limit = int(request.args.get("limit", "1000"))
        limit = min(limit, 10000)  # Max 10000 lines
    except ValueError:
        limit = 1000

    # Import LOGS_DIR at runtime to allow test mocking
    from nw_diff.logging_config import (  # pylint: disable=import-outside-toplevel
        LOGS_DIR as current_logs_dir,
    )

    log_file_path = os.path.join(current_logs_dir, "nw-diff.log")
    lines = []
    try:
        if os.path.exists(log_file_path):
            with open(log_file_path, "r", encoding="utf-8") as f:
                all_lines = f.readlines()
                lines = all_lines[-limit:]  # Get last N lines
        else:
            logger.warning("Log file does not exist yet: %s", log_file_path)
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.error("Error reading log file: %s", exc)
        lines = [f"Error reading log file: {exc}"]

    return render_template("logs.html", log_lines=lines)


# --- Logs API Endpoint ---
@app.route("/api/logs")
@require_api_token
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

    # Import LOGS_DIR at runtime to allow test mocking
    from nw_diff.logging_config import (  # pylint: disable=import-outside-toplevel
        LOGS_DIR as current_logs_dir,
    )

    log_file_path = os.path.join(current_logs_dir, "nw-diff.log")
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
        return jsonify({"error": "Error reading log file", "logs": []}), 500

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
