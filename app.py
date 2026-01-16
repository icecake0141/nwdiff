#!/usr/bin/env python3
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

import csv
import datetime
import os

from flask import Flask, redirect, render_template, request, url_for
from diff_match_patch import diff_match_patch
from netmiko import ConnectHandler

app = Flask(__name__)

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
    with open(HOSTS_CSV, newline="", encoding="utf-8") as csvfile:
        filtered = (line for line in csvfile if not line.lstrip().startswith("#"))
        reader = csv.DictReader(filtered)
        return list(reader)


# --- Helper function to get device info from CSV ---
def get_device_info(host):
    """
    Retrieves the device info dictionary from CSV for the given host.
    Returns None if the host is not found.
    """
    rows = read_hosts_csv()
    for row in rows:
        if row["host"] == host:
            return row
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
    Constructs the filename using the host and command (spaces replaced with underscores).
    """
    safe_command = command.replace(" ", "_")
    filename = f"{host}-{safe_command}.txt"
    if base == "origin":
        return os.path.join(ORIGIN_DIR, filename)
    elif base == "dest":
        return os.path.join(DEST_DIR, filename)
    else:
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
      - If a line contains any diff tags, the entire line is highlighted with a yellow background.
      - Additionally, text within <del> tags gets a red background and text within <ins> tags gets a blue background.
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
    Generates side-by-side HTML displaying the origin content (common parts plus deletions)
    on the left and the destination content (common parts plus insertions) on the right.
    For each column:
      - At the character level, text in <del> tags is highlighted with a red background
        and text in <ins> tags with a blue background.
      - At the line level, any line containing diff tags is wrapped with a yellow background.
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

    html = f"""<table class="table table-bordered" style="width:100%; border-collapse: collapse;">
  <tr>
    <td style="vertical-align: top; width:50%; white-space: pre-wrap;">{origin_html}</td>
    <td style="vertical-align: top; width:50%; white-space: pre-wrap;">{dest_html}</td>
  </tr>
</table>"""
    return html


# --- Capture endpoint for individual host ---
@app.route("/capture/<base>/<hostname>")
def capture(base, hostname):
    """
    Triggered when clicking the "Capture Origin" or "Capture Dest" button on the host list page.
    Establishes a single connection to the target device and retrieves output for each command
    (based on the device's model) before disconnecting.
    CSV reading ignores comment lines.
    """
    if base not in ["origin", "dest"]:
        return "Invalid capture type", 400

    commands = get_commands_for_host(hostname)
    device_info = get_device_info(hostname)
    if not device_info:
        return "Could not find device info in CSV for host: " + hostname

    device = {
        "device_type": device_info["model"],
        "host": device_info["ip"],
        "username": device_info["username"],
        "port": device_info["port"],
        "password": os.environ.get("DEVICE_PASSWORD", "your_password"),
    }

    try:
        connection = ConnectHandler(**device)
        connection.enable()

        # Execute all commands in a single session
        for command in commands:
            output = connection.send_command(command)
            filepath = get_file_path(hostname, command, base)
            create_backup(filepath)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(output)

        connection.disconnect()
        return redirect(url_for("host_list"))
    except Exception as exc:  # pylint: disable=broad-exception-caught
        return f"Failed to capture data: {exc}", 500


# --- New endpoint: Capture for all devices ---
@app.route("/capture_all/<base>")
def capture_all(base):
    """
    Captures data for all devices registered in hosts.csv.
    Establishes a connection for each device and retrieves the output for each command.
    CSV reading ignores comment lines.
    """
    if base not in ["origin", "dest"]:
        return "Invalid capture type", 400

    rows = read_hosts_csv()
    for row in rows:
        hostname = row["host"]
        commands = get_commands_for_host(hostname)
        device_info = get_device_info(hostname)
        if not device_info:
            continue

        device = {
            "device_type": device_info["model"],
            "host": device_info["ip"],
            "username": device_info["username"],
            "port": device_info["port"],
            "password": os.environ.get("DEVICE_PASSWORD", "your_password"),
        }
        try:
            connection = ConnectHandler(**device)
            connection.enable()

            for command in commands:
                output = connection.send_command(command)
                filepath = get_file_path(hostname, command, base)
                create_backup(filepath)
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(output)

            connection.disconnect()
        except Exception as exc:  # pylint: disable=broad-exception-caught
            print(f"Error capturing data for {hostname}: {exc}")
            # Continue with next device

    return redirect(url_for("host_list"))


# --- Host List page ---
@app.route("/")
def host_list():
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
    return render_template("host_list.html", hosts=hosts)


# --- Host Detail page ---
@app.route("/host/<hostname>")
def host_detail(hostname):
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
        else:
            diff_status, diff_html = compute_diff(origin_data, dest_data, view)
        # Save the diff file for later review
        diff_file_path = get_diff_file_path(hostname, command)
        try:
            with open(diff_file_path, "w", encoding="utf-8") as diff_file:
                diff_file.write(diff_html)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            print(f"Error writing diff file for {hostname} {command}: {exc}")

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
        host1 = request.form.get("host1")
        host2 = request.form.get("host2")
        base = request.form.get("base")
        command = request.form.get("command")
        view = request.form.get("view", "sidebyside")

        if not host1 or not host2 or not base or not command:
            error = "All fields are required."
        else:
            path1 = get_file_path(host1, command, base)
            path2 = get_file_path(host2, command, base)
            if not os.path.exists(path1):
                error = f"File for {host1} not found: {path1}"
            elif not os.path.exists(path2):
                error = f"File for {host2} not found: {path2}"
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
    return render_template(
        "compare_files.html",
        hosts=hosts,
        error=error,
        diff_html=diff_html,
        status=status,
    )


if __name__ == "__main__":
    app.run(debug=True)
