#!/usr/bin/env python3
import os
import csv
import datetime
import difflib
from flask import Flask, render_template, request, redirect, url_for
from diff_match_patch import diff_match_patch
from netmiko import ConnectHandler

app = Flask(__name__)

# Directories and CSV file settings
ORIGIN_DIR = "origin"
DEST_DIR = "dest"  # Changed from "dear" to "dest"
DIFF_DIR = "diff"  # Directory to store diff HTML files
HOSTS_CSV = "hosts.csv"

# Device model specific command lists
DEVICE_COMMANDS = {
    "fortinet": (
        "get system performance",
        "get hardware status",
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
DEFAULT_COMMANDS = (
    "get system status",
    "get switch physical-port",
    "diag stp vlan list",
)

# Create required directories if they do not exist
os.makedirs(ORIGIN_DIR, exist_ok=True)
os.makedirs(DEST_DIR, exist_ok=True)
os.makedirs(DIFF_DIR, exist_ok=True)

# --- Helper function to read CSV and skip comment lines ---
def read_hosts_csv():
    """
    Reads the CSV file while ignoring lines that start with '#' (comments).
    Returns a list of dictionaries (CSV rows).
    """
    with open(HOSTS_CSV, newline="", encoding="utf-8") as csvfile:
        filtered = (line for line in csvfile if not line.lstrip().startswith('#'))
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
        return datetime.datetime.fromtimestamp(os.path.getmtime(filepath)).strftime("%Y-%m-%d %H:%M:%S")
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
    Returns a tuple of (diff_status, diff_html) based on the view mode.
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
            diff_html = raw_diff_html.replace("¶", "<br>").replace("&para;", "")
    return status, diff_html

# --- Function to generate side-by-side diff HTML ---
def generate_side_by_side_html(origin_data, dest_data):
    """
    Generates side-by-side HTML displaying the origin content on the left and
    the diff comparison (dest) on the right using diff_match_patch.
    """
    dmp = diff_match_patch()
    diffs = dmp.diff_main(origin_data, dest_data)
    dmp.diff_cleanupSemantic(diffs)
    right_html = dmp.diff_prettyHtml(diffs).replace("¶", "").replace("&para;", "")
    html = f"""<table style="width:100%; border-collapse: collapse;">
  <tr>
    <td style="vertical-align: top; width:50%; border:1px solid #ccc; white-space: pre-wrap;">{origin_data}</td>
    <td style="vertical-align: top; width:50%; border:1px solid #ccc; white-space: pre-wrap;">{right_html}</td>
  </tr>
</table>"""
    return html

# --- Capture endpoints ---
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
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(output)

        connection.disconnect()
        return redirect(url_for("host_list"))
    except Exception as e:
        return f"Failed to capture data: {str(e)}", 500

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
            origin_info.append({"command": command, "mtime": get_file_mtime(origin_path)})
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
        hosts.append({
            "host": host,
            "ip": ip,
            "origin_info": origin_info,
            "dest_info": dest_info,
            "diff_info": diff_info,
        })
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
        except Exception as e:
            print(f"Error writing diff file for {hostname} {command}: {e}")

        command_results.append({
            "command": command,
            "origin_mtime": origin_mtime,
            "dest_mtime": dest_mtime,
            "diff_status": diff_status,
            "diff_html": diff_html,
        })
    toggle_view = "sidebyside" if view == "inline" else "inline"
    return render_template("host_detail.html",
                           hostname=hostname,
                           command_results=command_results,
                           view=view,
                           toggle_view=toggle_view)

if __name__ == "__main__":
    app.run(debug=True)
