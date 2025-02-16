#!/usr/bin/env python3
# filepath: /path/nwdiff/app.py
import os
import csv
import datetime
import difflib
from flask import Flask, render_template, request, redirect, url_for
from diff_match_patch import diff_match_patch
from netmiko import ConnectHandler

app = Flask(__name__)

# Directories, CSV file, and command list settings
ORIGIN_DIR = "origin"
DEST_DIR = "dest"  # Changed from "dear" to "dest"
DIFF_DIR = "diff"  # 新規追加
HOSTS_CSV = "hosts.csv"
COMMANDS = [
    "get system status",
    "get switch physical-port",
    "diag stp vlan list"
    # Add more commands as needed
]

# Create required directories if they do not exist
os.makedirs(ORIGIN_DIR, exist_ok=True)
os.makedirs(DEST_DIR, exist_ok=True)
os.makedirs(DIFF_DIR, exist_ok=True)  # diffディレクトリ作成


# --- Function to obtain switch data (assumes existing code) ---
def fetch_switch_data(host, command):
    """
    Connects to the switch using Netmiko and retrieves the output for the given command.
    """
    # CSVから該当ホストの情報を取得
    with open(HOSTS_CSV, newline="", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        device_info = None
        for row in reader:
            if row["host"] == host:
                device_info = row
                break
    
    if not device_info:
        return "Could not find device info in CSV for host: " + host

    device = {
        'device_type': device_info["model"],
        'host': device_info["ip"],
        'username': device_info["username"],
        'port': device_info["port"],
        'password': os.environ.get('DEVICE_PASSWORD', 'your_password'),
    }
    
    try:
        connection = ConnectHandler(**device)
        connection.enable()
        output = connection.send_command(command)
        connection.disconnect()
        return output
    except Exception as e:
        return f"Failed to retrieve data: {str(e)}"


# --- Helper function ---
def get_file_path(host, command, base):
    """
    base: "origin" or "dest"
    The filename is constructed by combining the host and command (spaces replaced with underscores).
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
    diffファイルのパスを構築
    """
    safe_command = command.replace(" ", "_")
    filename = f"{host}-{safe_command}-diff.html"
    return os.path.join(DIFF_DIR, filename)


# --- Capture endpoints ---
@app.route("/capture/<base>/<hostname>")
def capture(base, hostname):
    """
    Called when clicking the "Capture Origin" or "Capture Dest" button on the host list page.
    Retrieves the output for each command for the target host and saves it to a file.
    """
    if base not in ["origin", "dest"]:
        return "Invalid capture type", 400
    for command in COMMANDS:
        data = fetch_switch_data(hostname, command)
        filepath = get_file_path(hostname, command, base)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(data)
    return redirect(url_for("host_list"))


# --- Host List page ---
@app.route("/")
def host_list():
    hosts = []
    # Read the CSV file (assumes the CSV contains "host" and "ip" columns)
    with open(HOSTS_CSV, newline="", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            host = row["host"]
            ip = row["ip"]
            # For each command, get the file existence, update time, and diff status for origin and dest files
            origin_info = []
            dest_info = []
            diff_info = []
            for command in COMMANDS:
                origin_path = get_file_path(host, command, "origin")
                dest_path = get_file_path(host, command, "dest")
                if os.path.exists(origin_path):
                    origin_mtime = datetime.datetime.fromtimestamp(
                        os.path.getmtime(origin_path)
                    ).strftime("%Y-%m-%d %H:%M:%S")
                else:
                    origin_mtime = "file not found"
                if os.path.exists(dest_path):
                    dest_mtime = datetime.datetime.fromtimestamp(
                        os.path.getmtime(dest_path)
                    ).strftime("%Y-%m-%d %H:%M:%S")
                else:
                    dest_mtime = "file not found"
                # Determine diff status (calculate diff only if both files exist)
                if os.path.exists(origin_path) and os.path.exists(dest_path):
                    with open(origin_path, encoding="utf-8") as f:
                        origin_data = f.read()
                    with open(dest_path, encoding="utf-8") as f:
                        dest_data = f.read()
                    dmp = diff_match_patch()
                    diffs = dmp.diff_main(origin_data, dest_data)
                    dmp.diff_cleanupSemantic(diffs)
                    if len(diffs) == 1 and diffs[0][0] == 0:
                        diff_status = "identical"
                    else:
                        diff_status = "changes detected"
                else:
                    diff_status = "file not found"
                origin_info.append({"command": command, "mtime": origin_mtime})
                dest_info.append({"command": command, "mtime": dest_mtime})
                diff_info.append({"command": command, "status": diff_status})
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


def generate_side_by_side_html(origin_data, dest_data):
    """
    左側に origin の内容、右側に diff_match_patch による比較 (dest側) を表示する side-by-side HTML を生成する
    """
    dmp = diff_match_patch()
    diffs = dmp.diff_main(origin_data, dest_data)
    dmp.diff_cleanupSemantic(diffs)
    right_html = dmp.diff_prettyHtml(diffs).replace('¶', '').replace('&para;', '')
    html = f"""<table style="width:100%; border-collapse: collapse;">
  <tr>
    <td style="vertical-align: top; width:50%; border:1px solid #ccc; white-space: pre-wrap;">{origin_data}</td>
    <td style="vertical-align: top; width:50%; border:1px solid #ccc; white-space: pre-wrap;">{right_html}</td>
  </tr>
</table>"""
    return html

# --- Host Detail page ---
@app.route("/host/<hostname>")
def host_detail(hostname):
    view = request.args.get("view", "inline")
    command_results = []
    for command in COMMANDS:
        origin_path = get_file_path(hostname, command, "origin")
        dest_path = get_file_path(hostname, command, "dest")
        if os.path.exists(origin_path):
            origin_mtime = datetime.datetime.fromtimestamp(
                os.path.getmtime(origin_path)
            ).strftime("%Y-%m-%d %H:%M:%S")
            with open(origin_path, encoding="utf-8") as f:
                origin_data = f.read()
        else:
            origin_mtime = "file not found"
            origin_data = None

        if os.path.exists(dest_path):
            dest_mtime = datetime.datetime.fromtimestamp(
                os.path.getmtime(dest_path)
            ).strftime("%Y-%m-%d %H:%M:%S")
            with open(dest_path, encoding="utf-8") as f:
                dest_data = f.read()
        else:
            dest_mtime = "file not found"
            dest_data = None

        diff_html = ""
        if origin_data is None or dest_data is None:
            diff_status = "file not found"
        else:
            dmp = diff_match_patch()
            diffs = dmp.diff_main(origin_data, dest_data)
            dmp.diff_cleanupSemantic(diffs)
            if all(op == 0 for op, text in diffs):
                diff_status = "identical"
                if view == "inline":
                    diff_html = f"<pre>{origin_data}</pre>"
                elif view == "sidebyside":
                    diff_html = generate_side_by_side_html(origin_data, dest_data)
                else:
                    diff_html = f"<pre>{origin_data}</pre>"
            else:
                diff_status = "changes detected"
                if view == "inline":
                    raw_diff_html = dmp.diff_prettyHtml(diffs)
                    diff_html = raw_diff_html.replace('¶', '<br>').replace('&para;', '')
                elif view == "sidebyside":
                    diff_html = generate_side_by_side_html(origin_data, dest_data)
                else:
                    raw_diff_html = dmp.diff_prettyHtml(diffs)
                    diff_html = raw_diff_html.replace('¶', '<br>').replace('&para;', '')

        # diff ファイルとして保存
        diff_file_path = get_diff_file_path(hostname, command)
        try:
            with open(diff_file_path, "w", encoding="utf-8") as diff_file:
                diff_file.write(diff_html)
        except Exception as e:
            print(f"Error writing diff file for {hostname} {command}: {e}")

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


if __name__ == "__main__":
    app.run(debug=True)
