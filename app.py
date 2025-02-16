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
HOSTS_CSV = "hosts.csv"
COMMANDS = [
    "get switch physical-port"
    # Add more commands as needed
]

# Create required directories if they do not exist
os.makedirs(ORIGIN_DIR, exist_ok=True)
os.makedirs(DEST_DIR, exist_ok=True)


# --- Function to obtain switch data (assumes existing code) ---
def fetch_switch_data(host, command):
    """
    Connects to the switch using Netmiko and retrieves the output for the given command.
    """
    device = {
        'device_type': 'cisco_ios',  # Adjust this according to your device type
        'host': host,
        'username': 'your_username',  # Replace with your username
        'password': os.environ.get('DEVICE_PASSWORD', 'your_password'),  # Retrieve password from environment variable
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


# --- Host Detail page ---
@app.route("/host/<hostname>")
def host_detail(hostname):
    # The view parameter in the URL determines the display format ("inline" or "sidebyside")
    view = request.args.get("view", "inline")
    command_results = []
    for command in COMMANDS:
        origin_path = get_file_path(hostname, command, "origin")
        dest_path = get_file_path(hostname, command, "dest")
        # Origin file
        if os.path.exists(origin_path):
            origin_mtime = datetime.datetime.fromtimestamp(
                os.path.getmtime(origin_path)
            ).strftime("%Y-%m-%d %H:%M:%S")
            with open(origin_path, encoding="utf-8") as f:
                origin_data = f.read()
        else:
            origin_mtime = "file not found"
            origin_data = None
        # Dest file
        if os.path.exists(dest_path):
            dest_mtime = datetime.datetime.fromtimestamp(
                os.path.getmtime(dest_path)
            ).strftime("%Y-%m-%d %H:%M:%S")
            with open(dest_path, encoding="utf-8") as f:
                dest_data = f.read()
        else:
            dest_mtime = "file not found"
            dest_data = None

        # Calculate diff (only if both files exist)
        diff_html = ""
        if origin_data is None or dest_data is None:
            diff_status = "file not found"
        else:
            dmp = diff_match_patch()
            diffs = dmp.diff_main(origin_data, dest_data)
            dmp.diff_cleanupSemantic(diffs)
            if len(diffs) == 1 and diffs[0][0] == 0:
                diff_status = "identical"
            else:
                diff_status = "changes detected"
                if view == "inline":
                    diff_html = dmp.diff_prettyHtml(diffs)
                elif view == "sidebyside":
                    origin_lines = origin_data.splitlines()
                    dest_lines = dest_data.splitlines()
                    diff_table = difflib.HtmlDiff().make_table(
                        origin_lines,
                        dest_lines,
                        fromdesc="Origin",
                        todesc="Dest",
                        context=True,
                        numlines=2,
                    )
                    diff_html = diff_table
                else:
                    diff_html = dmp.diff_prettyHtml(diffs)
        command_results.append(
            {
                "command": command,
                "origin_mtime": origin_mtime,
                "dest_mtime": dest_mtime,
                "diff_status": diff_status,
                "diff_html": diff_html,
            }
        )
    # Link to toggle display format (inverts the view parameter)
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
