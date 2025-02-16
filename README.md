# Nwdiff Project

Nwdiff is a web application built with Flask that analyzes and displays differences in data retrieved from network devices. It connects to devices using Netmiko and calculates differences using diff-match-patch.

## Overview

- Host information is managed in a CSV file (`hosts.csv`).
- Output results are saved in "origin" and "dest" directories for each host.
- Data retrieval and difference comparison are performed using endpoints.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/nwdiff.git
   ```
2. Move to the project directory:
   ```bash
   cd nwdiff
   ```

## Usage

1. Install the required Python packages (e.g., Flask, netmiko, diff-match-patch).
2. Set the password required to connect to the devices in the environment variable `DEVICE_PASSWORD`.
3. Run the application:
   ```bash
   python app.py
   ```
4. Open http://localhost:5000 in your browser and retrieve data or compare differences for each host from the host information list.
   - Data retrieval endpoints: /capture/origin/<hostname> and /capture/dest/<hostname>
   - Detailed display endpoint: /host/<hostname>
