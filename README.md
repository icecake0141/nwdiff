# Nwdiff Project

Nwdiff is a Flask-based web application designed to retrieve, compare, and display configuration or status data collected from network devices. It leverages Netmiko to connect to devices and capture data defined in a CSV file. Using diff-match-patch, the application computes differences between two sets of data and presents the results in both inline and side-by-side views. Diff HTML files are generated and stored in a dedicated "diff" directory for subsequent review.

## Features

- **Device Configuration:**  
  Device details (hostname, IP address, SSH port, username, and device model) are maintained in a CSV file (`hosts.csv`).

- **Data Capture:**  
  Two endpoints capture data from each device:
  - `/capture/origin/<hostname>`: Captures the initial (or original) data.
  - `/capture/dest/<hostname>`: Captures the latest (or destination) data.
  
  The captured outputs are stored in the `origin` and `dest` directories, respectively.

- **Difference Computation:**  
  The application compares corresponding files from the `origin` and `dest` directories using diff-match-patch:
  - **Inline View:** Presents the standard diff output.
  - **Side-by-Side View:** Displays the origin data on the left and the computed differences on the right.
  
  Diff results are converted into HTML files and saved in the `diff` directory.

- **Detailed Device View:**  
  Access detailed information for each device through the `/host/<hostname>` endpoint.

### New Improvements

- **Error Logging:**  
  Comprehensive logging system tracks all operations, errors, and system events.
  - Logs are stored in the `logs` directory
  - View logs through the web interface at `/logs`
  - Access logs via API at `/api/logs`

- **Configuration Backup:**  
  Automatic backup rotation for captured configurations.
  - Backups are created before overwriting existing captures
  - Last 10 backups are retained per file
  - Backups are stored in the `backup` directory with timestamps

- **Export Functionality:**  
  Export diff results as JSON for automated processing or external integrations.
  - Access via `/api/export/<hostname>`
  - Includes all command results, timestamps, and diff status
  - Useful for CI/CD pipelines and monitoring systems

- **Search and Filter:**  
  Enhanced UI with search and filter capabilities.
  - Search hosts by name or IP address
  - Filter by diff status (changes detected, identical, file not found)
  - Real-time filtering without page reload

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/nwdiff.git
   ```
2. **Navigate to the project directory:**
   ```bash
   cd /workspaces/nwdiff
   ```

3. **Install dependencies:**  
   Ensure you have Python installed, then install the required packages:
   ```bash
   pip install -r requirements.txt
   ```
   Required packages include Flask, Netmiko, and diff-match-patch.

4. **Configure Environment Variables:**  
   Set the `DEVICE_PASSWORD` environment variable to provide the password needed for device connections:
   ```bash
   export DEVICE_PASSWORD=your_device_password
   ```

## Usage

1. **Run the Application:**
   ```bash
   python app.py
   ```
2. **Access the Application:**  
   Open your browser and navigate to [http://localhost:5000](http://localhost:5000).

3. **Interact with Endpoints:**
   - **Capture Data:**
     - For origin data: `/capture/origin/<hostname>`
     - For destination data: `/capture/dest/<hostname>`
   - **View Detailed Device Info:**  
     `/host/<hostname>`

4. **Review Diff Results:**  
   The computed diff HTML files are stored in the `diff` directory for offline viewing.

## Development

1. **Install development dependencies:**
   ```bash
   pip install -r requirements.txt -r requirements-dev.txt
   ```

2. **Format, lint, type check, and test:**
   ```bash
   black tests
   pylint tests
   mypy tests
   pytest
   ```

3. **Run pre-commit hooks:**
   ```bash
   pre-commit run --all-files
   ```
