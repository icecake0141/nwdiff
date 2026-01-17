# NW-Diff Project

NW-Diff is a Flask-based web application designed to retrieve, compare, and display configuration or status data collected from network devices. It leverages Netmiko to connect to devices and capture data defined in a CSV file. Using diff-match-patch, the application computes differences between two sets of data and presents the results in both inline and side-by-side views. Diff HTML files are generated and stored in a dedicated "diff" directory for subsequent review.

## Features

- **Device Configuration:**
  Device details (hostname, IP address, SSH port, username, and device model) are maintained in a CSV file (`hosts.csv`).

- **Data Capture:**
  Two endpoints capture data from each device:
  - `/capture/origin/<hostname>`: Captures the initial (or original) data.
  - `/capture/dest/<hostname>`: Captures the latest (or destination) data.

  The captured outputs are stored in the `origin` and `dest` directories, respectively.

- **Configuration Backup:**
  Automatic backup creation before overwriting files to preserve historical configurations and prevent data loss:
  - Backups are created automatically before any file is overwritten during capture operations
  - The rotation system keeps the last 10 backups per file
  - Backups are stored in the `backup/` directory with timestamps
  - Filename format: `YYYYMMDD_HHMMSS_hostname-command.txt`
  - Provides protection against accidental overwrites and enables historical configuration tracking
  - Allows recovery of older configurations if needed

- **Difference Computation:**
  The application compares corresponding files from the `origin` and `dest` directories using diff-match-patch:
  - **Inline View:** Presents the standard diff output.
  - **Side-by-Side View:** Displays the origin data on the left and the computed differences on the right.

  Diff results are converted into HTML files and saved in the `diff` directory.

- **Detailed Device View:**
  Access detailed information for each device through the `/host/<hostname>` endpoint.

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/nw-diff.git
   ```
2. **Navigate to the project directory:**
   ```bash
   cd nw-diff
   ```

3. **Install dependencies:**
   Ensure you have Python installed, then install the required packages:
   ```bash
   pip install -r requirements.txt
   ```
   Required packages include Flask, Netmiko, and diff-match-patch.

4. **Configure Environment Variables:**
   - Set the `DEVICE_PASSWORD` environment variable to provide the password needed for device connections:
     ```bash
     export DEVICE_PASSWORD=your_device_password
     ```
   - **Set the `NW_DIFF_API_TOKEN` environment variable to secure sensitive API endpoints** (capture, logs, export):
     ```bash
     export NW_DIFF_API_TOKEN=your_secure_random_token
     ```
     Generate a secure token with:
     ```bash
     python -c "import secrets; print(secrets.token_urlsafe(32))"
     ```

     **Important:** If `NW_DIFF_API_TOKEN` is not set, sensitive endpoints will be accessible without authentication (not recommended for production).

   - **(Optional) Set the `HOSTS_CSV` environment variable** to specify a custom location for the hosts inventory file:
     ```bash
     export HOSTS_CSV=/path/to/hosts.csv
     ```
     If not set, the application will use the default `hosts.csv` in the current directory.

     **Benefits:** Storing the hosts inventory outside the repository improves security by preventing accidental commits of sensitive data (IP addresses, usernames, device models). This is particularly useful for production deployments where the inventory can be mounted as a secret or configuration volume.

     **Container example:**
     ```bash
     docker run -v /secure/path/hosts.csv:/app/hosts.csv -e HOSTS_CSV=/app/hosts.csv ...
     ```

## Usage

### Running in Production Mode (Default)

By default, the application runs with Flask debug mode **disabled** for security:

1. **Run the Application:**
   ```bash
   python app.py
   ```
2. **Access the Application:**
   Open your browser and navigate to [http://localhost:5000](http://localhost:5000).

### Running in Development Mode

For local development, you can enable debug mode by setting the `APP_DEBUG` environment variable:

1. **Run with Debug Mode:**
   ```bash
   export APP_DEBUG=true
   python app.py
   ```
   Or run it inline:
   ```bash
   APP_DEBUG=true python app.py
   ```
2. **Access the Application:**
   Open your browser and navigate to [http://localhost:5000](http://localhost:5000).

**Note:** Debug mode should **never** be enabled in production environments as it can expose sensitive information and create security vulnerabilities.

### Interacting with Endpoints

#### Public Endpoints (No Authentication Required)
- **View Host List:** `/` (homepage)
- **View Detailed Device Info:** `/host/<hostname>`
- **Compare Files:** `/compare_files`

#### Protected Endpoints (Require Authentication)
The following endpoints require authentication via the `Authorization: Bearer <token>` header:
- **Capture Data:**
  - For origin data: `/capture/origin/<hostname>`
  - For destination data: `/capture/dest/<hostname>`
  - For all devices: `/capture_all/origin` or `/capture_all/dest`
- **View Logs:**
  - Web UI: `/logs`
  - API: `/api/logs`
- **Export Data:**
  - HTML export: `/export/<hostname>`
  - JSON API: `/api/export/<hostname>`

**Example using curl:**
```bash
curl -H "Authorization: Bearer your_token_here" http://localhost:5000/api/logs
```

**Note:** If `NW_DIFF_API_TOKEN` is not set, these endpoints will work without authentication (not recommended for production).

### Review Diff Results

The computed diff HTML files are stored in the `diff` directory for offline viewing.

## Development

1. **Install development dependencies:**
   ```bash
   pip install -r requirements.txt -r requirements-dev.txt
   ```

2. **Run security audit:**
   ```bash
   pip-audit -r requirements.txt -r requirements-dev.txt
   ```

3. **Format, lint, type check, and test:**
   ```bash
   black app.py tests nw_diff
   pylint app.py tests nw_diff
   mypy app.py nw_diff tests
   pytest
   ```

4. **Run pre-commit hooks:**
   ```bash
   pre-commit run --all-files
   ```
