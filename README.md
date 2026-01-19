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

### Local Development (HTTP on 127.0.0.1:5000)

For single-user local development, run Flask directly without Docker:

1. **Set Environment Variables:**
   ```bash
   export DEVICE_PASSWORD=your_device_password
   export APP_DEBUG=false  # Set to true only for development
   # Optional: Set NW_DIFF_API_TOKEN for authentication
   export NW_DIFF_API_TOKEN=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
   ```

2. **Run the Application:**
   ```bash
   python app.py
   ```
   
   The Flask application will start on `http://127.0.0.1:5000` by default.

3. **Access the Application:**
   Open your browser and navigate to [http://127.0.0.1:5000](http://127.0.0.1:5000).

**Note:** Debug mode should **never** be enabled in production environments as it can expose sensitive information and create security vulnerabilities.

### Docker Deployment with HTTPS and Basic Authentication

For production deployment or when sharing with others, use Docker with nginx as a reverse proxy:

#### Prerequisites

1. **Generate Self-Signed Certificate** (for testing) or use Let's Encrypt certificates:
   ```bash
   mkdir -p certs
   openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
     -keyout certs/privkey.pem \
     -out certs/fullchain.pem \
     -subj "/CN=localhost"
   ```

   **For production:** Use Let's Encrypt certificates instead:
   ```bash
   # Install certbot and obtain certificates
   sudo certbot certonly --standalone -d your-domain.com
   # Copy certificates to certs/ directory
   sudo cp /etc/letsencrypt/live/your-domain.com/fullchain.pem certs/
   sudo cp /etc/letsencrypt/live/your-domain.com/privkey.pem certs/
   ```

2. **Generate .htpasswd File for Basic Authentication:**
   ```bash
   mkdir -p nginx
   docker run --rm httpd:2.4 htpasswd -nbB admin your_password > nginx/.htpasswd
   ```
   
   Replace `admin` and `your_password` with your desired credentials.

3. **Create Environment File** (optional but recommended):
   ```bash
   cat > .env << 'EOF'
   NW_DIFF_API_TOKEN=your_secure_token_here
   NW_DIFF_BASIC_USER=admin
   NW_DIFF_BASIC_PASSWORD_HASH=$2y$05$...  # bcrypt hash from htpasswd
   DEVICE_PASSWORD=your_device_password
   EOF
   chmod 600 .env
   ```

#### Start the Services

```bash
docker-compose up -d
```

The application will be available at `https://localhost` (or your domain).

#### Access the Application

1. Open your browser and navigate to `https://localhost` (or your domain)
2. Accept the self-signed certificate warning (for testing only)
3. Enter Basic authentication credentials when prompted
4. You can now use the application

#### Stop the Services

```bash
docker-compose down
```

### Authentication Methods

The application supports multiple authentication methods for protected endpoints:

#### 1. Bearer Token Authentication (API Clients)

Set the `NW_DIFF_API_TOKEN` environment variable and use the `Authorization: Bearer <token>` header:

```bash
curl -H "Authorization: Bearer your_token_here" https://localhost/api/logs
```

#### 2. Basic Authentication (Browser/API)

Configure Basic authentication credentials via environment variables:

**Using Hashed Password (Recommended):**
```bash
export NW_DIFF_BASIC_USER=admin
export NW_DIFF_BASIC_PASSWORD_HASH='$2y$05$...'  # bcrypt hash
```

**Using Plaintext Password (Development Only):**
```bash
export NW_DIFF_BASIC_USER=admin
export NW_DIFF_BASIC_PASSWORD=secret
```

**API Usage:**
```bash
curl -u admin:secret https://localhost/api/logs
```

**Note:** If `NW_DIFF_API_TOKEN` is not set, authentication is not enforced (not recommended for production).

### Interacting with Endpoints

#### Public Endpoints (No Authentication Required)
- **View Host List:** `/` (homepage)
- **View Detailed Device Info:** `/host/<hostname>`
- **Compare Files:** `/compare_files`

#### Protected Endpoints (Require Authentication)
The following endpoints require authentication via Bearer token or Basic authentication:
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

**Example using Bearer token:**
```bash
curl -H "Authorization: Bearer your_token_here" https://localhost/api/logs
```

**Example using Basic auth:**
```bash
curl -u admin:password https://localhost/api/logs
```

**Note:** If `NW_DIFF_API_TOKEN` is not set, these endpoints will work without authentication (not recommended for production).

### Security Considerations

#### For Production Deployments

1. **Use HTTPS:** Always use HTTPS in production. Never expose the application over HTTP when accessible from the network.

2. **Use Let's Encrypt:** Replace self-signed certificates with Let's Encrypt or other trusted CA certificates.

3. **Use Hashed Passwords:** Always use `NW_DIFF_BASIC_PASSWORD_HASH` (bcrypt) instead of `NW_DIFF_BASIC_PASSWORD` (plaintext).

4. **Strong Credentials:** Use strong, randomly generated passwords:
   ```bash
   python -c "import secrets; print(secrets.token_urlsafe(32))"
   ```

5. **Network Security:** Use firewall rules to restrict access to trusted networks.

6. **Regular Updates:** Keep Docker images, Python packages, and system libraries up to date.

7. **Environment Variables:** Never commit `.env` files or credentials to version control.

8. **Nginx Basic Auth:** The nginx layer provides an additional Basic authentication layer for defense in depth.

#### Development vs Production

- **Development:** Can use HTTP on 127.0.0.1 without authentication
- **Production/Sharing:** Must use HTTPS with both nginx Basic auth and application Bearer/Basic auth

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
