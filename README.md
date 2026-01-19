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

   - **(Optional) Configure HTTP Basic Authentication** for browser-based access to protected endpoints:
     ```bash
     export NW_DIFF_BASIC_USER=your_username
     ```

     For **production**, use a hashed password (recommended):
     ```bash
     # Generate password hash using Python
     python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('your_password'))"
     export NW_DIFF_BASIC_PASSWORD_HASH='<generated_hash>'
     ```

     For **development only**, you can use a plain password (not recommended for production):
     ```bash
     export NW_DIFF_BASIC_PASSWORD=your_plain_password
     ```

     **Note:** Basic Authentication is only enforced when `NW_DIFF_API_TOKEN` is set. Both Bearer token (`Authorization: Bearer <token>`) and Basic auth (`Authorization: Basic <base64(user:pass)>`) will be accepted for protected endpoints.

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

### Running Modes Overview

The application supports two primary running modes:

1. **Local Development Mode**: Binds to `127.0.0.1:5000` (localhost only) for single-user development and testing. This is the secure default.
2. **Container/Production Mode**: Binds to `0.0.0.0:5000` to allow access from the container network or reverse proxy (nginx). Required for Docker deployments.

The application includes **ProxyFix middleware** to correctly handle `X-Forwarded-*` headers from reverse proxies (nginx, etc.), ensuring proper URL generation, HTTPS detection, and client IP logging when deployed behind a proxy.

### Running in Production Mode (Default)

By default, the application runs with Flask debug mode **disabled** for security and binds to **127.0.0.1** (localhost only):

1. **Run the Application:**
   ```bash
   python run_app.py
   ```
   Or directly from the source:
   ```bash
   PYTHONPATH=src python -m nw_diff.app
   ```
2. **Access the Application:**
   Open your browser and navigate to [http://localhost:5000](http://localhost:5000).

### Running in Development Mode

For local development, you can enable debug mode by setting the `APP_DEBUG` environment variable:

1. **Run with Debug Mode:**
   ```bash
   export APP_DEBUG=true
   python run_app.py
   ```
   Or run it inline:
   ```bash
   APP_DEBUG=true python run_app.py
   ```
2. **Access the Application:**
   Open your browser and navigate to [http://localhost:5000](http://localhost:5000).

**Note:** Debug mode should **never** be enabled in production environments as it can expose sensitive information and create security vulnerabilities.

### Customizing Bind Host and Port

You can customize the bind host and port using environment variables:

- `FLASK_RUN_HOST`: Host to bind to (default: `127.0.0.1` for local dev)
- `FLASK_RUN_PORT`: Port to bind to (default: `5000`)

**Examples:**

```bash
# Bind to all interfaces (useful for container environments)
FLASK_RUN_HOST=0.0.0.0 python run_app.py

# Use a different port
FLASK_RUN_PORT=8080 python run_app.py

# Combine multiple settings
FLASK_RUN_HOST=0.0.0.0 FLASK_RUN_PORT=8080 APP_DEBUG=false python run_app.py
```

**Security Note:** When running locally without a reverse proxy, use the default `127.0.0.1` to prevent unauthorized network access. Only use `0.0.0.0` in container environments or when behind a properly configured reverse proxy with authentication.

### Interacting with Endpoints

#### Public Endpoints (No Authentication Required)
- **View Host List:** `/` (homepage)
- **View Detailed Device Info:** `/host/<hostname>`
- **Compare Files:** `/compare_files`

#### Protected Endpoints (Require Authentication)
The following endpoints require authentication when `NW_DIFF_API_TOKEN` is set. Both Bearer token and Basic authentication are supported:
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

**Example using curl with Bearer token:**
```bash
curl -H "Authorization: Bearer your_token_here" http://localhost:5000/api/logs
```

**Example using curl with Basic authentication:**
```bash
curl -u username:password http://localhost:5000/api/logs
```

**Example using browser:**
When accessing protected endpoints in a browser, you'll be prompted for username and password if Basic Authentication is configured. The browser will automatically encode credentials as Basic auth headers.

**Note:** If `NW_DIFF_API_TOKEN` is not set, these endpoints will work without authentication (not recommended for production).

### Review Diff Results

The computed diff HTML files are stored in the `diff` directory for offline viewing.

## Docker Deployment

NW-Diff supports containerized deployment with HTTPS (TLS termination) and optional Basic Authentication via Docker and docker-compose. This provides a secure, production-ready deployment option.

**Architecture Overview:**
- **nginx**: Acts as a reverse proxy with TLS termination, sets `X-Forwarded-*` headers
- **Flask app**: Runs with ProxyFix middleware to correctly interpret forwarded headers
- **Container binding**: Flask binds to `0.0.0.0:5000` inside the container (set via `FLASK_RUN_HOST`)
- **Network isolation**: Only nginx is exposed to the host; Flask app is accessible only within the Docker network

The ProxyFix middleware ensures that the Flask app correctly detects the original request protocol (HTTPS), host, and client IP when running behind the nginx reverse proxy.

### Prerequisites

- Docker and Docker Compose installed
- OpenSSL (for generating self-signed certificates)
- Apache Utils (for generating htpasswd file) - `apt-get install apache2-utils` or `yum install httpd-tools`

### Quick Start

1. **Clone the repository and navigate to project directory:**
   ```bash
   git clone https://github.com/icecake0141/nw-diff.git
   cd nw-diff
   ```

2. **Set up environment variables:**
   ```bash
   cp .env.example .env
   # Edit .env and set DEVICE_PASSWORD and NW_DIFF_API_TOKEN
   ```

3. **Generate TLS certificates (self-signed for development):**
   ```bash
   ./scripts/mk-certs.sh
   # Follow prompts to generate certificates
   # Or specify hostname: CERT_HOSTNAME=myserver.example.com ./scripts/docker-setup.sh
   ```

4. **Generate Basic Authentication credentials:**
   ```bash
   ./scripts/mk-htpasswd.sh
   # Follow prompts to create username/password
   ```

5. **Create hosts.csv inventory file:**
   ```bash
   cp hosts.csv.sample hosts.csv
   # Edit hosts.csv with your device information
   ```

6. **Start the application stack:**
   ```bash
   docker-compose up -d
   ```

7. **Access the application:**
   - HTTPS: `https://localhost/` (you'll need to accept the self-signed certificate warning)
   - You'll be prompted for Basic Auth credentials

8. **View logs:**
   ```bash
   docker-compose logs -f
   ```

9. **Stop the application:**
   ```bash
   docker-compose down
   ```

### Configuration

#### Environment Variables

Set these in your `.env` file:

- `DEVICE_PASSWORD`: Password for SSH connections to network devices
- `NW_DIFF_API_TOKEN`: Secure token for API authentication (generate with `python -c "import secrets; print(secrets.token_urlsafe(32))"`)
- `NW_DIFF_BASIC_USER`: (Optional) Username for HTTP Basic Authentication
- `NW_DIFF_BASIC_PASSWORD_HASH`: (Optional) Hashed password for Basic Authentication (generate with `python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('password'))"`)
- `NW_DIFF_BASIC_PASSWORD`: (Optional) Plain password for Basic Authentication (development only - use hashed password in production)
- `APP_DEBUG`: Set to `false` in production (default)
- `HOSTS_CSV`: Optional custom path to hosts inventory file

**Authentication Modes:**
- If `NW_DIFF_API_TOKEN` is not set: No authentication required (legacy mode)
- If `NW_DIFF_API_TOKEN` is set:
  - API clients can use Bearer token: `Authorization: Bearer <token>`
  - Browser users can use Basic auth: `Authorization: Basic <base64(user:pass)>`
  - Both methods are accepted for protected endpoints (capture, logs, export)

#### TLS/SSL Certificates

For **development/testing**, use the provided script to generate self-signed certificates:
```bash
./scripts/mk-certs.sh
```

For **production**, you should:
- Use certificates from a trusted Certificate Authority (CA), or
- Use Let's Encrypt with Caddy or certbot, or
- Mount your existing certificates:
  ```bash
  # Place your certificates in docker/certs/
  cp /path/to/your/cert.pem docker/certs/cert.pem
  cp /path/to/your/key.pem docker/certs/key.pem
  chmod 644 docker/certs/cert.pem
  chmod 600 docker/certs/key.pem
  ```

#### Basic Authentication

Basic Authentication is enabled by default for all endpoints. To manage users:

**Add a user:**
```bash
./scripts/mk-htpasswd.sh
```

**Add additional users:**
```bash
htpasswd docker/.htpasswd <username>
```

**Disable Basic Auth (not recommended for production):**
Edit `docker/nginx.conf` and comment out these lines:
```nginx
# auth_basic "NW-Diff Access";
# auth_basic_user_file /etc/nginx/.htpasswd;
```
Then restart: `docker-compose restart nginx`

#### Persistent Data

Docker volumes are used for persistent storage:
- `nw-diff-logs`: Application logs
- `nw-diff-dest`: Destination configuration snapshots
- `nw-diff-origin`: Origin configuration snapshots
- `nw-diff-diff`: Generated diff files
- `nw-diff-backup`: Configuration backups

To backup or migrate data:
```bash
# Backup volumes
docker run --rm -v nw-diff-logs:/data -v $(pwd):/backup alpine tar czf /backup/nw-diff-logs-backup.tar.gz -C /data .

# Restore volumes
docker run --rm -v nw-diff-logs:/data -v $(pwd):/backup alpine tar xzf /backup/nw-diff-logs-backup.tar.gz -C /data
```

### Security Best Practices

1. **Always use HTTPS in production** - HTTP is redirected to HTTPS by default
2. **Use strong passwords** - Both for Basic Auth and device credentials
3. **Keep API tokens secure** - Store `NW_DIFF_API_TOKEN` securely, never commit to version control
4. **Use trusted certificates in production** - Self-signed certificates are for development only
   - For production: Obtain certificates from Let's Encrypt, a commercial CA, or your organization's PKI
   - **IMPORTANT**: When using trusted certificates, enable HSTS by uncommenting the line in `docker/nginx.conf`:
     ```nginx
     add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
     ```
   - **WARNING**: Do NOT enable HSTS with self-signed certificates as it will cause browser issues
5. **Regularly update base images** - Keep Docker images up-to-date for security patches
6. **Review nginx logs** - Monitor for suspicious activity
7. **Limit network exposure** - Use firewall rules to restrict access to trusted networks

### Troubleshooting

**Certificate errors in browser:**
- Self-signed certificates will show warnings - this is expected for development
- Add exception in browser or import certificate to system trust store (see scripts/mk-certs.sh output)

**Connection refused:**
- Verify containers are running: `docker-compose ps`
- Check logs: `docker-compose logs`

**Authentication failures:**
- Verify .htpasswd file exists: `ls -la docker/.htpasswd`
- Test credentials: `htpasswd -v docker/.htpasswd <username>`

**Permission errors:**
- Ensure certificate files have correct permissions (cert.pem: 644, key.pem: 600)
- Check volume permissions: `docker-compose exec nw-diff ls -la /app`

**Docker build SSL certificate errors:**
- If building in a corporate/CI environment with SSL interception, use:
  ```bash
  docker build --build-arg SKIP_PIP_SSL_VERIFY=1 -t nw-diff:latest .
  ```
- This adds `--trusted-host` flags for PyPI domains during pip install
- **Note:** Only use this workaround in trusted environments; it bypasses SSL verification

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
   black src tests
   pylint src tests
   mypy src tests
   pytest
   ```

4. **Run pre-commit hooks:**
   ```bash
   pre-commit run --all-files
   ```
