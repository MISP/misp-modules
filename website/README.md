# MISP Modules Website

Use all MISP modules through a dedicated website without requiring a MISP instance.

![Home](https://github.com/MISP/misp-modules/blob/main/website/doc/home_misp_module.png?raw=true)

![Query](https://github.com/MISP/misp-modules/blob/main/website/doc/query_misp_module.png?raw=true)

## Installation

The MISP Modules website uses [Poetry](https://python-poetry.org/) for dependency management. It is recommended to install dependencies in a virtual environment managed by Poetry.

### Prerequisites
- Python 3.8 or higher
- Poetry
- `misp-modules` installed in the parent directory (`../`)

### Steps
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/MISP/misp-modules.git
   cd misp-modules/website
   ```

2. **Initialize Submodules**:
   ```bash
   git submodule init
   git submodule update  # Initialize misp-objects submodule
   ```

3. **Install Dependencies**:
   ```bash
   poetry install
   ```

4. **Initialize the Database**:
   ```bash
   poetry run db-init
   ```
   This creates the database (`misp-module.sqlite`), initializes modules, and sets up the admin password (generated in development if not set).

5. **Install `misp-modules`**:
   Ensure `misp-modules` is installed in the parent directory (`../misp-modules`). Follow the main repository’s instructions for setup.

## Configuration

Configuration is managed via a `.env` file in `website/`. Copy the example and edit as needed:

```bash
cp .env.example .env
nano .env
```

### `.env` Settings
- `DATABASE_URI`: Database URL (default: `sqlite:///misp-module.sqlite`).
- `SECRET_KEY`: Secure key for the Flask app (generate with `python -c "import secrets; print(secrets.token_hex(16))"` or `openssl rand -hex 16`).
- `FLASK_URL`: Host for the website (default: `127.0.0.1`).
- `FLASK_PORT`: Port for the website (default: `7008`).
- `MISP_MODULE`: URL and port of `misp-modules` (default: `127.0.0.1:6666`).
- `ADMIN_PASSWORD`: Admin user password (optional in development, required in production).
- `QUERIES_LIMIT`: Maximum queries allowed (default: `100`).
- `SESSION_TYPE`: Session storage type (default: `sqlalchemy`).
- `SESSION_SQLALCHEMY_TABLE`: Session table name (default: `flask_sessions`).
- `FLASK_APP`: Flask entry point (default: `main`).

Example `.env`:
```
DATABASE_URI=sqlite:///misp-module.sqlite
SECRET_KEY=your-secure-secret-key
FLASK_URL=127.0.0.1
FLASK_PORT=7008
MISP_MODULE=127.0.0.1:6666
QUERIES_LIMIT=100
SESSION_TYPE=sqlalchemy
SESSION_SQLALCHEMY_TABLE=flask_sessions
FLASK_APP=main
# ADMIN_PASSWORD=your-admin-password  # Uncomment and set for production
```

## Launch

### Development
Run both `misp-modules` and the website in development mode with debug enabled:

```bash
poetry run dev-site
```

- If `ADMIN_PASSWORD` is unset in `.env`, a random 20-character password is generated and printed.
- Access the website at `http://127.0.0.1:7008` (or as configured).

### Production
Use systemd services for production deployment (see **Systemd Services** below). Ensure `ADMIN_PASSWORD` is set in `.env` to avoid startup errors.

## Admin User

If `ADMIN_PASSWORD` is set in `.env`, the admin user is active. Access the login page at `/login` and use the password from `.env` (or the generated password in development).

- **Development**: If `ADMIN_PASSWORD` is unset, a password is generated and printed to the console.
- **Production**: `ADMIN_PASSWORD` must be set in `.env`, or the application will fail to start with an error.

## Database Management

Manage the database with the following commands:

```bash
poetry run db-init      # Initialize database and modules
poetry run db-migrate   # Generate a new migration
poetry run db-upgrade   # Apply migrations
poetry run db-downgrade # Revert the latest migration
```

## Systemd Services

Template systemd service files are provided in `etc/` for `misp-modules` and the website.

### Installation
1. **Copy Service Files**:
   ```bash
   sudo cp website/etc/misp-modules.service /etc/systemd/system/
   sudo cp website/etc/misp-modules-website.service /etc/systemd/system/
   ```

2. **Reload Systemd**:
   ```bash
   sudo systemctl daemon-reload
   ```

3. **Enable and Start Services**:
   ```bash
   sudo systemctl enable misp-modules.service
   sudo systemctl enable misp-modules-website.service
   sudo systemctl start misp-modules.service
   sudo systemctl start misp-modules-website.service
   ```

4. **Check Status**:
   ```bash
   sudo systemctl status misp-modules.service
   sudo systemctl status misp-modules-website.service
   ```

Logs are written to `/var/log/misp-modules_*.log` and `/var/log/misp-modules-website_*.log`.

## Log Rotation

Log rotation configurations are provided in `etc/logrotate.d/` to manage service logs.

### Installation
1. **Copy Logrotate Files**:
   ```bash
   sudo cp etc/logrotate.d/misp-modules /etc/logrotate.d/
   ```

2. **Test Logrotate**:
   ```bash
   sudo logrotate -d /etc/logrotate.d/misp-modules
   ```

Logs are rotated daily, compressed, and retained for 7 days.

## Notes
- Ensure `misp-modules` is installed and running in `../misp-modules`.
- Set a secure `ADMIN_PASSWORD` in `.env` for production.
- Adjust `.service` and `logrotate.d` paths or user settings for your environment.