# MISP Modules Website

Use all MISP modules through a dedicated website without requiring a MISP instance.

![Home](https://github.com/MISP/misp-modules/blob/main/website/doc/home_misp_module.png?raw=true)

![Query](https://github.com/MISP/misp-modules/blob/main/website/doc/query_misp_module.png?raw=true)

See the [interface guide](doc/interface.md) for design references, asset builds,
and browser regression tests.

## Import modules

Choose **Import data** in the sidebar to test an active import module without a
MISP instance. Select a module, then upload a file or paste text according to its
supported input sources (up to 20 MiB). Modules that retrieve remote reports show
their configuration fields instead of a file input.

The form displays the module's import options, including boolean defaults and
required fields. Saved module settings are used automatically; **Override module
settings** supplies values for this run. An administrator can enable modules and
configure shared settings under **Module configuration**.

Imports open in the same results view as enrichments, with visual, JSON, and
Markdown views, downloads, and session history. Use **Choose modules** on an
imported attribute to start an enrichment. To repeat an import, choose **New
import** and provide the input again; the website does not retain uploaded input
for replay. Import results may themselves contain attachments supplied by a module.

## Export modules

Choose **Export data** in the sidebar, select an active export module, and upload
a MISP JSON file (up to 20 MiB) or choose an event from the **CIRCL OSINT** feed.
The feed picker searches event titles and UUIDs and paginates the feed manifest.
Feed access happens on the website server and requires outbound HTTPS access to
`www.circl.lu`. Feed failures can be retried without losing module options.

Standard `Event` JSON, bare events, lists, and `response` event collections are
accepted. Modules advertising single-event input reject collections. Module
options and saved settings work like imports, including per-run overrides.

When `ADMIN_PASSWORD` is configured, log in as the administrator to run exports
and access export results or downloads, including previously saved exports.
Export execution settings are not retained in browser-session trees or saved
history. The FireSIGHT script exporter always receives login/password placeholders
instead of saved or submitted credentials; add credentials to the script after
downloading it. Other module settings still use their configured defaults.

Exports open in the results view and session history. Text files have an escaped
preview; binary files have a download action. **Download** retrieves the original
decoded output with the module's file extension; **Download JSON** retrieves the
response envelope. Long previews are shortened without changing the download.
Use **New export** to run another module or provide another event. Uploaded input
is not saved for replay. Some export modules contact external services according
to their description and configuration.

Supported feed endpoints are explicitly registered in `app/export_core.py`.
To add another public MISP JSON feed, add its HTTPS base URL to `FEEDS`; it must
provide `manifest.json` and UUID-named event JSON files. Responses are bounded,
manifests are cached for five minutes, and redirects are rejected.

## Installation

The MISP Modules website uses [Poetry](https://python-poetry.org/) for dependency management. It is recommended to install dependencies in a virtual environment managed by Poetry.

### Prerequisites
- Python 3.10 or higher
- Poetry

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
   poetry run mmw db init
   ```
   This creates the database (`misp-module.sqlite`), initializes modules, and sets up the admin password (generated in development if not set).

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
poetry run mmw dev
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
poetry run mmw db init     # Initialize database and modules
poetry run mmw db migrate   # Generate a new migration
poetry run mmw db upgrade   # Apply migrations
poetry run mmw db downgrade # Revert the latest migration
```

### Updating an existing installation

After updating the code and installing dependencies, stop the website, back up
its database, and apply migrations before restarting it. Run this from `website/`
with the same `.env` / `DATABASE_URI` as the running service:

```bash
poetry install
poetry run mmw db upgrade
```

Only restart the website if the upgrade succeeds. `db migrate` generates migration
files for developers; it does not apply the migrations shipped with an update.
Likewise, `db init` creates missing tables but does not add columns to existing ones.

If `/external_tools/list` fails with `no such column: external_tools.api_key`,
run the upgrade above. It repairs the missing column and index even if the legacy
API-key migration was already recorded as applied, preserving existing tools,
API keys, and query history. Existing tools without a key will need one configured
on the **External tools** page before use.

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
