
# ReversingLabs MISP Enrichment Module

Compiled version: 1.0.0
Compiled on: 2025-12-18

Purpose
-------

This compiled module provides ReversingLabs-driven enrichment for common IOCs (file hashes, domains,
IPs, and URLs). It is packaged as a single Python file (`rl_enrichment.py`) for easy deployment into MISP.

Schema Note
-----------

This release uses standard MISP object templates (`report`, `file`, `domain-ip`, `url`, etc.) with
ReversingLabs enrichment data in summary/comment fields and event tags. This ensures compatibility
with all MISP instances without requiring custom template registration.

Quick install
-------------

1. Copy `rl_enrichment.py` to your MISP modules directory (example path shown below).
2. Ensure the file is readable by the web server user (typically `www-data` or `apache`).
3. Restart the web server / PHP-FPM / misp-modules service if necessary.

### Linux (Native MISP)

```bash
sudo cp rl_enrichment.py /var/www/MISP/app/files/misp-modules/misp_modules/modules/expansion/
sudo chown www-data:www-data /var/www/MISP/app/files/misp-modules/misp_modules/modules/expansion/rl_enrichment.py
sudo systemctl restart apache2
```

### Docker (PowerShell)

```powershell
# Copy module into container
docker cp rl_enrichment.py <container_name>:/var/www/MISP/app/files/misp-modules/misp_modules/modules/expansion/

# Set permissions and restart
docker exec <container_name> chown www-data:www-data /var/www/MISP/app/files/misp-modules/misp_modules/modules/expansion/rl_enrichment.py
docker exec <container_name> supervisorctl restart misp-modules
```

### Docker (Bash)

```bash
# Copy module into container
docker cp rl_enrichment.py <container_name>:/var/www/MISP/app/files/misp-modules/misp_modules/modules/expansion/

# Set permissions and restart
docker exec <container_name> chown www-data:www-data /var/www/MISP/app/files/misp-modules/misp_modules/modules/expansion/rl_enrichment.py
docker exec <container_name> supervisorctl restart misp-modules
```

Verifying the module
--------------------

1. In the MISP web UI, go to `Administration -> Server Settings & Maintenance`
2. Click on the `Plugins` tab
3. Use the search/filter box and type `rl_` to find the ReversingLabs module settings
4. Confirm you see entries like `Plugin.Enrichment_rl_enrichment_enabled`

MISP Configuration
------------------

After installing the module, configure it in the MISP web interface:

1. Navigate to `Administration -> Server Settings & Maintenance`
2. Click on the `Plugins` tab
3. In the search/filter box, type `rl_` to find all ReversingLabs module settings
4. Configure the following settings:

| Setting | Description | Example |
|---------|-------------|---------|
| `Plugin.Enrichment_rl_enrichment_enabled` | Enable the module | `true` |
| `Plugin.Enrichment_rl_enrichment_api_url` | ReversingLabs API base URL |
| `Plugin.Enrichment_rl_enrichment_api_token` | Your ReversingLabs API token | `your-api-token-here` |
| `Plugin.Enrichment_rl_enrichment_verify_ssl` | Enable SSL certificate verification | `true` |

> **Note for Docker users behind corporate proxies:** Some users have experienced SSL certificate errors when their corporate endpoint security blocks requests with unsigned or unrecognized certificates. Workarounds include:
> - Using `http://` URL/port instead of `https://` and setting `verify_ssl` to `false`
> - If your organization uses a corporate proxy with certificate inspection, you may need to provide the corporate CA certificate (`.pem` file) to the container

5. To edit a setting, **double-click on the setting name** (the left column), not the value. This opens an input field where you can enter the new value.
6. Press Enter or click outside the field to save the change

### Docker Environment Variables

For MISP-Docker deployments, you can also configure credentials via environment variables in your `docker-compose.yml`:

```yaml
services:
  misp:
    environment:
      - MISP_MODULE_RL_API_URL=your-spectra-analyze-a1000-endpoint-url
      - MISP_MODULE_RL_API_TOKEN=your-api-token-here
```

### Testing the Configuration

1. Go to an event containing a file hash, domain, IP, or URL attribute
2. Click on the attribute and select `Enrich` or use the enrichment popup
3. Select `rl_enrichment` from the available modules
4. Verify that enrichment results are returned

Troubleshooting
---------------

### Checking Logs

When something goes wrong, logs are your first stop for diagnosing issues.

**Native MISP Installation:**

```bash
# MISP application logs
sudo tail -f /var/www/MISP/app/tmp/logs/error.log
sudo tail -f /var/www/MISP/app/tmp/logs/debug.log

# MISP modules service logs
sudo journalctl -u misp-modules -f

# Web server logs
sudo tail -f /var/log/apache2/misp_error.log
```

**Docker Installation:**

```bash
# View MISP modules logs
docker exec <container_name> tail -f /var/log/misp-modules.log

# View all MISP logs
docker logs <container_name> -f

# Check supervisord status
docker exec <container_name> supervisorctl status
```

### Validating the Module File

If the module isn't loading, verify the file is syntactically correct:

```bash
# Check for Python syntax errors
python3 -m py_compile rl_enrichment.py

# Check for common issues with pyflakes
python3 -m pyflakes rl_enrichment.py
```

### Common Issues

| Symptom | Likely Cause | Solution |
|---------|--------------|----------|
| Module not listed in MISP | File permissions or location | Verify file is in the correct directory and readable by `www-data` |
| "Import error" in logs | Missing Python dependency | Check logs for the specific module; install with pip if needed |
| Module loads but enrichment fails | API configuration issue | Verify `api_url` and `api_token` in Plugin settings (see MISP Configuration above) |
| "Connection refused" | Wrong API URL or network issue | Confirm URL is reachable from the MISP server |
| "SSL certificate verify failed" | Self-signed or expired cert | Set `Plugin.Enrichment_rl_enrichment_verify_ssl` to `false` in Plugin settings, or fix the certificate chain |

### Restarting Services

After making changes, restart the relevant services:

**Native MISP:**
```bash
sudo systemctl restart misp-modules
sudo systemctl restart apache2
```

**Docker:**
```bash
docker exec <container_name> supervisorctl restart misp-modules
```

Testing Your Configuration
--------------------------

After configuring the module, verify it's working correctly:

### Quick Test via Attribute Enrichment

1. Navigate to any event containing a file hash (MD5, SHA1, or SHA256), domain, IP address, or URL
2. Click on the attribute to open the attribute details
3. Click the **Enrich** button (or right-click and select "Enrich")
4. Select **rl_enrichment** from the list of available modules
5. If configured correctly, you'll see ReversingLabs threat intelligence data returned

### Testing via the Modules Admin Page

You can also test directly from the admin interface:

1. Go to `Administration -> List Modules`
2. Find `rl_enrichment` in the module list
3. Click the module name to open its details
4. Use the **Test** button to send a sample query
5. Enter a known file hash (e.g., a SHA256) and verify you get results

### Common Issues

| Symptom | Likely Cause | Solution |
|---------|--------------|----------|
| Module not listed | File not copied correctly | Verify file exists in expansion modules directory |
| "Connection refused" | Wrong `api_url` | Check URL matches your ReversingLabs instance |
| "401 Unauthorized" | Invalid `api_token` | Regenerate and update your API token |
| "SSL certificate error" | Self-signed cert | Set `Plugin.Enrichment_rl_enrichment_verify_ssl` to `false` in Plugin settings (not recommended for production) |
| Empty results | IOC not in ReversingLabs database | Try a known malicious hash for testing |

> **Tip:** All module settings are found in `Administration -> Server Settings & Maintenance -> Plugins` tab. Filter by `rl_` to find ReversingLabs settings.

Trying MISP with Docker
-----------------------

If you don't have a MISP instance yet, you can quickly set one up using MISP Docker:

### Quick Start

```bash
# Clone the official MISP Docker repository
git clone https://github.com/MISP/misp-docker.git
cd misp-docker

# Copy the example environment file
cp template.env .env

# Start MISP (first run takes several minutes)
docker compose up -d
```

### Accessing MISP

Once running, access MISP at: **https://127.0.0.1** (or **http://127.0.0.1** depending on your configuration)

> **Note:** The port depends on your `docker-compose.yml` configuration (default is 443 for HTTPS, 80 for HTTP).

- Default credentials: `admin@admin.test` / `admin`
- Accept the self-signed certificate warning in your browser

### Installing the Module

With MISP Docker running, deploy the ReversingLabs module:

```bash
# Find your container name
docker ps --format '{{.Names}}' | grep misp

# Copy and install the module
docker cp rl_enrichment.py <container_name>:/var/www/MISP/app/files/misp-modules/misp_modules/modules/expansion/
docker exec <container_name> chown www-data:www-data /var/www/MISP/app/files/misp-modules/misp_modules/modules/expansion/rl_enrichment.py
docker exec <container_name> supervisorctl restart misp-modules
```

For more information, see the official MISP Docker repository: https://github.com/MISP/misp-docker

Generated By 
-------

This module was generated by the internal ReversingLabs MISP Builder tool.
For changes to mapping behavior or templates, please contact helpdesk@reversinglabs.com.