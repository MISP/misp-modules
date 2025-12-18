# INSTALL

Follow these steps to install the compiled ReversingLabs enrichment module into MISP.

## Linux (Native MISP)

1. Copy the compiled `rl_enrichment.py` into your MISP modules directory:

```bash
sudo cp rl_enrichment.py /var/www/MISP/app/files/misp-modules/misp_modules/modules/expansion/
```

2. Set ownership and permissions so the webserver can read the file:

```bash
sudo chown www-data:www-data /var/www/MISP/app/files/misp-modules/misp_modules/modules/expansion/rl_enrichment.py
sudo chmod 644 /var/www/MISP/app/files/misp-modules/misp_modules/modules/expansion/rl_enrichment.py
```

3. Restart web services:

```bash
sudo systemctl restart apache2
# or for php-fpm setups
sudo systemctl restart php8.1-fpm
```

## Docker (MISP-Docker)

1. Copy the module into the running container:

**PowerShell:**
```powershell
docker cp rl_enrichment.py <container_name>:/var/www/MISP/app/files/misp-modules/misp_modules/modules/expansion/
```

**Bash:**
```bash
docker cp rl_enrichment.py <container_name>:/var/www/MISP/app/files/misp-modules/misp_modules/modules/expansion/
```

2. Set permissions inside the container:

**PowerShell:**
```powershell
docker exec <container_name> chown www-data:www-data /var/www/MISP/app/files/misp-modules/misp_modules/modules/expansion/rl_enrichment.py
docker exec <container_name> chmod 644 /var/www/MISP/app/files/misp-modules/misp_modules/modules/expansion/rl_enrichment.py
```

**Bash:**
```bash
docker exec <container_name> chown www-data:www-data /var/www/MISP/app/files/misp-modules/misp_modules/modules/expansion/rl_enrichment.py
docker exec <container_name> chmod 644 /var/www/MISP/app/files/misp-modules/misp_modules/modules/expansion/rl_enrichment.py
```

3. Restart the MISP modules service inside the container:

**PowerShell:**
```powershell
docker exec <container_name> supervisorctl restart misp-modules
```

**Bash:**
```bash
docker exec <container_name> supervisorctl restart misp-modules
```

4. Verify the module is available in the MISP UI under `Administration -> List Modules` and review logs for any
	import or runtime errors.

Notes
-----

- The compiled header contains version and date metadata: `v=1.0.0|d=2025-12-18|...`. Keep this for troubleshooting.
- If you maintain multiple MISP instances, you can distribute the `public/` folder from the `dist/<version>` output.
