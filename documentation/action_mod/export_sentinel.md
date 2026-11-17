# Export to Microsoft Sentinel or Defender

This action invokes an existing MISP2Sentinel or MISP2Defender installation with
the event UUID. The module server operator chooses the installation; workflow
requests cannot select an interpreter or script.

Configure these variables in the environment of the **misp-modules service**:

```sh
EXPORT_SENTINEL_VENV=/var/www/MISP/misp-custom/misp2sentinel/venv
EXPORT_SENTINEL_SCRIPT=/var/www/MISP/misp-custom/misp2sentinel/script.py
```

Both paths must be absolute. The virtual environment must contain an executable
`bin/python`, and the script must be a readable regular file. Normal virtual
environment interpreter symlinks are supported. The script's parent directory
is used as the working directory, so existing exporter configuration still works.

The service environment, interpreter, exporter, dependencies, configuration and
their parent directories must be controlled by a trusted operating system
administrator. MISP users and the module service account should not have write
access to this code. The exporter still runs with the module service's privileges;
this change does not sandbox it.

Restart the module service after changing its environment. The action fails
without running a process when either setting is absent or invalid. It has no
default installation and never falls back to request-supplied paths.

## Migration from version 0.1

Move the existing `misp2_venv` and `misp2_script` values into the service environment
as shown above, then remove those parameters from existing workflows. Requests
that still contain either legacy key in `params` or `config` fail, including when
the server environment is configured. This makes stale configurations visible
instead of silently using a different installation.

The event UUID is validated and normalized before being passed as a single
argument to the exporter. Execution uses an argument list without a shell and
retains the existing 300-second timeout and `{"data": true/false}` result format.
