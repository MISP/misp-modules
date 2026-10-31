"""Publish a query pack to a server-configured directory for filesystem deployments."""

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path

from misp_modules.lib.osquery import boolean, build, serialize

moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "OSQuery Pack Publish",
    "description": "Publish a MISP query pack to a configured local osquery pack directory.",
    "module-type": ["action"],
    "logo": "osquery.png",
    "requirements": ["OSQUERY_PACK_DIRECTORY on the module server; filesystem pack distribution and config reload"],
    "features": (
        "Atomically publishes a named pack under OSQUERY_PACK_DIRECTORY. Defaults to dry run; existing packs require"
        " explicit overwrite. Reuses the export's platform selectors, IDS filtering and bounded scan paths."
        " Publication does not execute queries or reload osquery. See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/action_mod/osquery_pack_publish.md)."
    ),
    "references": ["https://osquery.readthedocs.io/en/stable/deployment/configuration/#query-packs"],
    "input": "Selected MISP events and object attributes in workflow data.",
    "output": "Publication status, pack content, counts, provenance and content SHA-256.",
}
moduleconfig = {
    "params": {
        "pack_name": {"type": "string", "description": "Required: pack basename, letters/digits/_/- only"},
        "interval": {"type": "string", "description": "Query interval in seconds", "value": "3600"},
        "scan_path": {"type": "string", "description": "Absolute osquery file path pattern for file scans"},
        "dry_run": {"type": "string", "description": "Preview without writing files", "value": "true"},
        "overwrite": {
            "type": "string",
            "description": "Replace the complete named pack with this snapshot",
            "value": "false",
        },
    },
    "blocking": True,
    "support_filters": False,
    "expect_misp_core_format": True,
}
returns = "data"


def _publish(filename, content, overwrite):
    directory = Path(os.getenv("OSQUERY_PACK_DIRECTORY", ""))
    if not directory.is_absolute() or not directory.is_dir():
        raise ValueError("Configure OSQUERY_PACK_DIRECTORY as an existing absolute directory on the module server.")
    target = directory / filename
    if target.is_symlink():
        raise ValueError("Refusing to publish over a symlink.")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=directory, prefix=".misp-pack-", delete=False) as output:
            temporary = output.name
            os.fchmod(output.fileno(), 0o640)
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        if overwrite:
            os.replace(temporary, target)
        else:
            # An atomic no-clobber create, including when another workflow writes concurrently.
            os.link(temporary, target)
    except FileExistsError:
        raise ValueError("Pack already exists; set overwrite=true to replace its complete contents.") from None
    finally:
        if temporary is not None and os.path.exists(temporary):
            os.unlink(temporary)


def handler(q=False):
    if not q:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ValueError("Request must be an object.")
        if "filteredItems" in request or "matchingData" in request:
            raise ValueError("Workflow filters/extracted data are unsupported; supply selected events in data.")
        params = request.get("params", {})
        if not isinstance(params, dict):
            raise ValueError("params must be an object.")
        name = params.get("pack_name")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", name):
            raise ValueError("pack_name must be 1-64 letters, digits, _ or -, starting with a letter or digit.")
        dry_run_setting = params.get("dry_run")
        dry_run = boolean("true" if dry_run_setting in (None, "") else dry_run_setting, "dry_run")
        overwrite = boolean(params.get("overwrite"), "overwrite")
        # Workflow actions only publish IDS-marked attributes.
        pack, summary, sources = build(
            request.get("data"),
            {
                "interval": params.get("interval"),
                "scan_path": params.get("scan_path"),
            },
        )
        if not pack["queries"]:
            raise ValueError("No eligible queries; refusing to publish an empty pack.")
        content = serialize(pack)
        filename = f"misp-{name}.conf"
        if not dry_run:
            _publish(filename, content, overwrite)
    except (ValueError, TypeError) as exc:
        return {"error": f"osquery pack publish: {exc}"}
    except OSError:
        return {"error": "osquery pack publish: filesystem write failed; check server permissions and pack state."}
    return {
        "result_key": "osquery_pack_publish",
        "data": {
            "success": True,
            "status": "planned" if dry_run else "published",
            "filename": filename,
            "sha256": hashlib.sha256(content).hexdigest(),
            "pack": pack,
            "summary": summary,
            "sources": sources,
            "activation": "Distribute the pack and reload osquery configuration; publication does not execute queries.",
        },
    }


def introspection():
    return {"config": moduleconfig}


def version():
    return dict(moduleinfo, config=moduleconfig)
