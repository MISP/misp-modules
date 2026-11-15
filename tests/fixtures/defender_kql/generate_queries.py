"""Print representative exporter queries for the independent Microsoft KQL analyzer.

Run from the repository root: PYTHONPATH=. python tests/fixtures/defender_kql/generate_queries.py
"""

import base64
import json

from misp_modules.modules.export_mod import defender_endpoint_export as defender

attributes = [
    {"type": "sha256", "value": "a" * 64},
    {"type": "sha1", "value": "b" * 40},
    {"type": "md5", "value": "c" * 32},
    {"type": "domain", "value": "Example.ORG."},
    {"type": "domain", "value": "faß.de"},
    {"type": "url", "value": 'https://example.org/a\'\\b?q="c";|union%20DeviceEvents'},
    {"type": "url", "value": 'https://example.org/é/")]));print%20x=1;//'},
    {"type": "ip-src", "value": "192.0.2.1"},
    {"type": "ip-dst", "value": "192.0.2.2"},
    {"type": "ip-src", "value": "2001:db8::1"},
    {"type": "ip-dst", "value": "2001:0db8:0:0::2"},
]
configs = [
    {"tables": list(defender.TABLE_FIELDS)},
    {"tables": list(defender.TABLE_FIELDS), "domain_mode": "subdomains"},
    {"start_time": "2026-01-01T02:00:00+02:00", "end_time": "2026-01-02T00:00:00Z"},
    {"batch_size": 1},
    *({"tables": table} for table in defender.TABLE_FIELDS),
]
for config in configs:
    for items in [[item] for item in attributes] + [attributes]:
        result = defender.handler(json.dumps({"data": {"Attribute": items}, "config": config}))
        if "error" in result:
            raise ValueError(result["error"])
        print(base64.b64decode(result["data"]).decode("utf-8"), end="")
