# MWDB Submit

The `mwdb` expansion module uploads an attachment or an unpacked MISP malware sample to MWDB and returns a link to the file. It uses an API key and the `mwdblib` Python client. Analysis may be triggered by the MWDB instance's Karton integration; the module does not wait for analysis.

Requires `mwdblib>=4.0.0` and MWDB Core 2.6.0 or later for upload attributes and tags.

## Configuration

| Setting | Required | Meaning |
| --- | --- | --- |
| `mwdb_apikey` | Yes | API key issued by the target MWDB instance. |
| `mwdb_url` | Yes | Instance URL or API URL, for example `https://mwdb.example` or `https://mwdb.example/api/`. Reverse proxy prefixes are preserved. |
| `mwdb_public` | No | Public sharing flag. Defaults to **true**, preserving the existing module behavior. Set **false** to use the instance's normal upload sharing rather than explicitly sharing publicly. |
| `mwdb_misp_attribute` | No | Existing MWDB attribute key in which to store the MISP event ID as a string. Requires `event_id` in the request. |
| `include_tags_event` | No | Forward event tags and add a comment with the event ID and title. Defaults to false. |
| `include_tags_attribute` | No | Forward attribute tags and its comment. Defaults to false. |

Boolean settings accept JSON booleans, `1`/`0`, and case-insensitive strings `true`/`false`, `yes`/`no`, `on`/`off`. Missing, null, or empty settings use the defaults. Other values return a configuration error before any upload.

The optional tag settings use `/var/www/MISP/PyMISP/keys.py`, which must define `misp_url`, `misp_key`, and `misp_verifycert`. This file is only loaded if either setting is enabled. Event tags require `event_id`; attribute tags require `attribute_uuid`. Tags are deduplicated, and MISP galaxy tags are excluded as in the original module.

`mwdb_misp_attribute` stores the event ID, not a full MISP URL. The key must already exist on the MWDB instance and allow the API key's user to set it.

## Input and result

The existing flat expansion request format is preserved:

```json
{
  "attachment": "sample.bin",
  "data": "c2FtcGxl",
  "event_id": "42",
  "attribute_uuid": "32876e4a-916d-4935-9e51-7b69a76718f8",
  "config": {
    "mwdb_apikey": "<MWDB API key>",
    "mwdb_url": "https://mwdb.example/api/",
    "mwdb_public": "false"
  }
}
```

For a `malware-sample`, supply `"malware-sample": "original-name|md5"` instead of `attachment` and put the base64-encoded MISP ZIP archive in `data`. The module reads it in memory using the standard MISP password `infected`, skips directories and `.filename.txt` metadata, and requires exactly one binary payload. An attachment is decoded directly without unpacking.

On success, the result is a link attribute using the canonical MWDB file ID (SHA-256), with the existing `results` list format. Tags and the event ID attribute are included in the upload request. The MISP attribute UUID is added as a comment unless an attribute comment was retrieved.

If adding comments fails after upload, the module still returns the file link and reports the comment failure in the link's comment. This avoids reporting an already uploaded file as an upload failure. API and network errors do not expose exception text or API keys. Rate limiting is reported to the caller rather than sleeping inside the module.

See [MWDB's REST API and mwdblib guide](https://mwdb.readthedocs.io/en/latest/user-guide/8-REST-and-mwdblib.html).
