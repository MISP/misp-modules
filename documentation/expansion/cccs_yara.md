# CCCS YARA Metadata Validator

`cccs_yara` checks every rule in a `yara` attribute against the
[Canadian Centre for Cyber Security YARA specification](https://github.com/CybercentreCanada/CCCS-Yara).
It is available for hover and enrichment, and returns a text report with each
rule's name, metadata validity, errors and warnings. Warnings do not make a rule
invalid. The original attribute is preserved; metadata generation is disabled.
Missing fields that the upstream CLI could generate are reported as errors.

## Setup

Install the `all` extra, which includes `cccs-yara`:

```bash
poetry install -E all
```

The dependency constraint keeps `plyara` below 2.2.7, whose bundled `ply`
package conflicts with Pandoc. When downgrading an existing environment from
`plyara` 2.2.7 or 2.2.8, reinstall `ply` after installing the dependencies to
restore the files overwritten by those releases:

```bash
poetry run python -m pip install --force-reinstall ply==3.11
```

CCCS-YARA uses a local ATT&CK STIX store to validate technique IDs and actor
metadata. Provision it before starting the module server, using the ATT&CK
version expected by CCCS-YARA 2.11:

```bash
git clone --depth 1 --branch 'ATT&CK-v16.1' https://github.com/mitre/cti.git /srv/misp-modules/cti
export MITRE_STIX_DATA_PATH=/srv/misp-modules/cti
poetry run misp-modules -l 127.0.0.1
```

Choose a data directory readable by the module server and configure the same
environment variable in its service definition. The directory must contain
the ATT&CK domain directories such as `enterprise-attack`. The library reads this
setting at import time, so restart the server after changing it. Without the
dataset, the module returns a setup error. Module discovery does not import the
validator or download its dataset; validation uses the provisioned local data.
No API key or module configuration is required.

## Request and response

Send the rule content in `yara`, as with the existing YARA syntax validator:

```json
{
  "module": "cccs_yara",
  "yara": "rule missing_metadata { condition: true }"
}
```

```json
{
  "results": [
    {
      "types": ["text"],
      "values": "Rule missing_metadata: CCCS YARA metadata invalid.\nErrors:\nmetadata: No Metadata Present\n"
    }
  ]
}
```

The module also accepts `{"attribute": {"type": "yara", "value": "..."}}`.
For an attribute containing multiple rules, the report contains a separate
paragraph for each rule. A compliant rule reports
`Rule <name>: CCCS YARA metadata valid.`; optional warnings follow it.

YARA syntax errors are reported before metadata validation. File includes are
disabled to prevent rules from reading server files. Rules must compile as
supplied, including module imports and rule dependencies; external variables
are not synthesized. The upstream specification and ATT&CK snapshot determine
the accepted metadata values. This module does not return rewritten rules or
perform the upstream CLI's metadata generation and enrichment operations.
