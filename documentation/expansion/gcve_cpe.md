# GCVE CPE

Expand a MISP `cpe` attribute using the public [GCVE CPE Editor API](https://cpe.gcve.eu/api/docs).
No API key is required.

The module searches `GET /api/cpes` and imports only a record whose `cpe_uri`
equals the input value (after trimming surrounding whitespace). The API search
uses substrings and SQL LIKE wildcards, so unrelated search hits are ignored.
CPE 2.3 formatted strings and CPE URI bindings are sent literally: this module
does not translate between bindings or infer version applicability.

The output uses `misp_standard` format and contains:

- The original attribute, retaining its UUID and metadata.
- An annotation containing the exact catalog record as JSON and a link to its
  CPE detail page. This retains the title, notes, identifiers, timestamps,
  deprecation information, PURL mappings (when present), and vulnerability references.
- A vulnerability object for each distinct reference, preserving its identifier,
  `cpe_applicability`, rationale, and relationships to the original CPE and annotation.
  CVE, GCVE and GHSA identifiers are supported. Only `vulnerable` references add
  a `vulnerable-configuration` attribute. `not_vulnerable`, `requires_configuration`
  and `under_investigation` remain explicit context rather than affected-version claims.

New enrichment attributes use `to_ids=false`. Catalog deprecation does not by
itself imply vulnerability, and replacement CPEs are retained as metadata without
automatic expansion. No vulnerability details or scores are invented from references.
An exhausted search with no exact match returns only the original attribute.

| Setting | Default | Meaning |
| --- | --- | --- |
| `api_url` | `https://cpe.gcve.eu` | Instance root, without `/api`; HTTP(S) and instance path prefixes are supported. |
| `timeout` | `30` | Seconds per request; greater than zero and at most 120. |
| `max_pages` | `5` | Maximum search pages, from 1 to 20; each request asks for 100 records. |

Omitted, null or blank settings use defaults. If the search limit is reached
before an exact match, the module returns an explicit error suggesting an increase
to `max_pages`. HTTP errors (including 404 and 429), timeouts, invalid JSON and
invalid response structures are reported as module errors. TLS verification is
enabled and redirects are not followed. The service's top-level execution timeout
can further limit the total duration across requests.

Example request:

```json
{
  "module": "gcve_cpe",
  "attribute": {
    "type": "cpe",
    "value": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
    "uuid": "32876e4a-916d-4935-9e51-7b69a76718f8"
  },
  "config": {}
}
```

The module is discovered automatically by misp-modules. After restarting the
service, enable `gcve_cpe` in MISP's enrichment settings.

Run `pytest tests/test_gcve_cpe.py` for mocked API tests covering exact matching,
pagination, applicability states, metadata preservation and failure responses.
