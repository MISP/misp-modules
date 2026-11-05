# CrowdStrike Falcon Intelligence enrichment

`crowdstrike_falcon` queries **Falcon Intelligence indicators** when you run
enrichment on an attribute or use its enabled hover lookup. Publishing a MISP
event does not invoke this module, upload indicators to Falcon, poll endpoint
detections, or create sightings. A domain or hash observed by a Falcon endpoint
is not necessarily present in the Falcon Intelligence indicator database.

## Configure and run a lookup

1. Install the `crowdstrike-falconpy` dependency in the Python environment running
   misp-modules; it is included in the `minimal` and `all` extras.
2. In Falcon, create an OAuth2 API client with the **Intel: Read** scope. The
   account also needs access to the Falcon Intelligence service.
3. Enable **CrowdStrike Falcon** in MISP's enrichment settings for the relevant
   organisation. Set `api_id` to the OAuth2 **client ID** and `apikey` to its
   **client secret**. The current module does not use the legacy
   `QUERYAPIUSER`/`QUERYAPIKEY` credentials mentioned in issue #408.
4. On a supported attribute, such as a domain or SHA-256, select **Enrich** and
   choose **CrowdStrike Falcon**. Review and accept the returned attributes.
   Test with an indicator known to exist in **Falcon Intelligence**.

The request uses FalconPy's `Intel.query_indicator_entities(q=value)`, which
calls `GET /intel/combined/indicators/v1`. This is a generic substring search
across intelligence fields. The module imports available related indicators,
actors, malware families, labels and report metadata. Its advertised input
types are individual attributes; split composite attributes before lookup.

## Verify discovery and API access

Check that misp-modules lists the module, using the URL configured in MISP:

```bash
curl --fail --silent --show-error http://127.0.0.1:6666/modules \
  | jq '.[] | select(.name == "crowdstrike_falcon")'
```

A missing entry indicates a service or dependency problem. Check the installed
Python environment and startup log, then restart misp-modules after installing
dependencies. Discovery alone does not authenticate to CrowdStrike.

An enrichment request sent to `/query` has this shape. Replace the placeholders
with the same settings used by MISP and keep credentials in a protected request
file if testing with curl; do not put them in the command line or issue reports.

```json
{
  "module": "crowdstrike_falcon",
  "attribute": {
    "type": "sha256",
    "value": "<SHA256 known to Falcon Intelligence>",
    "uuid": "32876e4a-916d-4935-9e51-7b69a76718f8"
  },
  "config": {
    "api_id": "<OAuth2 client ID>",
    "apikey": "<OAuth2 client secret>"
  }
}
```

```bash
curl --fail --silent --show-error \
  -H 'Content-Type: application/json' \
  --data-binary @request.json http://127.0.0.1:6666/query
```

Inspect the JSON response: module errors can be returned with HTTP 200, so a
successful curl exit status alone does not verify Falcon authentication.

| Result | Meaning and next step |
| --- | --- |
| `CrowdStrike apikey/api_id is missing` | Configure the OAuth2 client secret/client ID in the settings used by this organisation. |
| HTTP/API error 401 | Check the OAuth2 credentials. |
| HTTP/API error 403 | Check Intel: Read scope and Falcon Intelligence access for the account. |
| HTTP/API error 429 | Rate limit reached; retry later. |
| Invalid API response | The SDK did not return a valid indicator response; this is not a no-match result. |
| `results` with only the original attribute | The request succeeded but supplied no additional supported relationships or metadata. An empty indicator list is a normal outcome. |

If the goal is to publish custom detection IOCs to Falcon, use the separate
[CrowdStrike IOC Publish workflow action](../action_mod/crowdstrike_ioc_publish.md).
Endpoint detections and sightings require a separate integration.

References: [FalconPy Intel collection](https://www.falconpy.io/Service-Collections/Intel.html)
and [issue #408](https://github.com/MISP/misp-modules/issues/408).
