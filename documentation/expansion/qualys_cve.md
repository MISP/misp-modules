# Qualys CVE Enrichment

Retrieve Qualys KnowledgeBase vulnerability details for a CVE identifier.

Set url to the HTTPS API URL for your Qualys platform. Uses Basic authentication and GET /api/4.0/fo/knowledge_base/vuln/ with action=list, details=All and the cve filter. max_results defaults to 25 (1-100). All matching QIDs retain title, diagnosis, solution, severity and CVSS data. Only entries explicitly containing the requested CVE are imported. Does not query customer host inventories.

Input: vulnerability.

Configuration: url, username, password, max_results. Required: url, username, password.

Requests verify TLS, reject redirects and use a 30 second timeout. Credentials stay in authentication headers or request bodies. Service errors are reported without echoing credentials or response bodies.

New attributes use `to_ids=false`; the source attribute retains its UUID and metadata. Results reference the source. Empty lookups return the source without fabricated enrichment.

References:

- https://docs.qualys.com/en/vm/api/

Example request:

```json
{
  "module": "qualys_cve",
  "attribute": {
    "type": "vulnerability",
    "value": "CVE-2025-12345",
    "uuid": "32876e4a-916d-4935-9e51-7b69a76718f8"
  },
  "config": {
    "url": "https://service.example",
    "username": "YOUR_USERNAME",
    "password": "YOUR_API_KEY"
  }
}
```

Validation: `pytest tests/test_qualys_cve.py`. Tests use mocked provider responses; authenticated live API calls were not exercised.

The module uses the active v4 KnowledgeBase API. Endpoint HTTP 404 responses are errors; a successful XML response with no matching vulnerability entries is an empty lookup. The API lifecycle is documented at https://docs.qualys.com/en/vm/qweb-all-api/mergedProjects/qapi-scan/kbase/knowledgebase.htm .
