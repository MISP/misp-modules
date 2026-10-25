# Intezer Sandbox

Retrieve Intezer Analyze file reports or submit an attachment for analysis.

Exchanges the API key through POST /get-access-token, then authenticates with a Bearer token. Hashes retrieve an existing report via GET /files/{hash}; text accepts an analysis UUID for GET /analyses/{id}. Attachments use POST /analyze once and return the receipt, without polling. max_size_mb defaults to 25 (1-100). Report status, verdict, family and privacy remain in sandbox-report objects. Attachment submissions send content to your Intezer account.

Input: md5, sha1, sha256, attachment, text.

Configuration: apikey, max_size_mb. Required: apikey.

Requests verify TLS, reject redirects and use a 30 second timeout. Credentials stay in authentication headers or request bodies. Service errors are reported without echoing credentials or response bodies.

New attributes use `to_ids=false`; the source attribute retains its UUID and metadata. Results reference the source. Empty lookups return the source without fabricated enrichment.

References:

- https://intezer-python-sdk.readthedocs.io/

The provider file_name is mapped to the MISP filename relation. HTTP 410 is treated as a missing result only for an analysis-ID lookup; failed submissions still return an error.
