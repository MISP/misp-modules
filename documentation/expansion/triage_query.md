# Triage Report Enrichment

Retrieve Triage overview reports by trusted report link or search existing analyses by file hash. api_url defaults to https://tria.ge/api; configure https://private.tria.ge/api for private accounts. Overview reports preserve verdicts, signatures, extracted configuration and available analysis metadata. This module performs lookups only. It does not submit samples or poll unfinished tasks.

Input: link, md5, sha1, sha256.

Configuration: api_key, api_url, max_results. Required: api_key.

max_results defaults to 25 and accepts 1–100. New attributes use `to_ids=false`; the source UUID, detection flag and metadata are preserved. Objects reference the source attribute. Requests verify TLS, reject redirects and use connection/read timeouts of 5/30 seconds. API errors do not echo credentials. No automatic submission retries or background polling occur.

Reference: https://tria.ge/docs/
