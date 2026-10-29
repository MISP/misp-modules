# DNSTwist Domain Enrichment

Generate domain permutations locally with optional DNS resolution. Install dnstwist in the module server Python environment. resolve defaults to false and performs no DNS checks. Set resolve=true to return DNS-resolving candidates with available A, AAAA, NS and MX observations. timeout defaults to 30 seconds (1–120); threads defaults to 4 (1–16). An isolated subprocess prevents changes to the module server argument list and bounds runtime. Generated candidates and resolving domains are investigation leads, not maliciousness assertions. Each result preserves its mutation algorithm.

Input: domain, hostname.

Configuration: resolve, timeout, threads, max_results. Required: none.

max_results defaults to 25 and accepts 1–100. New attributes use `to_ids=false`; the source UUID, detection flag and metadata are preserved. Objects reference the source attribute. Requests verify TLS, reject redirects and use connection/read timeouts of 5/30 seconds. API errors do not echo credentials. No automatic submission retries or background polling occur.

Reference: https://github.com/elceef/dnstwist

Install the optional engine with `python -m pip install dnstwist` in the Python environment running misp-modules. The module uses the same Python executable for its isolated worker.
