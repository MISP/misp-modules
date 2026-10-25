# Import External Reference

Capture a public web reference as Markdown or a PDF attachment.

Downloads a public HTTP(S) URL on ports 80 or 443, with a 30-second timeout and at most five redirects. Resolves and validates every hop, connects directly to the validated public address and verifies TLS against the original hostname. Private, reserved and mixed public/private DNS answers are rejected. No proxy or browser is used. max_size_mb defaults to 5 (1-25), enforced while streaming decompressed content. HTML is converted into Markdown; PDFs are preserved. Returns a page-capture object referencing the URL attribute.

Input: url.

Configuration: max_size_mb. Required: .

New attributes use `to_ids=false`; the source attribute retains its UUID and metadata. Results reference the source. Empty lookups return the source without fabricated enrichment.

References:

- https://www.misp-project.org/objects.html#_page_capture
