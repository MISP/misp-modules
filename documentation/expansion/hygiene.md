# Hygiene Warninglist Check

Check an observable against local MISP warninglists and record the matching lists.

Uses the warninglists bundled with pymispwarninglists without downloading during enrichment. Optional warninglists_path points to a local repository containing lists/*/list.json. slow_search defaults to true for CIDR and hostname-aware matching; false selects exact matching. Matching-list name, version, type and description become warninglist-match objects. max_results defaults to 25 (1-100). Matches are context for analyst review, not proof of benignness; source detection flags and scores are preserved.

Input: domain, hostname, url, ip-src, ip-dst, md5, sha1, sha256, email-src, email-dst.

Configuration: warninglists_path, slow_search, max_results. Required: .

New attributes use `to_ids=false`; the source attribute retains its UUID and metadata. Results reference the source. Empty lookups return the source without fabricated enrichment.

References:

- https://github.com/MISP/misp-warninglists
- https://github.com/MISP/PyMISPWarningLists

Warninglist matching_attributes restrictions are applied before result limits. Email domains are lowercased and IDNA-encoded while preserving the local part.
