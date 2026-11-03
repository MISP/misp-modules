# NeutrinoAPI IP Blocklist

Expand public IPv4/IPv6 `ip-src` and `ip-dst` attributes with NeutrinoAPI's
IP Blocklist endpoint.

Multicast, reserved and IPv4-mapped IPv6 inputs are rejected before network
access. Leading/trailing whitespace is removed from both account credentials.

| Setting | Purpose |
| --- | --- |
| `user_id` | Required NeutrinoAPI account user ID. |
| `api_key` | Required API key. Sent in an HTTP header with the user ID. |
| `vpn_lookup` | `true` or `false`; defaults to `false`. Enables public VPN provider lookup. |

The module returns the source attribute and a referenced annotation containing
listing status, categories, sensor details, counts, timestamps and the flags
actually present in the response. False flags and zero counts are retained.
Missing flags remain unknown, and `is-vpn` is included only when VPN lookup was
requested. An unlisted address is not automatically classified as benign.
New enrichment has `to_ids=false`; source metadata is preserved.

API errors, including errors returned with HTTP 200, are reported without
including credentials or remote error bodies. Requests have a finite timeout,
do not follow redirects and do not retry automatically.

Enable `neutrino` in MISP's enrichment settings after restarting misp-modules.
The module uses existing `requests` and PyMISP dependencies.

Validate offline with `python -m pytest tests/test_neutrino.py`.

[IP Blocklist API](https://www.neutrinoapi.com/api/ip-blocklist/)
