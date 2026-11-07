# SiberKapan

Look up an IP address in [SiberKapan](https://siberkapan.org), a threat intelligence platform whose indicators come only from its own sensors (honeypots, Fail2ban, nginx and web sensors). SiberKapan is also available as a MISP default feed.

The module works as both a hover and an expansion module. It queries the public SiberKapan API, so no API key and no extra Python requirements are needed.

Supported attribute types are `ip-src`, `ip-dst`, `ip-src|port` and `ip-dst|port`. For the `|port` types only the IP part is used.

## Output

The module returns text values describing the SiberKapan record for the IP address.

- Threat score (0-100).
- Background noise score (0-100) and class, computed over the last 90 days.
  - `mass scanning` means the IP hits many sensors and ports indiscriminately.
  - `focused` means the activity is concentrated on a single SiberKapan sensor. This does not by itself prove a targeted attack.
  - `opportunistic` covers everything in between.
- Breadth of activity, as the number of sensors, ports and active days.
- Observed attack types and the sensor types that reported the IP.
- First and last seen dates, ASN and country.
- A link to the IP detail page on siberkapan.org.

## Errors and limits

- If the IP is not listed in SiberKapan, the module returns a single text value saying so. An IP not being listed does not mean it is safe.
- Network errors and unexpected HTTP status codes are returned as module errors so they appear in the MISP interface.
- Requests time out after 10 seconds.
- The module sends the queried IP address to siberkapan.org, so `data-source` is set to `external`.

## Verification

`tests/test_siberkapan.py` exercises the handler with mocked HTTP responses for a listed IP, an unlisted IP, the `ip-dst|port` input format, a missing value and a network error. No real network calls are made.
