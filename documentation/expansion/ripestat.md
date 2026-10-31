# RIPEstat

Enrich `ip-src`, `ip-dst` and `AS` attributes with the public
[RIPEstat Data API](https://stat.ripe.net/docs/data-api/ripestat-data-api).
No API key or additional dependency is required beyond `requests` and PyMISP.

| Input | Endpoint | Result |
| --- | --- | --- |
| IPv4 or IPv6 address | `network-info`, then `as-overview` for each distinct origin ASN | Announcing ASN, ASN holder and containing prefix |
| IPv4 or IPv6 CIDR prefix in `ip-src` or `ip-dst` | `prefix-overview` | Origin ASNs, their holders and the returned prefix |
| AS number, such as `AS3333` or `3333` | `as-overview` | ASN holder and announcement status |

Results use the latest data available to each endpoint. They are routing context,
not a reputation verdict or a historical ownership claim. Multiple origin ASNs
produce separate `asn` objects. Each object references the original attribute;
the source UUID and metadata are preserved. Newly generated attributes have
`to_ids=false`. The holder is stored as `description`, the prefix as
`subnet-announced`, and AS Overview's announcement status in the object comment.
An ASN reported as unannounced may still be used for transit.

CIDRs with host bits are normalised before querying. If Prefix Overview returns
a less specific containing prefix, the object records that returned prefix.
Unrouted IPs and prefixes without origin ASNs return only the source attribute.
ASN queries do not download all announced prefixes. The module does not query
WHOIS, abuse contacts, geolocation or routing history.

The optional `sourceapp` setting defaults to `misp-modules`. It accepts ASCII
letters, digits, hyphens and underscores. For regular use above 1,000 requests
per day, follow RIPEstat's registration guidance in the linked API documentation.
Requests are sequential; RIPEstat limits concurrent requests per source IP, so
deployments must account for concurrent module invocations.

Requests use HTTPS with certificate verification, a 30-second timeout per call,
and no redirects. HTTP errors (including rate limits), API maintenance/error
statuses, transport failures and malformed responses return an error. The module
does not retry or return incomplete results when a secondary lookup fails.

Example request to the misp-modules `/query` endpoint:

```json
{
  "module": "ripestat",
  "attribute": {
    "type": "ip-dst",
    "value": "193.0.6.139",
    "uuid": "32876e4a-916d-4935-9e51-7b69a76718f8"
  },
  "config": {
    "sourceapp": "misp-modules"
  }
}
```

Validation: `pytest tests/test_ripestat.py` uses mocked API responses and requires
no network access or credentials.

Endpoint references:

- [Network Info](https://stat.ripe.net/docs/data-api/api-endpoints/network-info)
- [Prefix Overview](https://stat.ripe.net/docs/data-api/api-endpoints/prefix-overview)
- [AS Overview](https://stat.ripe.net/docs/data-api/api-endpoints/as-overview)
