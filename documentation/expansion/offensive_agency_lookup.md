# Offensive Agency Lookup

Run `offensive_agency_lookup` on an `ip-src` or `ip-dst` attribute to query
Offensive Agency's `/api/host/<ip>` endpoint. It accepts IPv4 and IPv6 and
requires no API key. A missing host returns the input attribute without
adding observations. Other HTTP failures produce a module error.

An example request uses a documentation address.

```json
{
  "module": "offensive_agency_lookup",
  "attribute": {
    "type": "ip-dst",
    "value": "192.0.2.1",
    "uuid": "7d40c53e-626d-4ddc-8522-c9907e3c25ad"
  }
}
```

The `offensive-agency-observation` object references the input attribute.
It includes ONYPHE observation dates, framework confidence, network context,
and the complete per-IP JSON response as an attachment. Related `domain-ip`
and `ip-port` objects carry the reported DNS names and ports. New attributes
have IDS export disabled, and shared CDN addresses have correlation disabled.

For the complete host export, use the gathering module's `all_hosts` parameter.
[Gathering guide](../mkdocs/gathering-guide.md#offensive-agency) ·
[Provider methodology and exports](https://offensive.agency/about)
