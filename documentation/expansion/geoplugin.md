# geoPlugin Lookup

Addresses [module request #438](https://github.com/MISP/misp-modules/issues/438).
Expand or hover over a public IPv4 `ip-src`, `ip-dst` or `domain|ip` attribute
to retrieve its geolocation from geoPlugin. For `domain|ip`, only the IP component
is queried; the domain is not resolved. IPv6 is rejected because geoPlugin's
current API documentation specifies IPv4 support.

Enable `geoplugin` in MISP's enrichment settings and configure `api_key` with
your geoPlugin developer key. The module uses the current documented
`https://api.geoplugin.com/` endpoint with `ip` and `auth` query parameters.
It does not use the historical unauthenticated `geoplugin.net/json.gp` service.
Requests verify TLS, reject redirects and use a 5 second connection timeout
and a 30 second read timeout. Requests are not retried. IP addresses are sent
to geoPlugin; private, reserved and multicast addresses are rejected locally.

The original attribute and its metadata are preserved. A `geolocation` object
references its UUID with `related-to`. Available country, country code, region,
city, postal code, latitude, longitude and accuracy radius are included. Continent
and timezone use the object's `text` relation. Provider attribution is preserved
in the object comment. All new attributes have `to_ids=false`.

Missing or null fields are omitted; zero coordinates remain valid. Full (200)
and partial (206) lookup statuses are accepted as numbers or strings. A response
must identify the queried address and contain location data. Authentication,
rate limit, transport, malformed response and no-location failures return an
`error` to MISP. Error messages omit response bodies and request URLs to avoid
exposing the API key.

Example request to the misp-modules `/query` endpoint:

```json
{
  "module": "geoplugin",
  "attribute": {
    "type": "ip-dst",
    "value": "8.8.8.8",
    "uuid": "32876e4a-916d-4935-9e51-7b69a76718f8"
  },
  "config": {
    "api_key": "YOUR_GEOPLUGIN_API_KEY"
  }
}
```

Run `pytest tests/test_geoplugin.py` for offline tests using mocked API responses.
An end-to-end lookup requires a valid geoPlugin API key and network access.

Reference: [geoPlugin API documentation](https://www.geoplugin.com/docs).
