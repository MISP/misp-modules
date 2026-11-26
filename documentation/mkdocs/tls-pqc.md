# TLS and post-quantum readiness

MISP modules is **not unconditionally PQC compliant**. Compliance needs a named
policy and evidence from the deployed connections. TLS 1.3 and a modern cipher
suite alone do not prove post-quantum key exchange. Hybrid key exchange also does
not replace classical certificate signatures with post-quantum authentication.

## Protocol review

The source review below covers the core API, representative outbound transport
paths, and explicit TLS verification overrides at baseline commit
`a123fc2ee99fd30b37d0879a1e576b684a826829`. It is not a certification, an exhaustive
audit of third-party SDK internals, or a scan of running external services.

| Path | Finding | Action |
| --- | --- | --- |
| Core API (`misp_modules/__main__.py`) | HTTP on localhost by default. Previously had no native TLS configuration. | Optional native TLS 1.3 listener described below; retain loopback HTTP for a local TLS proxy. |
| Outbound HTTPS (`requests`, service SDKs) | No repository-wide requirement for a hybrid group. The linked TLS library, application overrides, proxy and peer determine negotiation. Python package versions do not select the system TLS library. | Use a supported, patched PQC-capable runtime and verify every required service and TLS hop. |
| Cytomic Orion (`modules/expansion/cytomic_orion.py`) | All four requests disable certificate verification, including the OAuth exchange. | Existing fix: [PR #865](https://github.com/MISP/misp-modules/pull/865). Until resolved, exclude this integration from authenticated-TLS claims. |
| VMRay (`modules/expansion/vmray_submit.py`, `lib/_vmray/parser.py`) | Passes `False` to the shared API client's certificate-verification argument. | Existing fix: [PR #881](https://github.com/MISP/misp-modules/pull/881). Until resolved, exclude these paths from authenticated-TLS claims. |
| Other verification options (`vmware_nsx`, Lastline, `reversinglabs_spectra_analyze`) | Verification is configurable. | Keep verification enabled and install the correct CA trust; review actual configuration. |
| RST Cloud's optional MISP connections (`modules/expansion/_rstcloud/client.py`) | Certificate verification previously defaulted off. The galaxy resolver cache was keyed only by URL, allowing reuse across credentials and verification settings. | Verification now defaults on, and both MISP client caches isolate credentials and verification mode. |
| DNS (`dns.py`, `dns_query.py`) | Uses resolver queries without requiring encrypted DNS. DNSSEC, where used, authenticates DNS data and does not encrypt queries. | Use a controlled local resolver with a verified hybrid TLS upstream if query confidentiality is required; protect each hop. |
| WHOIS (`whois.py`) | Raw TCP to a configured uwhois proxy. | Keep it local or use a protected tunnel. RDAP uses HTTPS, whose negotiated group still needs verification. |
| IRC (`action_mod/irc.py`) | Verified TLS is the default, with an explicit plaintext option. | Keep `use_tls=true`; verify the server's group and runtime. |
| URL capture and configurable service URLs | Some modules intentionally retrieve HTTP URLs or accept HTTP endpoints. | Apply service-specific policy; do not rewrite HTTP indicators as HTTPS or describe these paths as PQC protected. |
| Companion website (`website/main.py`, `website/app/utils/utils.py`) | Separate web listener and HTTP backend client. Native API TLS flags do not configure the website. | Use a TLS proxy for the website and keep its HTTP backend on the same trusted host. The backend client currently assumes HTTP. |
| Messaging protocols | TLS protects individual network hops. Matrix action messages are sent to unencrypted rooms; Signal delegates to an external REST service. | Assess end-to-end encryption and that service separately from transport TLS. |

These findings are independent: hybrid key exchange does not compensate for
disabled certificate verification, plaintext traffic, or an unprotected proxy
hop. Custom modules and SDKs with separate TLS backends need their own review.

### RST Cloud configuration change

For `rst_ioc` and `rst_noise_control`, optional connections back to MISP now
verify the certificate by default. If MISP uses a private CA, install that CA
in the client's trust store (for the standard requests transport,
`REQUESTS_CA_BUNDLE` can select a CA bundle). Existing deployments relying on
unverified certificates must correct trust or explicitly set `misp_verifycert`
to `false`. The opt-out also accepts `0`, `no`, and `off`; empty or unrecognized
values keep verification enabled. Failed connections retain the existing
best-effort behavior: optional galaxy resolution/write-back is skipped, with
no retry using weaker TLS settings.

## Native API TLS

Supply a PEM certificate chain and its matching PEM private key:

```bash
misp-modules --listen 127.0.0.1 --port 6666 \
  --tls-certfile /etc/misp-modules/fullchain.pem \
  --tls-keyfile /etc/misp-modules/privkey.pem
```

The listener requires TLS 1.3. Both arguments are required together, and invalid
TLS configuration stops startup before listening. It never falls back to HTTP
after a certificate/key error. Clients must use HTTPS and validate the server's
certificate and hostname. The generated OpenAPI server URL reflects HTTPS.
Changing certificate files requires a service restart.

Without these arguments the default remains HTTP on localhost. A non-loopback
HTTP bind produces a warning. The API has no built-in client authentication or
authorization: restrict access to trusted clients, or put it behind an
authenticated TLS proxy. TLS alone does not make the API safe for public access.
When terminating TLS at a proxy, configure the policy there and keep the HTTP
upstream on loopback; use verified TLS for an upstream across hosts.

The server leaves key-exchange groups to OpenSSL configuration and defaults.
OpenSSL 3.5 introduced built-in hybrid groups including `X25519MLKEM768`, with
hybrid groups preferred by default. Use a currently supported, patched version.
Default negotiation can still choose a classical group for a classical peer.
Check the library used by the **service's Python interpreter**, which can differ
from the `openssl` CLI:

```bash
python -c 'import ssl; print(ssl.OPENSSL_VERSION)'
openssl version
```

See the [OpenSSL 3.5 release notes](https://openssl-library.org/news/openssl-3.5-notes/)
and [group configuration documentation](https://docs.openssl.org/3.5/man3/SSL_CTX_set1_groups_list/).

## Requiring hybrid key exchange

For a deployment that must reject classical fallback, configure an explicit
hybrid-only group policy. The following is a dedicated OpenSSL configuration
example for a compatible OpenSSL 3.5+ runtime, saved as
`/etc/misp-modules/openssl-pqc.cnf`:

```ini
config_diagnostics = 1
openssl_conf = misp_init

[misp_init]
ssl_conf = misp_ssl

[misp_ssl]
system_default = misp_tls

[misp_tls]
MinProtocol = TLSv1.3
Groups = X25519MLKEM768
Ciphersuites = TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
```

Set the configuration before Python starts:

```bash
OPENSSL_CONF=/etc/misp-modules/openssl-pqc.cnf \
  misp-modules --listen 127.0.0.1 --port 6666 \
  --tls-certfile /etc/misp-modules/fullchain.pem \
  --tls-keyfile /etc/misp-modules/privkey.pem
```

This policy intentionally breaks connections to peers without the hybrid group.
It applies to OpenSSL contexts in the process that load the configuration and
do not override it, including outbound contexts; it is not an enforcement layer
for other TLS libraries, HTTP URLs or raw TCP. Merge the example into existing
provider/FIPS configuration where required instead of discarding that policy.
An unavailable group/provider or ignored configuration must be discovered during
deployment validation. Do not rely on a version string or successful startup as
proof that this policy took effect. Use a separately managed TLS terminator if
the runtime cannot reliably enforce the required policy.

## Verify the deployed connections

With a hybrid-capable OpenSSL client, check both trust and key exchange. Substitute
the actual service hostname and its CA bundle; use a port or connect address
appropriate to the deployment:

```bash
openssl s_client -connect modules.example.org:6666 \
  -servername modules.example.org -verify_hostname modules.example.org \
  -CAfile /path/to/trusted-ca-bundle.pem -verify_return_error \
  -tls1_3 -groups X25519MLKEM768 -brief </dev/null
```

Require successful certificate verification, TLS 1.3, and the reported negotiated
group `X25519MLKEM768`. A cipher name such as `TLS_AES_256_GCM_SHA384` does not
identify the key-exchange group. For a hybrid-only policy, repeat with
`-groups X25519` and require handshake failure; also repeat with `-tls1_2`
instead of `-tls1_3` and require failure. With the ordinary default group policy,
the classical TLS 1.3 probe may succeed; that is expected fallback.

Repeat for each outbound provider and each TLS-terminating proxy. An `s_client`
probe shows what that probe negotiated; it does not prove a Python SDK did the
same. Confirm actual application traffic using approved handshake capture or
endpoint/proxy telemetry. In particular, the MISP caller has a separate TLS stack
(often PHP/libcurl), and the companion website has separate configuration.

`tls_certificate_check` reports certificate metadata and the TLS version; it
does not currently report a negotiated group or certify PQC readiness.

Record the runtime, provider/policy, peer, protocol, group, trust result, and
fallback tests for the connections covered by your requirement. Review classical
certificate authentication and any end-to-end encryption separately. A hybrid
ML-KEM handshake offers post-quantum key establishment for that hop; it is not a
claim of fully post-quantum authentication or system-wide compliance.
