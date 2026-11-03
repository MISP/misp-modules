"""TLS for the API listener; key exchange policy belongs to the TLS runtime."""

import ssl


def server_context(certfile=None, keyfile=None):
    """Keep local HTTP optional, but never fall back to it on a TLS error."""
    if certfile is None and keyfile is None:
        return None
    if certfile is None or keyfile is None:
        raise ValueError("--tls-certfile and --tls-keyfile must be supplied together")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    # Preserve OpenSSL's configured groups, including hybrid ML-KEM groups on
    # capable runtimes. Pinning an ECDH curve here would disable those groups.
    context.load_cert_chain(certfile, keyfile)
    return context
