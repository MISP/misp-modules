from urllib.parse import quote, urlparse

from anyrun import RunTimeException


class Config:
    INTEGRATION: str = "MISP:0.2"


def get_proxy_settings(config: dict) -> dict:
    """
    Builds the ANY.RUN SDK connector proxy kwargs from the module config

    :param config: MISP module config
    :return: Kwargs to pass to the ANY.RUN SDK connector, empty if no proxy is configured
    :raises RunTimeException: If the proxy config is incomplete
    """
    host = config.get("proxy_host")
    port = config.get("proxy_port")
    username = config.get("proxy_username")
    password = config.get("proxy_password")

    if not host:
        return {}

    if not port:
        raise RunTimeException(
            "The anyrun_sandbox proxy_host config is set, please also set the proxy_port."
        )

    parsed = urlparse(host)
    scheme = parsed.scheme or "http"
    netloc = parsed.netloc or parsed.path

    credentials = ""
    if username:
        if not password:
            raise RunTimeException(
                "The anyrun_sandbox proxy_username config is set, please also set the proxy_password."
            )
        credentials = f"{quote(username, safe='')}:{quote(password, safe='')}@"

    return {"proxy": f"{scheme}://{credentials}{netloc}:{port}"}
