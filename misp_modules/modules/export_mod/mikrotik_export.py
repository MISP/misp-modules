"""Export MikroTik RouterOS v7 IPv4/IPv6 firewall filter commands."""

from misp_modules.lib import network_acl as acl

moduleinfo = acl.module_info(
    "MikroTik RouterOS ACL Export",
    "mikrotik_export",
    "Export IDS-marked network attributes as RouterOS IPv4/IPv6 firewall filter commands.",
    ["https://help.mikrotik.com/docs/spaces/ROS/pages/48660574/Filter"],
)
EXTRA_CONFIG = {"chain": {"type": "String", "message": "Firewall chain: forward (default), input or output"}}
moduleconfig = [*acl.COMMON_CONFIG, *EXTRA_CONFIG]


def _configure(config):
    chain = acl.token(config, "chain", "forward")
    if chain not in ("forward", "input", "output"):
        raise ValueError("chain must be forward, input or output.")
    return dict(config, chain=chain)


def _render(rules, config):
    for rule in rules:
        path = "/ip firewall filter" if rule.family == 4 else "/ipv6 firewall filter"
        action = "drop" if config["mode"] == "block" else "log"
        line = (
            f"{path} add chain={config['chain']} action={action}"
            f" src-address={rule.source} dst-address={rule.destination}"
        )
        if rule.port:
            line += f" protocol={rule.protocol} {rule.direction}-port={rule.port}"
        if config["mode"] == "log":
            line += f' log-prefix="{config["name_prefix"]} "'
        yield line + f' comment="{config["name_prefix"]}-{rule.key}"'


def _warnings(config):
    warnings = [
        "RouterOS add appends entries; move them before established/related accepts, FastTrack and other terminal"
        " rules."
    ]
    if config["mode"] == "log":
        warnings.append("RouterOS action=log continues to the next rule and preserves later policy decisions.")
    return warnings


def handler(q=False):
    return acl.handle(q, moduleinfo["name"], _configure, _render, _warnings)


def introspection():
    return acl.introspection(EXTRA_CONFIG)


def version():
    return dict(moduleinfo, config=moduleconfig)
