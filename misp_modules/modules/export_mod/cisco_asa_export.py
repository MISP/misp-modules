"""Export Cisco ASA 9.x unified IPv4/IPv6 extended access lists."""

import ipaddress

from misp_modules.lib import network_acl as acl

moduleinfo = acl.module_info(
    "Cisco ASA ACL Export",
    "cisco_asa_export",
    "Export IDS-marked network attributes as Cisco ASA 9.x IPv4/IPv6 extended ACL entries.",
    [
        "https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/A-H/asa-command-ref-A-H/aa-ac-commands.html"
    ],
)
moduleconfig = list(acl.COMMON_CONFIG)
POLICY_WARNING = "ASA ACLs have an implicit deny; merge entries into existing ACLs and preserve their final rules."


def _address(value):
    network = ipaddress.ip_network(value)
    if network.prefixlen == 0:
        return f"any{network.version}"
    if network.prefixlen == network.max_prefixlen:
        return f"host {network.network_address}"
    if network.version == 4:
        return f"{network.network_address} {network.netmask}"
    return str(network)


def _render(rules, config):
    for rule in rules:
        source, destination = _address(rule.source), _address(rule.destination)
        if rule.port:
            if rule.direction == "src":
                source += f" eq {rule.port}"
            else:
                destination += f" eq {rule.port}"
        action = "deny" if config["mode"] == "block" else "permit"
        suffix = " log" if config["mode"] == "log" else ""
        yield (
            f"access-list {config['name_prefix']} extended {action}"
            f" {rule.protocol or 'ip'} {source} {destination}{suffix}"
        )


def _warnings(config):
    return [POLICY_WARNING, *([acl.PERMIT_LOG_WARNING] if config["mode"] == "log" else [])]


def handler(q=False):
    return acl.handle(q, moduleinfo["name"], lambda config: config, _render, _warnings, comment="!")


def introspection():
    result = acl.introspection()
    result["userConfig"]["mode"] = {"type": "String", "message": "block (deny) or log (permits matching traffic)"}
    return result


def version():
    return dict(moduleinfo, config=moduleconfig)
