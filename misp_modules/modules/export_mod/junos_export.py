"""Export Junos stateless inet/inet6 firewall filter terms."""

from misp_modules.lib import network_acl as acl

moduleinfo = acl.module_info(
    "Juniper Junos ACL Export",
    "junos_export",
    "Export IDS-marked network attributes as Junos inet/inet6 stateless firewall filter set commands.",
    [
        "https://www.juniper.net/documentation/us/en/software/junos/routing-policy/topics/concept/firewall-filter-overview.html"
    ],
)
moduleconfig = list(acl.COMMON_CONFIG)
FILTER_WARNING = (
    "Junos filters have an implicit discard; merge terms into existing filters and retain their final terms."
)


def _render(rules, config):
    for rule in rules:
        family = "inet" if rule.family == 4 else "inet6"
        prefix = (
            f"set firewall family {family} filter {config['name_prefix']}-V{rule.family}"
            f" term {config['name_prefix']}-{rule.key}"
        )
        yield f"{prefix} from source-address {rule.source}"
        yield f"{prefix} from destination-address {rule.destination}"
        if rule.port:
            protocol_key = "protocol" if rule.family == 4 else "next-header"
            port_key = "source-port" if rule.direction == "src" else "destination-port"
            yield f"{prefix} from {protocol_key} {rule.protocol}"
            yield f"{prefix} from {port_key} {rule.port}"
        if config["mode"] == "log":
            yield f"{prefix} then log"
            yield f"{prefix} then next term"
        else:
            yield f"{prefix} then discard"


def _warnings(config):
    warnings = [FILTER_WARNING]
    if config["mode"] == "log":
        warnings.append("Logging uses log and next term; a later term must provide the traffic verdict.")
    return warnings


def handler(q=False):
    return acl.handle(q, moduleinfo["name"], lambda config: config, _render, _warnings)


def introspection():
    return acl.introspection()


def version():
    return dict(moduleinfo, config=moduleconfig)
