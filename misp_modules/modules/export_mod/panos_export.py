"""Export PAN-OS local security rules and custom TCP/UDP services."""

from misp_modules.lib import network_acl as acl

moduleinfo = acl.module_info(
    "Palo Alto PAN-OS ACL Export",
    "panos_export",
    "Export IDS-marked network attributes as PAN-OS local security policy set commands.",
    ["https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-cli-quick-start"],
)
EXTRA_CONFIG = {
    "from_zone": {"type": "String", "message": "Source zone (default: any)"},
    "to_zone": {"type": "String", "message": "Destination zone (default: any)"},
}
moduleconfig = [*acl.COMMON_CONFIG, *EXTRA_CONFIG]


def _configure(config):
    return dict(config, from_zone=acl.token(config, "from_zone", "any"), to_zone=acl.token(config, "to_zone", "any"))


def _render(rules, config):
    for rule in rules:
        name = f"{config['name_prefix']}-{rule.key}"
        service = "any"
        if rule.port:
            service = name + "-svc"
            destination = rule.port if rule.direction == "dst" else "1-65535"
            source = f" source-port {rule.port}" if rule.direction == "src" else ""
            yield f"set service {service} protocol {rule.protocol} port {destination}{source}"
        prefix = f"set rulebase security rules {name}"
        yield f"{prefix} from {config['from_zone']}"
        yield f"{prefix} to {config['to_zone']}"
        yield f"{prefix} source {rule.source}"
        yield f"{prefix} destination {rule.destination}"
        yield f"{prefix} application any"
        yield f"{prefix} service {service}"
        yield f"{prefix} action {'drop' if config['mode'] == 'block' else 'allow'}"
        yield f"{prefix} log-end yes"


def _warnings(config):
    return [acl.PERMIT_LOG_WARNING] if config["mode"] == "log" else []


def handler(q=False):
    return acl.handle(q, moduleinfo["name"], _configure, _render, _warnings, supports_zero=False)


def introspection():
    result = acl.introspection(EXTRA_CONFIG)
    result["userConfig"]["mode"] = {"type": "String", "message": "block (drop) or log (allows matching traffic)"}
    return result


def version():
    return dict(moduleinfo, config=moduleconfig)
