"""Export FortiOS 7.4 unified firewall policy and dependent objects."""

import ipaddress
import re

from misp_modules.lib import network_acl as acl

moduleinfo = acl.module_info(
    "Fortinet FortiOS ACL Export",
    "fortios_export",
    "Export IDS-marked network attributes as FortiOS 7.4+ address objects, services and firewall policies.",
    ["https://docs.fortinet.com/document/fortigate/7.4.8/cli-reference/333889629/config-firewall-policy"],
)
EXTRA_CONFIG = {
    "srcintf": {"type": "String", "message": "Source interface or zone (default: any)"},
    "dstintf": {"type": "String", "message": "Destination interface or zone (default: any)"},
    "start_policy_id": {
        "type": "String",
        "message": "First reserved policy ID (default: 10000); existing IDs are overwritten",
    },
}
moduleconfig = [*acl.COMMON_CONFIG, *EXTRA_CONFIG]


def _configure(config):
    policy_id = config.get("start_policy_id")
    if policy_id is None or policy_id == "":
        policy_id = 10000
    if (
        isinstance(policy_id, bool)
        or not isinstance(policy_id, (str, int))
        or not re.fullmatch(r"[0-9]{1,10}", str(policy_id))
    ):
        raise ValueError("start_policy_id must be an integer from 1 to 4294967294.")
    policy_id = int(policy_id)
    if not 1 <= policy_id <= 4294967294:
        raise ValueError("start_policy_id must be an integer from 1 to 4294967294.")
    return dict(
        config,
        srcintf=acl.token(config, "srcintf", "any"),
        dstintf=acl.token(config, "dstintf", "any"),
        name_prefix=acl.token(config, "name_prefix", "MISP-IOC", limit=18),
        start_policy_id=policy_id,
    )


def _render(rules, config):
    if config["start_policy_id"] + len(rules) - 1 > 4294967294:
        raise ValueError("Generated policy IDs exceed 4294967294.")
    for index, rule in enumerate(rules):
        name = f"{config['name_prefix']}-{rule.key}"
        address = name + "-addr"
        service = "ALL"
        any_address = name + "-any"
        for object_name, value in ((address, rule.address), (any_address, rule.any_network)):
            network = ipaddress.ip_network(value)
            yield f"config firewall {'address' if rule.family == 4 else 'address6'}"
            yield f'    edit "{object_name}"'
            if rule.family == 4:
                yield f"        set subnet {network.network_address} {network.netmask}"
            else:
                yield f"        set ip6 {network}"
            yield "    next"
            yield "end"
        if rule.port:
            service = name + "-svc"
            ports = rule.port if rule.direction == "dst" else f"1-65535:{rule.port}"
            yield "config firewall service custom"
            yield f'    edit "{service}"'
            yield "        set protocol TCP/UDP/SCTP"
            yield f"        set {rule.protocol}-portrange {ports}"
            yield "    next"
            yield "end"
        yield "config firewall policy"
        yield f"    edit {config['start_policy_id'] + index}"
        yield f'        set name "{name}"'
        yield f'        set srcintf "{config["srcintf"]}"'
        yield f'        set dstintf "{config["dstintf"]}"'
        field_suffix = "" if rule.family == 4 else "6"
        source = address if rule.direction == "src" else any_address
        destination = address if rule.direction == "dst" else any_address
        yield f'        set srcaddr{field_suffix} "{source}"'
        yield f'        set dstaddr{field_suffix} "{destination}"'
        other_suffix = "6" if rule.family == 4 else ""
        yield f"        unset srcaddr{other_suffix}"
        yield f"        unset dstaddr{other_suffix}"
        yield f'        set service "{service}"'
        yield '        set schedule "always"'
        yield f"        set action {'deny' if config['mode'] == 'block' else 'accept'}"
        yield "        set logtraffic all"
        yield "    next"
        yield "end"


def _warnings(config):
    warnings = [
        "Reserve the generated numeric policy ID range in the selected VDOM: edit modifies existing IDs. IDs are"
        " assigned in sorted order and can change when the indicator set changes; remove stale policies and objects."
    ]
    if config["mode"] == "log":
        warnings.append(acl.PERMIT_LOG_WARNING)
    return warnings


def handler(q=False):
    return acl.handle(q, moduleinfo["name"], _configure, _render, _warnings, supports_zero=False)


def introspection():
    result = acl.introspection(EXTRA_CONFIG)
    result["userConfig"]["name_prefix"] = {
        "type": "String",
        "message": "Managed name prefix, 1-18 ASCII characters (default: MISP-IOC)",
    }
    result["userConfig"]["mode"] = {"type": "String", "message": "block (deny) or log (accepts matching traffic)"}
    return result


def version():
    return dict(moduleinfo, config=moduleconfig)
