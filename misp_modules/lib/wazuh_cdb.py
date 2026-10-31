"""Network-free conversion of selected MISP indicators to a Wazuh CDB list."""

import ipaddress

from misp_modules.lib.indicator_list import HASH_LENGTHS, SUPPORTED_TYPES, boolean, collect

INDICATOR_TYPES = {"ipv4", "ipv6", "domain", *HASH_LENGTHS}
INPUT_TYPES = SUPPORTED_TYPES - {"url"}
MAX_VALUES = 100000
MAX_BYTES = 32 * 1024 * 1024
ACTIVATION_NOTICE = (
    "Register the list under ruleset in ossec.conf, reference it from a detection rule, and reload analysisd through"
    " the Wazuh API to load changes. A full manager restart is not required."
)


def build(data, config, allow_non_ids=False):
    """Return the list bytes, summary and provenance; reject empty/oversized lists."""
    if config is None:
        config = {}
    if not isinstance(config, dict):
        raise ValueError("Configuration must be an object.")
    selected = config.get("indicator_type")
    if selected is None or selected == "":
        selected = "ipv4"
    if not isinstance(selected, str) or selected not in INDICATOR_TYPES:
        raise ValueError("indicator_type must be ipv4, ipv6, domain, md5, sha1, sha256 or sha512.")
    include_non_ids = boolean(config.get("include_non_ids"), "include_non_ids")
    if include_non_ids and not allow_non_ids:
        raise ValueError("The action only publishes to_ids attributes.")
    values, skipped = collect(data, selected, include_non_ids, limit=MAX_VALUES)
    if selected == "ipv6":
        # Python versions differ in displaying IPv4-mapped IPv6. Wazuh's quoted-key
        # validator rejects dots, so spell the final 32 bits as hexadecimal too.
        normalized = {}
        for value, refs in values.items():
            if "." in value:
                prefix, _, tail = value.rpartition(":")
                number = int(ipaddress.IPv4Address(tail))
                value = f"{prefix}:{number >> 16:x}:{number & 0xffff:x}"
            normalized[value] = refs
        values = normalized
    if not values:
        raise ValueError("No exportable indicators for the selected type; refusing to produce an empty CDB list.")
    # Colon-containing keys must be quoted. Normalized IPv6 contains only hex digits and colons,
    # as required by Wazuh's CDB upload validator. URLs cannot be represented by that validator.
    output = "".join(f'"{value}":\n' if ":" in value else f"{value}:\n" for value in sorted(values)).encode("ascii")
    if len(output) > MAX_BYTES:
        raise ValueError(f"CDB list exceeds {MAX_BYTES:,} bytes; split the input.")
    return output, {"indicator_type": selected, "count": len(values), "skipped": skipped}, values


def warnings(summary):
    notice = (
        "Wazuh acknowledged the ruleset reload request; check analysisd logs to confirm completion."
        if summary.get("activation") == "reload_requested"
        else ACTIVATION_NOTICE
    )
    messages = [notice] + [
        f"Skipped {count} {reason} attribute(s)." for reason, count in sorted(summary["skipped"].items())
    ]
    if summary.get("reload_warning_nodes"):
        messages.append("Wazuh reported ruleset reload warnings; inspect analysisd logs on the indicated nodes.")
    return messages
