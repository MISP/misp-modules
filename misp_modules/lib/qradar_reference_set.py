"""QRadar reference-set types and compatibility exports for shared indicator collection."""

from misp_modules.lib.indicator_list import HASH_LENGTHS, SUPPORTED_TYPES, boolean, collect, indicator_type

ENTRY_TYPES = {
    "ipv4": {"IP"},
    "ipv6": {"ALN"},
    "domain": {"ALN", "ALNIC"},
    "url": {"ALN"},
    **{kind: {"ALN", "ALNIC"} for kind in HASH_LENGTHS},
}

__all__ = ["HASH_LENGTHS", "ENTRY_TYPES", "SUPPORTED_TYPES", "boolean", "collect", "indicator_type"]
