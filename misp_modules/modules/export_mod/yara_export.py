import base64
import json
import re

import yara

misperrors = {"error": "Error"}


userConfig = {}

moduleconfig = []

# fixed for now, options in the future:
# event, attribute, event-collection, attribute-collection
inputSource = ["event"]

outputFileExtension = "yara"
responseType = "text/plain"


moduleinfo = {
    "version": "0.1",
    "author": "Christophe Vandeplas",
    "description": "This module is used to export MISP events to YARA.",
    "module-type": ["export"],
    "name": "YARA Rule Export",
    "logo": "yara.png",
    "requirements": ["yara-python python library"],
    "features": (
        "The module will dynamically generate YARA rules for attributes that are marked as to IDS. Basic metadata about"
        " the event is added to the rule.\nAttributes that are already YARA rules are also exported, with a rewritten"
        " rule name."
    ),
    "references": ["https://virustotal.github.io/yara/"],
    "input": "Attributes and Objects.",
    "output": "A YARA file that can be used with the YARA scanning tool.",
}


class YaraRule:
    def __init__(self, name):
        self.name = name
        self.strings = {}
        self.conditions = []
        self.meta = {}

    def add_string(self, type_: str, s: str):
        type_clean = "".join(c if c.isalnum() or c == "_" else "_" for c in type_)
        if type_clean not in self.strings:
            self.strings[type_clean] = []
        self.strings[type_clean].append(s)

    def add_condition(self, condition: str):
        self.conditions.append(condition)

    def add_meta(self, key: str, value: str):
        if key not in self.meta:
            self.meta[key] = []
        self.meta[key].append(value)

    def __str__(self):
        if len(self.strings) == 0 and len(self.conditions) == 0:
            return "\n"  # no strings, so no rule

        result = []
        result.append(f"rule {self.name} {{")

        result.append("    meta:")
        for key, values in self.meta.items():
            i = 0
            if len(values) == 1:
                result.append(f'        {key} = "{values[0]}"')
                continue
            for value in values:
                result.append(f'        {key}_{i} = "{value}"')
                i += 1

        result.append("    strings:")
        for key, values in self.strings.items():
            i = 0
            for value in values:
                result.append(f'        ${key}_{i} = "{value}"')
                i += 1

        result.append("    condition:")
        if len(self.conditions) == 0:
            result.append("        any of them")
        for condition in self.conditions:
            result.append(f"        {condition}")

        result.append("}")
        result.append("")
        return "\n".join(result)


def handle_string(yara_rules: list, yr: YaraRule, attribute: dict):
    if not attribute["to_ids"]:  # skip non IDS attributes
        return
    yr.add_string(attribute["type"], attribute["value"])
    return


def handle_combined(yara_rules: list, yr: YaraRule, attribute: dict):
    if not attribute["to_ids"]:  # skip non IDS attributes
        return
    type_1, type_2 = attribute["type"].split("|")
    value_1, value_2 = attribute["value"].split("|")
    try:
        handlers[type_1](yara_rules, yr, type_1, value_1)
    except KeyError:
        # ignore unsupported types
        pass
    try:
        handlers[type_2](yara_rules, yr, type_2, value_2)
    except KeyError:
        # ignore unsupported types
        pass


def handle_yara(yara_rules: list, yr: YaraRule, attribute: dict):
    # do not check for to_ids, as we want to always export the Yara rule
    # split out as a separate rule, and rewrite the rule name
    value = re.sub(
        "^[ \t]*rule ",
        "rule MISP_e{}_".format(attribute["event_id"]),
        attribute["value"],
        flags=re.MULTILINE,
    )
    # cleanup dirty stuff from people
    substitutions = (
        ("”", '"'),
        ("“", '"'),
        ("″", '"'),
        ("`", "'"),
        ("\r", ""),
        ("Rule ", "rule "),  # some people write this with the wrong case
        # ('$ ', '$'),    # this breaks rules
        # ('\t\t', '\n'), # this breaks rules
    )
    for substitution in substitutions:
        if substitution[0] in value:
            value = value.replace(substitution[0], substitution[1])

    # we may ignore any global rules as they might disable everything
    # on the other hand we're only processing one event...
    # if 'global rule' in value:
    #     return

    # private rules need some more rewriting
    if "private rule" in value:
        priv_rules = re.findall(r"private rule (\w+)", value, flags=re.MULTILINE)
        for priv_rule in priv_rules:
            value = re.sub(
                priv_rule,
                "MISP_e{}_{}".format(attribute["event_id"], priv_rule),
                value,
                flags=re.MULTILINE,
            )

    # compile the yara rule to confirm it's validity
    try:
        yara.compile(source=value)
    except Exception:
        # skip rules that do not compile
        return

    # all checks done, add the rule
    yara_rules.append(value)
    return


def handle_malware_sample(yara_rules: list, yr: YaraRule, attribute: dict):
    if not attribute["to_ids"]:  # skip non IDS attributes
        return
    handle_combined(yara_rules, yr, "filename|md5", attribute["value"])


def handle_meta(yara_rules: list, yr: YaraRule, attribute: dict):
    yr.add_meta(attribute["type"], attribute["value"])
    return


handlers = {
    "yara": handle_yara,
    "hostname": handle_string,
    "hostname|port": handle_combined,
    "domain": handle_string,
    "domain|ip": handle_combined,
    "ip": handle_string,
    "ip-src": handle_string,
    "ip-dst": handle_string,
    "ip-dst|port": (
        handle_combined
    ),  # we could also handle_string, which would be more specific. Less false positives, but less true positives too...
    "ip-src|port": handle_combined,
    "url": handle_string,
    "email": handle_string,
    "email-src": handle_string,
    "email-dst": handle_string,
    "email-subject": handle_string,
    "email-attachment": handle_string,
    "email-header": handle_string,
    "email-reply-to": handle_string,
    "email-x-mailer": handle_string,
    "email-mime-boundary": handle_string,
    "email-thread-index": handle_string,
    "email-message-id": handle_string,
    "filename": handle_string,
    "filename|md5": handle_combined,
    "filename|sha1": handle_combined,
    "filename|sha256": handle_combined,
    "filename|authentihash": handle_combined,
    "filename|vhash": handle_combined,
    "filename|ssdeep": handle_combined,
    "filename|imphash": handle_combined,
    "filename|impfuzzy": handle_combined,
    "filename|pehash": handle_combined,
    "filename|sha224": handle_combined,
    "filename|sha384": handle_combined,
    "filename|sha512": handle_combined,
    "filename|sha512/224": handle_combined,
    "filename|sha512/256": handle_combined,
    "filename|sha3-224": handle_combined,
    "filename|sha3-256": handle_combined,
    "filename|sha3-384": handle_combined,
    "filename|sha3-512": handle_combined,
    "filename|tlsh": handle_combined,
    "malware-sample": handle_malware_sample,
    "pattern-in-file": handle_string,
    "pattern-in-traffic": handle_string,
    "pattern-in-memory": handle_string,
    "link": handle_meta,
}

# auto-generate the list of types to use
types_to_use = handlers.keys()


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)

    yara_rules = []
    for event in request["data"]:
        event_info_clean = "".join(c if c.isalnum() or c == "_" else "_" for c in event["Event"]["info"])
        yr = YaraRule(f"MISP_e{event['Event']['id']}_{event_info_clean}")

        yr.add_meta("description", event["Event"]["info"])
        yr.add_meta("author", f"MISP - {event['Orgc']['name']}")
        yr.add_meta("misp_event_date", event["Event"]["date"])
        yr.add_meta("misp_event_id", event["Event"]["id"])
        yr.add_meta("misp_event_uuid", event["Event"]["uuid"])

        for attribute in event.get("Attribute", []):
            try:
                handlers[attribute["type"]](yara_rules, yr, attribute)
            except KeyError:
                # ignore unsupported types
                pass
        for obj in event.get("Object", []):
            for attribute in obj["Attribute"]:
                try:
                    handlers[attribute["type"]](yara_rules, yr, attribute)
                except KeyError:
                    # ignore unsupported types
                    pass
        yara_rules.append(str(yr))
    r = {
        "response": [],
        "data": str(base64.b64encode(bytes("\n".join(yara_rules), "utf-8")), "utf-8"),
    }

    return r


def introspection():
    modulesetup = {}
    try:
        responseType
        modulesetup["responseType"] = responseType
    except NameError:
        pass
    try:
        userConfig
        modulesetup["userConfig"] = userConfig
    except NameError:
        pass
    try:
        outputFileExtension
        modulesetup["outputFileExtension"] = outputFileExtension
    except NameError:
        pass
    try:
        inputSource
        modulesetup["inputSource"] = inputSource
    except NameError:
        pass
    return modulesetup


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
