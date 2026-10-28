"""Enrich phone numbers locally using libphonenumber's numbering-plan metadata."""

import json

import phonenumbers
from phonenumbers import carrier, geocoder, timezone
from pymisp import MISPEvent, MISPObject
from pymisp.exceptions import PyMISPError

from . import check_input_attribute, standard_error_message

mispattributes = {
    "input": ["phone-number", "whois-registrant-phone"],
    "output": ["MISP objects", "text"],
    "format": "misp_standard",
}
moduleconfig = ["default_region", "language"]
moduleinfo = {
    "version": "0.1",
    "author": "MISP Project",
    "description": "Offline phone-number normalization, numbering-plan geography and original carrier lookup.",
    "module-type": ["expansion"],
    "name": "Phone Number Information",
    "logo": "",
    "requirements": ["phonenumbers >=9.0,<10.0 (included in the minimal and all installation extras)"],
    "features": (
        "Parse phone-number and whois-registrant-phone attributes locally without API credentials or network calls.\n"
        "International numbers beginning with + need no configuration. National numbers and international dialling "
        "prefixes require default_region, a two-letter region code such as GB. The region is never guessed.\n"
        "Return a phone-number object with E.164 normalization, calling code, inferred region and a labeled text "
        "summary of validity, number type, numbering-plan area, original carrier, possible time zones and library "
        "version. Preserve extensions separately in the summary and retain the original attribute and its UUID.\n"
        "language selects the geographic/carrier description language (default en). Missing metadata is Unknown.\n"
        "A parseable but invalid number returns only the original attribute and a non-correlating text diagnostic. "
        "Malformed or ambiguous input returns an error. Short codes are outside the module's scope.\n"
        "Location describes numbering-plan allocation, not the subscriber's physical location. Carrier metadata "
        "may identify the original carrier rather than the current operator after number portability. "
        "Validity does not establish assignment, reachability or ownership."
    ),
    "references": [
        "https://github.com/daviddrysdale/python-phonenumbers",
        "https://github.com/google/libphonenumber/blob/master/FAQ.md",
        "https://github.com/MISP/misp-modules/issues/538",
    ],
    "input": "A phone-number or whois-registrant-phone attribute with type, value and uuid.",
    "output": "The original attribute and a linked phone-number object, or a text diagnostic for invalid numbers.",
}


def _summary(number, original, language):
    zones = [zone for zone in timezone.time_zones_for_number(number) if zone != "Etc/Unknown"]
    return "\n".join(
        [
            f"Original input: {original}",
            "Possible: true",
            "Valid according to numbering plan: true",
            f"Number type: {phonenumbers.PhoneNumberType.to_string(phonenumbers.number_type(number))}",
            f"Numbering-plan area: {geocoder.description_for_number(number, language) or 'Unknown'}",
            f"Original carrier: {carrier.name_for_number(number, language) or 'Unknown'}",
            f"Possible time zones: {', '.join(zones) or 'Unknown'}",
            f"Extension: {number.extension or 'None'}",
            f"Metadata source: phonenumbers {phonenumbers.__version__}",
            "Area is numbering-plan geography, not the subscriber's physical location.",
            "Original carrier may differ from the current operator after number portability.",
            "Validity does not establish assignment, reachability or ownership.",
        ]
    )


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
    except (TypeError, ValueError):
        return {"error": "Invalid JSON request."}
    if not isinstance(request, dict):
        return {"error": "The request must be a JSON object."}

    attribute = request.get("attribute")
    if not isinstance(attribute, dict) or not check_input_attribute(attribute):
        return {"error": f"{standard_error_message}, containing type, value and uuid."}
    if attribute["type"] not in mispattributes["input"]:
        return {"error": "Wrong input attribute type."}
    original = attribute["value"]
    if not isinstance(original, str) or not original.strip():
        return {"error": "The phone number must be a nonempty string."}

    config = request.get("config")
    if config is None:
        config = {}
    if not isinstance(config, dict):
        return {"error": "Configuration must be an object."}
    region = config.get("default_region")
    if region is None or region == "":
        region = None
    elif not isinstance(region, str) or region.strip().upper() not in phonenumbers.SUPPORTED_REGIONS:
        return {"error": "default_region must be a supported two-letter region code, such as GB."}
    else:
        region = region.strip().upper()
    language = config.get("language")
    if language is None or language == "":
        language = "en"
    if not isinstance(language, str) or not language.strip():
        return {"error": "language must be a nonempty language code, such as en."}
    language = language.strip()

    if not original.strip().startswith("+") and region is None:
        return {"error": "Use an international number beginning with + or configure default_region."}
    try:
        number = phonenumbers.parse(original, region)
    except phonenumbers.NumberParseException as error:
        return {"error": f"Unable to parse the phone number: {error}"}

    event = MISPEvent()
    try:
        source = event.add_attribute(**attribute)
    except (PyMISPError, TypeError, ValueError) as error:
        return {"error": f"Invalid input attribute: {error}"}

    if not phonenumbers.is_valid_number(number):
        possible = str(phonenumbers.is_possible_number(number)).lower()
        event.add_attribute(
            type="text",
            value=(
                f"Original input: {original}\nPossible: {possible}\nValid according to numbering plan: false\n"
                "No normalized phone-number object was created. This does not establish whether the number is "
                f"assigned or reachable.\nMetadata source: phonenumbers {phonenumbers.__version__}"
            ),
            comment=f"phone_number_info diagnostic for attribute {source.uuid}",
            to_ids=False,
            disable_correlation=True,
        )
    else:
        phone = MISPObject("phone-number")
        phone.add_attribute("phone-number", phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164))
        phone.add_attribute("country-code-numeric", f"+{number.country_code}")
        number_region = phonenumbers.region_code_for_number(number)
        # 001 denotes a non-geographic calling code, not a country.
        if number_region and number_region != "001":
            phone.add_attribute("country-code", number_region)
        phone.add_attribute("text", _summary(number, original, language))
        phone.add_reference(source.uuid, "derived-from")
        event.add_object(phone)

    event = json.loads(event.to_json())
    return {"results": {"Attribute": event.get("Attribute", []), "Object": event.get("Object", [])}}


def introspection():
    return mispattributes


def version():
    return {**moduleinfo, "config": moduleconfig}
