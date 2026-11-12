import json
import math
import re
from datetime import date, datetime, timedelta, timezone

import requests
from pymisp import MISPEvent, MISPObject

mispattributes = {"input": ["AS"], "format": "misp_standard"}
moduleconfig = ["date", "address_family"]
moduleinfo = {
    "version": "1",
    "author": "Raphaël Vinot, MISP Project",
    "name": "BGP Ranking",
    "description": "Query CIRCL BGP Ranking for the daily ranking of an Autonomous System number.",
    "module-type": ["expansion", "hover"],
    "logo": "",
    "requirements": ["requests", "PyMISP"],
    "features": (
        "Queries the public BGP Ranking API without an API key. Returns linked asn and bgp-ranking objects using"
        " existing templates. The optional date (YYYY-MM-DD) defaults to yesterday in UTC; address_family defaults"
        " to v4 and also accepts v6. ASNs without a ranking entry return ASN context only, not a clean verdict."
        " See documentation/expansion/bgpranking.md."
    ),
    "references": ["https://bgpranking.circl.lu/", "https://github.com/D4-project/BGP-Ranking/"],
    "input": "An AS attribute, such as AS13335 or 13335.",
    "output": "An asn object linked to the source attribute and, when ranked, a daily bgp-ranking object.",
}

API_URL = "https://bgpranking.circl.lu/json/asn"
TIMEOUT = 30


class ModuleError(ValueError):
    """An input or service error that can be returned to the caller."""


def _asn(value):
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ModuleError("Invalid AS number.")
    number = str(value).strip().upper()
    if number.startswith("AS"):
        number = number[2:]
    if not re.fullmatch(r"[0-9]{1,10}", number) or not 0 <= int(number) <= 4294967295:
        raise ModuleError("Invalid AS number.")
    return str(int(number))


def _options(config):
    if config is None:
        config = {}
    if not isinstance(config, dict):
        raise ModuleError("The config must be a JSON object.")
    day = config.get("date")
    if day is None or day == "":
        day = (datetime.now(timezone.utc).date() - timedelta(days=1)).isoformat()
    if not isinstance(day, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", day):
        raise ModuleError("date must be YYYY-MM-DD.")
    date.fromisoformat(day)
    family = config.get("address_family")
    if family is None or family == "":
        family = "v4"
    if family not in ("v4", "v6"):
        raise ModuleError("address_family must be v4 or v6.")
    return day, family


def _query(number, day, family):
    try:
        response = requests.post(
            API_URL,
            json={"asn": number, "date": day, "ipversion": family},
            headers={"Accept": "application/json"},
            timeout=TIMEOUT,
            allow_redirects=False,
        )
    except requests.RequestException:
        raise ModuleError("BGP Ranking request failed or timed out.") from None
    if response.status_code != 200:
        raise ModuleError(f"BGP Ranking returned HTTP {response.status_code}.")
    try:
        payload = response.json()
    except ValueError:
        raise ModuleError("BGP Ranking returned invalid JSON.") from None
    if not isinstance(payload, dict):
        raise ModuleError("BGP Ranking returned an invalid response.")
    if payload.get("error"):
        raise ModuleError("BGP Ranking reported an API error.")
    # The API echoes the query in meta; it does not resolve a latest available date.
    meta = payload.get("meta")
    if (
        not isinstance(meta, dict)
        or _asn(meta.get("asn")) != number
        or meta.get("date") != day
        or meta.get("ipversion") != family
    ):
        raise ModuleError("BGP Ranking returned unexpected query metadata.")
    data = payload.get("response")
    if not isinstance(data, dict):
        raise ModuleError("BGP Ranking returned invalid data.")
    return data


def _ranking(data):
    ranking = data.get("ranking")
    if not isinstance(ranking, dict):
        raise ModuleError("BGP Ranking returned an invalid ranking.")
    rank = ranking.get("rank")
    position = ranking.get("position")
    total = ranking.get("total_known_asns")
    if (
        isinstance(rank, bool)
        or not isinstance(rank, (int, float))
        or not math.isfinite(rank)
        or rank < 0
        or type(total) is not int
        or total < 0
        or "position" not in ranking
    ):
        raise ModuleError("BGP Ranking returned an invalid ranking.")
    if position is None:
        # The service uses zero for ASNs absent from the day's ranked set.
        if rank != 0:
            raise ModuleError("BGP Ranking returned a score without a position.")
    elif type(position) is not int or not 1 <= position <= total:
        raise ModuleError("BGP Ranking returned an invalid position.")
    return rank, position, total


def _expand(event, attribute, number, day, family, data):
    rank, position, total = _ranking(data)
    description = data.get("asn_description")
    # Unknown ASNs have an empty mapping instead of a description string.
    if description is not None and not isinstance(description, str) and description != {}:
        raise ModuleError("BGP Ranking returned an invalid ASN description.")
    asn = MISPObject("asn")
    asn.comment = f"CIRCL BGP Ranking; date: {day}; address family: {family}; total known ASNs: {total}."
    asn.add_attribute("asn", value=f"AS{number}", to_ids=False)
    if description:
        holder, separator, country = description.rpartition(", ")
        if separator and re.fullmatch(r"[A-Z]{2}", country):
            asn.add_attribute("description", value=holder, to_ids=False)
            asn.add_attribute("country", value=country, to_ids=False)
        else:
            asn.add_attribute("description", value=description, to_ids=False)
    asn.add_reference(attribute["uuid"], "describes")
    if position is None:
        asn.comment += " No ranking entry for this date and address family; this is not a clean verdict."
    else:
        bgp = MISPObject("bgp-ranking")
        bgp.comment = f"CIRCL BGP Ranking; total known ASNs: {total}; position 1 is the most malicious ASN of the day."
        bgp.add_attribute("ranking", value=rank, to_ids=False)
        bgp.add_attribute("position", value=position, to_ids=False)
        bgp.add_attribute("date", value=f"{day}T00:00:00Z", to_ids=False)
        bgp.add_attribute("address-family", value=family, to_ids=False)
        asn.add_reference(bgp.uuid, "ranked-with")
        event.add_object(bgp)
    event.add_object(asn)


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ModuleError("The request must be a JSON object.")
        attribute = request.get("attribute")
        if not isinstance(attribute, dict) or not all(attribute.get(key) for key in ("type", "value", "uuid")):
            raise ModuleError("An attribute containing type, value and uuid is required.")
        if attribute["type"] not in mispattributes["input"]:
            raise ModuleError("Unsupported attribute type.")
        if not isinstance(attribute["value"], str):
            raise ModuleError("The AS attribute value must be a string.")
        number = _asn(attribute["value"])
        day, family = _options(request.get("config"))
        event = MISPEvent()
        event.add_attribute(**attribute)
        _expand(event, attribute, number, day, family, _query(number, day, family))
        result = json.loads(event.to_json())
        return {"results": {key: result.get(key, []) for key in ("Attribute", "Object")}}
    except ModuleError as exc:
        return {"error": str(exc)}
    except (ValueError, TypeError, KeyError):
        return {"error": "Invalid request or BGP Ranking response."}


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)
