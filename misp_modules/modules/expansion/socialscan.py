import json

from pymisp import MISPAttribute, MISPEvent, MISPObject
from socialscan.platforms import Platforms
from socialscan.util import sync_execute_queries

from . import check_input_attribute, standard_error_message

moduleinfo = {
    "version": "2",
    "author": "Christian Studer",
    "description": (
        "A hover module to get information on the availability of an email address or username on some online"
        " platforms."
    ),
    "module-type": ["hover"],
    "name": "Socialscan Lookup",
    "logo": "",
    "requirements": ["The socialscan python library"],
    "features": (
        "The module takes an email address or username as input and check its availability on some online platforms."
        " The results for each platform are then returned to see if the email address or the username is used,"
        " available or if there is an issue with it."
    ),
    "references": ["https://github.com/iojw/socialscan"],
    "input": "An email address or usename attribute.",
    "output": "One user-account object per online platform the email address or username has an account on.",
}
mispattributes = {
    "input": [
        "github-username",
        "target-user",
        "email",
        "email-src",
        "email-dst",
        "target-email",
        "whois-registrant-email",
    ],
    "format": "misp_standard",
}
moduleconfig = []

_PLATFORMS = [
    Platforms.INSTAGRAM,
    Platforms.TWITTER,
    Platforms.GITHUB,
    Platforms.TUMBLR,
    Platforms.LASTFM,
]
_EMAIL_PLATFORMS = [Platforms.PINTEREST, Platforms.SPOTIFY, Platforms.FIREFOX]
_EMAIL_PLATFORMS.extend(_PLATFORMS)
_USERNAME_PLATFORMS = [
    Platforms.SNAPCHAT,
    Platforms.GITLAB,
    Platforms.REDDIT,
    Platforms.YAHOO,
]
_USERNAME_PLATFORMS.extend(_PLATFORMS)


def parse_results(query_results, attribute, relation):
    """One user-account object per platform the value has an account on.

    A platform that answered "available" has no account to describe, and one
    that failed or rejected the value has nothing to say about it either, so
    neither produces an object."""
    misp_event = MISPEvent()
    input_attribute = MISPAttribute()
    input_attribute.from_dict(**attribute)
    misp_event.add_attribute(**input_attribute)

    found = 0
    for result in query_results:
        if not result.success or not result.valid or result.available:
            continue
        user_account = MISPObject("user-account")
        user_account.add_attribute("account-type", str(result.platform))
        user_account.add_attribute(relation, attribute["value"])
        if relation == "email":
            # user-account requires one of username / user-id / password, and on
            # these platforms the address is what identifies the account.
            user_account.add_attribute("user-id", attribute["value"])
        user_account.add_reference(input_attribute.uuid, "related-to")
        misp_event.add_object(user_account)
        found += 1

    if not found:
        return {"error": f"No account linked to {attribute['value']} found on the platforms queried."}
    event = json.loads(misp_event.to_json())
    return {"results": {key: event[key] for key in ("Attribute", "Object") if (key in event and event[key])}}


def parse_email(attribute):
    results = sync_execute_queries([attribute["value"]], platforms=_EMAIL_PLATFORMS)
    return parse_results(results, attribute, "email")


def parse_username(attribute, platforms=_USERNAME_PLATFORMS):
    results = sync_execute_queries([attribute["value"]], platforms=platforms)
    return parse_results(results, attribute, "username")


def parse_github_username(attribute):
    return parse_username(attribute, platforms=[Platforms.GITHUB])


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get("attribute") or not check_input_attribute(request["attribute"]):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    attribute = request["attribute"]
    if attribute["type"] == "github-username":
        return parse_github_username(attribute)
    if attribute["type"] == "target-user":
        return parse_username(attribute)
    if attribute["type"] in mispattributes["input"][2:]:
        return parse_email(attribute)
    return {"error": "Unsupported attributes type"}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
