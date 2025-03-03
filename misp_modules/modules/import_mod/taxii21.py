"""
Import content from a TAXII 2.1 server.
"""

import collections
import itertools
import json
import re
from pathlib import Path

import requests
import taxii2client
import taxii2client.exceptions
from misp_stix_converter import ExternalSTIX2toMISPParser, InternalSTIX2toMISPParser, _is_stix2_from_misp
from stix2.v20 import Bundle as Bundle_v20
from stix2.v21 import Bundle as Bundle_v21


class ConfigError(Exception):
    """
    Represents an error in the config settings for one invocation of this
    module.
    """

    pass


misperrors = {"error": "Error"}

moduleinfo = {
    "version": "0.2",
    "author": "Abc",
    "description": "Import content from a TAXII 2.1 server",
    "module-type": ["import"],
    "name": "TAXII 2.1 Import",
    "logo": "",
    "requirements": ["misp-lib-stix2", "misp-stix"],
    "features": "",
    "references": [],
    "input": "",
    "output": "",
}

mispattributes = {
    "inputSource": [],
    "output": ["MISP objects"],
    "format": "misp_standard",
}


userConfig = {
    "url": {
        "type": "String",
        "message": "A TAXII 2.1 collection URL",
        "required": True,
    },
    "added_after": {
        "type": "String",
        "message": "Lower bound on time the object was uploaded to the TAXII server",
    },
    "stix_id": {"type": "String", "message": "STIX ID(s) of objects"},
    "spec_version": {  # TAXII 2.1 specific
        "type": "String",
        "message": "STIX version(s) of objects",
    },
    "type": {"type": "String", "message": "STIX type(s) of objects"},
    "version": {
        "type": "String",
        "message": 'Version timestamp(s), or "first"/"last"/"all"',
    },
    # Should we give some user control over this?  It will not be allowed to
    # exceed the admin setting.
    "STIX object limit": {
        "type": "Integer",
        "message": "Maximum number of STIX objects to process",
    },
    "username": {
        "type": "String",
        "message": "Username for TAXII server authentication, if necessary",
    },
    "password": {
        "type": "String",
        "message": "Password for TAXII server authentication, if necessary",
    },
}

# Paging will be handled transparently by this module, so user-defined
# paging-related filtering parameters will not be supported.


# This module will not process more than this number of STIX objects in total
# from a TAXII server in one module invocation (across all pages), to limit
# resource consumption.
moduleconfig = ["stix_object_limit"]


# In case there is neither an admin nor user setting given.
_DEFAULT_STIX_OBJECT_LIMIT = 1000


# Page size to use when paging TAXII results.  Trades off the amount of
# hammering on TAXII servers and overhead of repeated requests, with the
# resource consumption of a single page.  (Should be an admin setting too?)
_PAGE_SIZE = 100


_synonymsToTagNames_path = Path(__file__).parent / "../../lib/synonymsToTagNames.json"


# Collects module config information necessary to perform the TAXII query.
Config = collections.namedtuple(
    "Config",
    [
        "url",
        "added_after",
        "id",
        "spec_version",
        "type",
        "version",
        "stix_object_limit",
        "username",
        "password",
    ],
)


def _pymisp_to_json_serializable(obj):
    """
    Work around a possible bug with PyMISP's
    AbstractMisp.to_dict(json_format=True) method, which doesn't always produce
    a JSON-serializable value (i.e. a value which is serializable with the
    default JSON encoder).

    :param obj: A PyMISP object
    :return: A JSON-serializable version of the object
    """

    # The workaround creates a JSON string and then parses it back to a
    # JSON-serializable value.
    json_ = obj.to_json()
    json_serializable = json.loads(json_)

    return json_serializable


def _normalize_multi_values(value):
    """
    Some TAXII filters may contain multiple values separated by commas,
    without spaces around the commas.  Maybe give MISP users a little more
    flexibility?  This function normalizes a possible multi-valued value
    (e.g. multiple values delimited by commas or spaces, all in the same
    string) to TAXII-required format.

    :param value: A MISP config value
    :return: A normalized value
    """

    if "," in value:
        value = re.sub(r"\s*,\s*", ",", value)
    else:
        # Assume space delimiting; replace spaces with commas.
        # I don't think we need to worry about spaces embedded in values.
        value = re.sub(r"\s+", ",", value)

    value = value.strip(",")

    return value


def _get_config(config):
    """
    Combine user, admin, and default config settings to produce a config
    object with all settings together.

    :param config: The misp-modules request's "config" value.
    :return: A Config object
    :raises ConfigError: if any config errors are detected
    """

    # Strip whitespace from all config settings... except for password?
    for key, val in config.items():
        if isinstance(val, str) and key != "password":
            config[key] = val.strip()

    url = config.get("url")
    added_after = config.get("added_after")
    id_ = config.get("stix_id")
    spec_version = config.get("spec_version")
    type_ = config.get("type")
    version_ = config.get("version")
    username = config.get("username")
    password = config.get("password")
    admin_stix_object_limit = config.get("stix_object_limit")
    user_stix_object_limit = config.get("STIX object limit")

    if admin_stix_object_limit:
        admin_stix_object_limit = int(admin_stix_object_limit)
    else:
        admin_stix_object_limit = _DEFAULT_STIX_OBJECT_LIMIT

    if user_stix_object_limit:
        user_stix_object_limit = int(user_stix_object_limit)
        stix_object_limit = min(user_stix_object_limit, admin_stix_object_limit)
    else:
        stix_object_limit = admin_stix_object_limit

    # How much of this should we sanity-check here before passing it off to the
    # TAXII client (and thence, to the TAXII server)?

    if not url:
        raise ConfigError("A TAXII 2.1 collection URL is required.")

    if admin_stix_object_limit < 1:
        raise ConfigError("Invalid admin object limit: must be positive: " + str(admin_stix_object_limit))

    if stix_object_limit < 1:
        raise ConfigError("Invalid object limit: must be positive: " + str(stix_object_limit))

    if id_:
        id_ = _normalize_multi_values(id_)
    if spec_version:
        spec_version = _normalize_multi_values(spec_version)
    if type_:
        type_ = _normalize_multi_values(type_)
    if version_:
        version_ = _normalize_multi_values(version_)

    # STIX->MISP converter currently only supports STIX 2.0, so let's force
    # spec_version="2.0".
    if not spec_version:
        spec_version = "2.1"
    if spec_version not in ("2.0", "2.1"):
        raise ConfigError('Only spec versions "2.0" and "2.1" are valid versions.')

    if (username and not password) or (not username and password):
        raise ConfigError('Both or neither of "username" and "password" are required.')

    config_obj = Config(
        url,
        added_after,
        id_,
        spec_version,
        type_,
        version_,
        stix_object_limit,
        username,
        password,
    )

    return config_obj


def _query_taxii(config):
    """
    Query the TAXII server according to the given config, convert the STIX
    results to MISP, and return a standard misp-modules response.

    :param config: Module config information as a Config object
    :return: A dict containing a misp-modules response
    """

    collection = taxii2client.Collection(config.url, user=config.username, password=config.password)

    # No point in asking for more than our overall limit.
    page_size = min(_PAGE_SIZE, config.stix_object_limit)

    kwargs = {"per_request": page_size}

    if config.spec_version:
        kwargs["spec_version"] = config.spec_version
    if config.version:
        kwargs["version"] = config.version
    if config.id:
        kwargs["id"] = config.id
    if config.type:
        kwargs["type"] = config.type
    if config.added_after:
        kwargs["added_after"] = config.added_after

    pages = taxii2client.as_pages(collection.get_objects, **kwargs)

    # Chain all the objects from all pages together...
    all_stix_objects = itertools.chain.from_iterable(taxii_envelope.get("objects", []) for taxii_envelope in pages)

    # And only take the first N objects from that.
    limited_stix_objects = itertools.islice(all_stix_objects, 0, config.stix_object_limit)

    # Collect into a list.  This is... unfortunate, but I don't think the
    # converter will work incrementally (will it?).  It expects all objects to
    # be given at once.
    #
    # It may also be desirable to have all objects available at once so that
    # cross-references can be made where possible, but it results in increased
    # memory usage.
    stix_objects = list(limited_stix_objects)

    bundle = (Bundle_v21 if config.spec_version == "2.1" else Bundle_v20)(stix_objects, allow_custom=True)

    converter = InternalSTIX2toMISPParser() if _is_stix2_from_misp(bundle.objects) else ExternalSTIX2toMISPParser()
    converter.load_stix_bundle(bundle)
    converter.parse_stix_bundle(single_event=True)

    attributes = [_pymisp_to_json_serializable(attr) for attr in converter.misp_event.attributes]

    objects = [_pymisp_to_json_serializable(obj) for obj in converter.misp_event.objects]

    tags = [_pymisp_to_json_serializable(tag) for tag in converter.misp_event.tags]

    result = {"results": {"Attribute": attributes, "Object": objects, "Tag": tags}}

    return result


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)

    result = None
    config = None

    try:
        config = _get_config(request["config"])
    except ConfigError as e:
        result = misperrors
        result["error"] = e.args[0]

    if not result:
        try:
            result = _query_taxii(config)
        except taxii2client.exceptions.TAXIIServiceException as e:
            result = misperrors
            result["error"] = str(e)
        except requests.HTTPError as e:
            # Let's give a better error message for auth issues.
            if e.response.status_code in (401, 403):
                result = misperrors
                result["error"] = "Access was denied."
            else:
                raise

    return result


def introspection():
    mispattributes["userConfig"] = userConfig
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
