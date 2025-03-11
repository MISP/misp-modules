import json

misperrors = {"error": "Error"}

# config fields that your code expects from the site admin
moduleconfig = {
    "params": {
        "foo": {"type": "string", "description": "blablabla", "value": "xyz"},
        "Data extraction path": {
            # Extracted data can be found under the `matchingData` key
            "type": "hash_path",
            "description": "Only post content extracted from this path",
            "value": "Attribute.{n}.AttributeTag.{n}.Tag.name",
        },
    },
    # Blocking modules break the exection of the current of action
    "blocking": False,
    # Indicates whether parts of the data passed to this module should be extracted. Extracted data can be found under the `filteredItems` key
    "support_filters": False,
    # Indicates whether the data passed to this module should be compliant with the MISP core format
    "expect_misp_core_format": False,
}

# returns either "boolean" or "data"
# Boolean is used to simply signal that the execution has finished.
# For blocking modules the actual boolean value determines whether we break execution
returns = "boolean"

moduleinfo = {
    "version": "0.1",
    "author": "Andras Iklody",
    "description": "This module is merely a test, always returning true. Triggers on event publishing.",
    "module-type": ["action"],
    "name": "Test action",
    "logo": "",
    "requirements": [],
    "features": "",
    "references": [],
    "input": "",
    "output": "",
}


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)  # noqa
    success = True
    r = {"data": success}
    return r


def introspection():
    modulesetup = {}
    try:
        modulesetup["config"] = moduleconfig
    except NameError:
        pass
    return modulesetup


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
