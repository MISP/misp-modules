"""Adapt both module response formats to the generic CSV exporter."""

import base64
import json

from misp_modules.modules.export_mod.csv_export import handler


def export_result(result, query, module):
    if not isinstance(result, dict) or "error" in result:
        raise ValueError("This module result cannot be exported as CSV.")
    results = result.get("results")
    if isinstance(results, dict):
        event = {key: results[key] for key in ("Attribute", "Object") if key in results}
        if not event:
            raise ValueError("This module result has no exportable attributes.")
    elif isinstance(results, list):
        attributes = []
        for group in results:
            if not isinstance(group, dict):
                raise ValueError("Invalid attribute result.")
            types = group.get("types", [])
            values = group.get("values", [])
            if not isinstance(types, list) or not isinstance(values, list):
                raise ValueError("Result types and values must be lists.")
            # Each legacy value is offered for every suggested MISP type.
            for kind in types:
                for value in values:
                    attributes.append(
                        {
                            **{
                                key: group[key]
                                for key in ("category", "comment", "to_ids")
                                if key in group
                            },
                            "type": kind,
                            "value": value,
                        }
                    )
        event = {"Attribute": attributes}
    else:
        raise ValueError("This module result has no exportable attributes.")
    event["info"] = f"{module}: {query}"
    response = handler(json.dumps({"data": [event]}))
    if "error" in response:
        raise ValueError(response["error"])
    return base64.b64decode(response["data"])
