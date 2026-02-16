import json
import traceback

from anyrun import RunTimeException

from anyrun_sandbox.submitter import AnyRunSubmitter

moduleinfo = {
    "version": "0.1",
    "author": "ANY.RUN integrations team",
    "description": (
        "A module designed to submit URLs or files to the ANY.RUN Sandbox for analysis "
        "and return the unique analysis link and ID."
    ),
    "module-type": ["expansion"],
    "name": "ANYRUN Sandbox Submit",
    "logo": "",
    "requirements": [
        "anyrun-sdk: ANY.RUN API python3 library",
        "ANY.RUN Sandbox API-KEY"
    ],
    "features": (
        "Supports submission of URLs and files via the ANY.RUN API; requires an API key for authentication; "
        "returns the task ID and permanent URL for tracking analysis progress; "
        "integrates seamlessly with MISP events by enriching attributes with submission results."
    ),
    "references": ["https://any.run"],
    "input": "Attachment, malware-sample or url to submit to ANY.RUN Sandbox.",
    "output": "ANY.RUN Sandbox analysis URL and UUID.",
}

moduleconfig = [
    "api_key",
    "os_type",
    "opt_timeout",
    "opt_network_connect",
    "opt_network_fakenet",
    "opt_network_tor",
    "opt_network_geo",
    "opt_network_mitm",
    "opt_network_residential_proxy",
    "opt_network_residential_proxy_geo",
    "opt_privacy_type",
    "obj_ext_extension",
    "obj_ext_browser",
    "env_locale",
    "env_version",
    "env_bitness",
    "env_type",
    "obj_ext_startfolder",
    "obj_ext_cmd",
    "obj_force_elevation",
    "run_as_root"
]

mispattributes = {
    "input": ["attachment", "malware-sample", "url"],
    "output": ["link", "text"],
}


def handler(q=False):
    if q is False:
        return False

    try:

        request = json.loads(q)
        submitter = AnyRunSubmitter(request)
        analysis_uuid = submitter.submit()

        return {
            "results": [
                {
                    "types": "link",
                    "categories": "External analysis",
                    "values": f"https://app.any.run/tasks/{analysis_uuid}",
                    "comment": f"ANY.RUN Analysis URL for attribute with ID = {request.get('attribute_uuid')}",
                },
                {
                    "types": "text",
                    "categories": "Other",
                    "values": analysis_uuid,
                    "comment": f"ANY.RUN Analysis ID for attribute with ID = {request.get('attribute_uuid')}"
                }
            ]
        }
    except RunTimeException as exception:
        return {"error": str(exception)}
    except Exception:
        return {"error": f"Unspecified exception: {traceback.format_exc()}"}


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
