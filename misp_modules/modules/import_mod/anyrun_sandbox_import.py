import json
import traceback

from anyrun import RunTimeException
from anyrun.connectors import SandboxConnector

from anyrun_sandbox.config import Config
from anyrun_sandbox.parser import AnyRunParser


moduleinfo = {
    "version": "0.1",
    "author": "ANY.RUN integrations team",
    "description": (
        "A module designed to retrieve an analysis report from the ANY.RUN Sandbox by its unique ID "
        "and extract results (such as verdict, malware tags, and IOCs), "
        "converting them into MISP attributes within your event."
    ),
    "module-type": ["import"],
    "name": "ANYRUN Sandbox Import",
    "logo": "anyrun.png",
    "requirements": [
        "anyrun-sdk: ANY.RUN API python3 library",
        "ANY.RUN Sandbox API-KEY"
    ],
    "features": (
        "Fetches detailed JSON reports using the ANY.RUN API; "
        "parses key elements like verdict, extracted IOCs (hashes, IPs, URLs), malware tags; "
        "maps data to MISP attributes and galaxies (e.g., malware family or MITRE ATT&CK Techniques)."
    ),
    "references": ["https://any.run"],
    "input": "ANY.RUN Sandbox analysis UUID.",
    "output": "Analysis external references, verdict, IOCs (hashes, IPs, URLs), malware tags, MITRE ATT&CK Techniques"
}

mispattributes = {
    "inputSource": [],
    "output": ["MISP objects"],
    "format": "misp_standard",
}

userConfig = {
    "ANYRUN Analysis UUID": {
        "type": "String",
        "message": "ANY.RUN Analysis UUID",
        "required": True,
    },
    "IOCs": {
        "type": "Boolean",
        "message": "Include ANY.RUN Sandbox Indicators",
        "checked": "True",
    },
    "Tags": {
        "type": "Boolean",
        "message": "Include ANY.RUN Sandbox Tags",
        "checked": "True",
    },
    "MITRE": {
        "type": "Boolean",
        "message": "Include ANY.RUN Sandbox MITRE ATT&CK Techniques",
        "checked": "True",
    }
}

moduleconfig = [
    "api_key"
]


def handler(q=False):
    if q is False:
        return False

    try:
        request = json.loads(q)

        token = request.get("config").get("api_key")
        analysis_uuid = request.get("config").get("ANYRUN Analysis UUID")

        if not any((token, analysis_uuid)):
            raise RunTimeException(f"ANY.RUN API-KEY and Analysis UUID must be specified.")

        with SandboxConnector.windows(token, integration=Config.INTEGRATION) as connector:
            connector.check_authorization()

            parser = AnyRunParser(request.get("config"), analysis_uuid, connector)
            results = parser.generate_results()

            return results

    except RunTimeException as exception:
        return {"error": str(exception)}
    except Exception:
        return {"error": f"Unspecified exception: {traceback.format_exc()}"}


def introspection():
    mispattributes["userConfig"] = userConfig
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
