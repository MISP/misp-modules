import requests
import json

misperrors = {"error": "Error"}
mispattributes = {"input": ["ip-dst", "ip-src"], "output": ["text"]}
moduleinfo = {
    "version": "1.0",
    "author": "Brad Chiappetta <brad@greynoise.io>",
    "description": "Module to access GreyNoise.io API.",
    "module-type": ["hover"],
}
moduleconfig = ["api_key", "api_type"]
codes_mapping = {
    "0x00": "The IP has never been observed scanning the Internet",
    "0x01": "The IP has been observed by the GreyNoise sensor network",
    "0x02": "The IP has been observed scanning the GreyNoise sensor network, "
    "but has not completed a full connection, meaning this can be spoofed",
    "0x03": "The IP is adjacent to another host that has been directly observed by "
    "the GreyNoise sensor network",
    "0x04": "Reserved",
    "0x05": "This IP is commonly spoofed in Internet-scan activity",
    "0x06": "This IP has been observed as noise, but this host belongs to a cloud "
    "provider where IPs can be cycled frequently",
    "0x07": "This IP is invalid",
    "0x08": "This IP was classified as noise, but has not been observed engaging in "
    "Internet-wide scans or attacks in over 60 days",
}


def handler(q=False):  # noqa: C901
    if q is False:
        return False
    request = json.loads(q)
    if not request.get("config") or not request["config"].get("api_key"):
        return {"error": "Missing Greynoise API key."}
    if request["config"]["api_type"] and request["config"]["api_type"] == "enterprise":
        greynoise_api_url = "https://api.greynoise.io/v2/noise/quick/"
    else:
        greynoise_api_url = "https://api.dev.greynoise.io/v3/community/"

    headers = {
        "Accept": "application/json",
        "key": request["config"]["api_key"],
        "User-Agent": "greynoise-misp-module-{}".format(moduleinfo["version"]),
    }
    for input_type in mispattributes["input"]:
        if input_type in request:
            ip = request[input_type]
            break
    else:
        misperrors["error"] = "Unsupported attributes type."
        return misperrors
    response = requests.get(f"{greynoise_api_url}{ip}", headers=headers)  # Real request
    if response.status_code == 200:
        if request["config"]["api_type"] == "enterprise":
            return {
                "results": [
                    {
                        "types": ["text"],
                        "values": codes_mapping[response.json()["code"]],
                    }
                ]
            }
        elif response.json()["noise"]:
            return {
                "results": [
                    {
                        "types": ["text"],
                        "values": "IP Address ({}) has been observed by GreyNoise "
                        "scanning the internet in the last 90 days. GreyNoise has "
                        "classified it as {} and it was last seen on {}. For more "
                        "information visit {}".format(
                            response.json()["ip"],
                            response.json()["classification"],
                            response.json()["last_seen"],
                            response.json()["link"],
                        ),
                    }
                ]
            }
        elif response.json()["riot"]:
            return {
                "results": [
                    {
                        "types": ["text"],
                        "values": "IP Address ({}) is part of GreyNoise Project RIOT "
                        "and likely belongs to a benign service from {}.  For more "
                        "information visit {}".format(
                            response.json()["ip"],
                            response.json()["name"],
                            response.json()["link"],
                        ),
                    }
                ]
            }
    # There is an error
    errors = {
        400: "Bad request.",
        404: "IP not observed scanning the internet or contained in RIOT data set.",
        401: "Unauthorized. Please check your API key.",
        429: "Too many requests. You've hit the rate-limit.",
    }
    try:
        misperrors["error"] = errors[response.status_code]
    except KeyError:
        misperrors[
            "error"
        ] = f"GreyNoise API not accessible (HTTP {response.status_code})"
    return misperrors


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
