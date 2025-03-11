import json
import logging
import os
import sys

from apiosintDS import apiosintDS

log = logging.getLogger("apiosintDS")
log.setLevel(logging.DEBUG)
apiodbg = logging.StreamHandler(sys.stdout)
apiodbg.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
apiodbg.setFormatter(formatter)
log.addHandler(apiodbg)

misperrors = {"error": "Error"}

mispattributes = {
    "input": [
        "domain",
        "domain|ip",
        "hostname",
        "ip-dst",
        "ip-src",
        "ip-dst|port",
        "ip-src|port",
        "url",
        "md5",
        "sha1",
        "sha256",
        "filename|md5",
        "filename|sha1",
        "filename|sha256",
    ],
    "output": [
        "domain",
        "ip-dst",
        "url",
        "comment",
        "md5",
        "sha1",
        "sha256",
        "link",
        "text",
    ],
}

moduleinfo = {
    "version": "0.2",
    "author": "Davide Baglieri aka davidonzo",
    "description": "On demand query API for OSINT.digitalside.it project.",
    "module-type": ["expansion", "hover"],
    "name": "OSINT DigitalSide",
    "logo": "",
    "requirements": ["The apiosintDS python library to query the OSINT.digitalside.it API."],
    "features": (
        "The module simply queries the API of OSINT.digitalside.it with a domain, ip, url or hash attribute.\n\nThe"
        " result of the query is then parsed to extract additional hashes or urls. A module parameters also allows to"
        " parse the hashes related to the urls.\n\nFurthermore, it is possible to cache the urls and hashes collected"
        " over the last 7 days by OSINT.digitalside.it"
    ),
    "references": ["https://osint.digitalside.it/#About"],
    "input": "A domain, ip, url or hash attribute.",
    "output": "Hashes and urls resulting from the query to OSINT.digitalside.it",
}

moduleconfig = [
    "STIX2_details",
    "import_related",
    "cache",
    "cache_directory",
    "cache_timeout_h",
    "local_directory",
]


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    tosubmit = []
    if request.get("domain"):
        tosubmit.append(request["domain"])
    elif request.get("domain|ip"):
        tosubmit.append(request["domain|ip"].split("|")[0])
        tosubmit.append(request["domain|ip"].split("|")[1])
    elif request.get("hostname"):
        tosubmit.append(request["hostname"])
    elif request.get("ip-dst"):
        tosubmit.append(request["ip-dst"])
    elif request.get("ip-src"):
        tosubmit.append(request["ip-src"])
    elif request.get("ip-dst|port"):
        tosubmit.append(request["ip-dst|port"].split("|")[0])
    elif request.get("ip-src|port"):
        tosubmit.append(request["ip-src|port"].split("|")[0])
    elif request.get("url"):
        tosubmit.append(request["url"])
    elif request.get("md5"):
        tosubmit.append(request["md5"])
    elif request.get("sha1"):
        tosubmit.append(request["sha1"])
    elif request.get("sha256"):
        tosubmit.append(request["sha256"])
    elif request.get("filename|md5"):
        tosubmit.append(request["filename|md5"].split("|")[1])
    elif request.get("filename|sha1"):
        tosubmit.append(request["filename|sha1"].split("|")[1])
    elif request.get("filename|sha256"):
        tosubmit.append(request["filename|sha256"].split("|")[1])
    else:
        return False

    persistent = 0
    if request.get("persistent"):
        persistent = request["persistent"]

    submitcache = False
    submitcache_directory = False
    submitcache_timeout = False
    submit_stix = False
    import_related = False
    sumbit_localdirectory = False

    r = {"results": []}

    if request.get("config"):

        if request["config"].get("cache") and request["config"]["cache"].lower() == "yes":
            submitcache = True

        if request["config"].get("import_related") and request["config"]["import_related"].lower() == "yes":
            import_related = True

        if request["config"].get("STIX2_details") and request["config"]["STIX2_details"].lower() == "yes":
            submit_stix = True

        if request["config"].get("cache_timeout_h") and len(request["config"]["cache_timeout_h"]) > 0:
            submitcache_timeout = int(request["config"].get("cache_timeout_h"))

        localdirectory = request["config"].get("local_directory")
        if localdirectory and len(localdirectory) > 0:
            if os.access(localdirectory, os.R_OK):
                sumbit_localdirectory = localdirectory
                WarningMSG = "Local directory OK! Ignoring cache configuration..."
                log.debug(str(WarningMSG))
                submitcache = False
                submitcache_directory = False
            else:
                ErrorMSG = (
                    "Unable to read local 'Threat-Intel' directory ("
                    + localdirectory
                    + "). Please, check your configuration and retry."
                )
                log.debug(str(ErrorMSG))
                misperrors["error"] = ErrorMSG
                return misperrors

        if submitcache:
            cache_directory = request["config"].get("cache_directory")
            if cache_directory and len(cache_directory) > 0:
                if os.access(cache_directory, os.W_OK):
                    submitcache_directory = cache_directory
                else:
                    ErrorMSG = "Cache directory is not writable. Please fix it before."
                    log.debug(str(ErrorMSG))
                    misperrors["error"] = ErrorMSG
                    return misperrors
            else:
                ErrorMSG = (
                    "Value for Plugin.Enrichment_apiosintds_cache_directory is empty but cache option is enabled as"
                    " recommended. Please set a writable cache directory in plugin settings."
                )
                log.debug(str(ErrorMSG))
                misperrors["error"] = ErrorMSG
                return misperrors
        else:
            if sumbit_localdirectory == False:
                log.debug(
                    "Cache option is set to "
                    + str(submitcache)
                    + ". You are not using the internal cache system and this is NOT recommended!"
                )
                log.debug(
                    "Please, consider to turn on the cache setting it to 'Yes' and specifing a writable directory for"
                    " the cache directory option."
                )
    try:
        response = apiosintDS.request(
            entities=tosubmit,
            stix=submit_stix,
            cache=submitcache,
            cachedirectory=submitcache_directory,
            cachetimeout=submitcache_timeout,
            verbose=True,
            localdirectory=sumbit_localdirectory,
        )
        r["results"] += apiosintParserHover(persistent, response, import_related, submit_stix)
        return r
    except Exception as e:
        log.exception("Could not process apiosintDS")
        return {"error": str(e)}


def apiosintParserHover(ispersistent, response, import_related, stix):
    apiosinttype = ["hash", "ip", "url", "domain"]
    line = "##############################################"
    linedot = "--------------------------------------------------------------------"
    linedotty = "-------------------"
    ret = []
    retHover = []
    if isinstance(response, dict):
        for key in response:
            if key in apiosinttype:
                for item in response[key]["items"]:
                    if item["response"]:
                        comment = (
                            "IoC '"
                            + item["item"]
                            + "' found in OSINT.DigitaiSide.it repository. List file: "
                            + response[key]["list"]["file"]
                            + ". List date: "
                            + response[key]["list"]["date"]
                        )
                        commentH = "IoC '" + item["item"] + "' found in OSINT.DigitaiSide.it repository."
                        CommentHDate = (
                            "List file: "
                            + response[key]["list"]["file"]
                            + ". Date list: "
                            + response[key]["list"]["date"]
                        )
                        ret.append({"types": ["text"], "values": [comment]})

                        retHover.append({"types": ["text"], "values": [commentH]})
                        retHover.append({"types": ["text"], "values": [CommentHDate]})
                        retHover.append({"types": ["text"], "values": [line]})

                        if key in ["url", "hash"]:
                            if "hashes" in item:
                                headhash = "Hashes set"
                                retHover.append({"types": ["text"], "values": [headhash]})
                                if "md5" in item["hashes"].keys():
                                    ret.append(
                                        {
                                            "types": ["md5"],
                                            "values": [item["hashes"]["md5"]],
                                            "comment": "Related to: " + item["item"],
                                        }
                                    )

                                    strmd5 = "MD5: " + item["hashes"]["md5"]
                                    retHover.append({"types": ["text"], "values": [strmd5]})

                                if "sha1" in item["hashes"].keys():
                                    ret.append(
                                        {
                                            "types": ["sha1"],
                                            "values": [item["hashes"]["sha1"]],
                                            "comment": "Related to: " + item["item"],
                                        }
                                    )

                                    strsha1 = "SHA1: " + item["hashes"]["sha1"]
                                    retHover.append({"types": ["text"], "values": [strsha1]})

                                if "sha256" in item["hashes"].keys():
                                    ret.append(
                                        {
                                            "types": ["sha256"],
                                            "values": [item["hashes"]["sha256"]],
                                            "comment": "Related to: " + item["item"],
                                        }
                                    )

                                    strsha256 = "SHA256: " + item["hashes"]["sha256"]
                                    retHover.append({"types": ["text"], "values": [strsha256]})

                        if "online_reports" in item:
                            headReports = "Online Reports (availability depends on retention)"
                            retHover.append({"types": ["text"], "values": [linedot]})
                            retHover.append({"types": ["text"], "values": [headReports]})
                            onlierepor = item["online_reports"]
                            ret.append(
                                {
                                    "category": "External analysis",
                                    "types": ["link"],
                                    "values": [onlierepor["MISP_EVENT"]],
                                    "comment": "MISP Event related to: " + item["item"],
                                }
                            )
                            ret.append(
                                {
                                    "category": "External analysis",
                                    "types": ["link"],
                                    "values": [onlierepor["MISP_CSV"]],
                                    "comment": "MISP CSV related to: " + item["item"],
                                }
                            )
                            ret.append(
                                {
                                    "category": "External analysis",
                                    "types": ["link"],
                                    "values": [onlierepor["OSINTDS_REPORT"]],
                                    "comment": "DigitalSide report related to: " + item["item"],
                                }
                            )
                            ret.append(
                                {
                                    "category": "External analysis",
                                    "types": ["link"],
                                    "values": [onlierepor["STIX"]],
                                    "comment": "STIX2 report related to: " + item["item"],
                                }
                            )

                            MISPEVENT = "MISP Event => " + onlierepor["MISP_EVENT"]
                            MISPCSV = "MISP CSV => " + onlierepor["MISP_CSV"]
                            OSINTDS = "DigitalSide report => " + onlierepor["OSINTDS_REPORT"]
                            STIX = "STIX report => " + onlierepor["STIX"]

                            retHover.append({"types": ["text"], "values": [MISPEVENT]})
                            retHover.append({"types": ["text"], "values": [MISPCSV]})
                            retHover.append({"types": ["text"], "values": [OSINTDS]})
                            retHover.append({"types": ["text"], "values": [STIX]})

                            if stix and onlierepor:
                                if "STIXDETAILS" in onlierepor:
                                    retHover.append({"types": ["text"], "values": [linedot]})
                                    headStix = "STIX2 report details"
                                    stixobj = onlierepor["STIXDETAILS"]
                                    stxdet = (
                                        "TLP:"
                                        + stixobj["tlp"]
                                        + " | Observation: "
                                        + str(stixobj["number_observed"])
                                        + " | First seen: "
                                        + stixobj["first_observed"]
                                        + " | First seen: "
                                        + stixobj["last_observed"]
                                    )
                                    ret.append(
                                        {
                                            "types": ["comment"],
                                            "values": [stxdet],
                                            "comment": "STIX2 details for: " + item["item"],
                                        }
                                    )
                                    retHover.append({"types": ["text"], "values": [headStix]})
                                    retHover.append({"types": ["text"], "values": [stxdet]})

                                    if stixobj["observed_time_frame"] != False:
                                        obstf = "Observation time frame: " + str(stixobj["observed_time_frame"])
                                        ret.append(
                                            {
                                                "types": ["comment"],
                                                "values": [obstf],
                                                "comment": "STIX2 details for: " + item["item"],
                                            }
                                        )
                                        retHover.append({"types": ["text"], "values": [obstf]})

                                    filename = stixobj["filename"]
                                    ret.append(
                                        {
                                            "category": "Payload delivery",
                                            "types": ["filename"],
                                            "values": [filename],
                                            "comment": "STIX2 details for: " + item["item"],
                                        }
                                    )

                                    Hovefilename = "Filename: " + filename
                                    retHover.append({"types": ["text"], "values": [Hovefilename]})

                                    filesize = stixobj["filesize"]
                                    ret.append(
                                        {
                                            "types": ["size-in-bytes"],
                                            "values": [filesize],
                                            "comment": "STIX2 details for: " + item["item"],
                                        }
                                    )

                                    Hovefilesize = "Filesize in bytes: " + str(filesize)
                                    retHover.append({"types": ["text"], "values": [Hovefilesize]})

                                    filetype = stixobj["mime_type"]
                                    ret.append(
                                        {
                                            "category": "Payload delivery",
                                            "types": ["mime-type"],
                                            "values": [filetype],
                                            "comment": "STIX2 details for: " + item["item"],
                                        }
                                    )

                                    Hovemime = "Filetype: " + filetype
                                    retHover.append({"types": ["text"], "values": [Hovemime]})

                                    if "virus_total" in stixobj:
                                        if stixobj["virus_total"] != False:
                                            VTratio = "VirusTotal Ratio: " + str(
                                                stixobj["virus_total"]["vt_detection_ratio"]
                                            )
                                            ret.append(
                                                {
                                                    "types": ["comment"],
                                                    "values": [VTratio],
                                                    "comment": "STIX2 details for: " + item["item"],
                                                }
                                            )
                                            retHover.append({"types": ["text"], "values": [VTratio]})

                                            VTReport = str(stixobj["virus_total"]["vt_report"])
                                            ret.append(
                                                {
                                                    "category": "External analysis",
                                                    "types": ["link"],
                                                    "values": [VTReport],
                                                    "comment": "VirusTotal Report for: " + item["item"],
                                                }
                                            )
                        if import_related:
                            if len(item["related_urls"]) > 0:
                                retHover.append({"types": ["text"], "values": [linedot]})
                                countRelated = "Related URLS count: " + str(len(item["related_urls"]))
                                retHover.append({"types": ["text"], "values": [countRelated]})
                                for urls in item["related_urls"]:
                                    if isinstance(urls, dict):
                                        itemToInclude = urls["url"]
                                        ret.append(
                                            {
                                                "types": ["url"],
                                                "values": [itemToInclude],
                                                "comment": (
                                                    "Download URL for "
                                                    + urls["hashes"]["md5"]
                                                    + ". Related to: "
                                                    + item["item"]
                                                ),
                                            }
                                        )

                                        retHover.append({"types": ["text"], "values": [linedot]})
                                        relatedURL = "Related URL " + itemToInclude
                                        retHover.append({"types": ["text"], "values": [relatedURL]})

                                        if "hashes" in urls.keys():
                                            if "md5" in urls["hashes"].keys():
                                                ret.append(
                                                    {
                                                        "types": ["md5"],
                                                        "values": [urls["hashes"]["md5"]],
                                                        "comment": "Related to: " + itemToInclude,
                                                    }
                                                )

                                                strmd5 = "MD5: " + urls["hashes"]["md5"]
                                                retHover.append(
                                                    {
                                                        "types": ["text"],
                                                        "values": [strmd5],
                                                    }
                                                )

                                            if "sha1" in urls["hashes"].keys():
                                                ret.append(
                                                    {
                                                        "types": ["sha1"],
                                                        "values": [urls["hashes"]["sha1"]],
                                                        "comment": "Related to: " + itemToInclude,
                                                    }
                                                )

                                                strsha1 = "SHA1: " + urls["hashes"]["sha1"]
                                                retHover.append(
                                                    {
                                                        "types": ["text"],
                                                        "values": [strsha1],
                                                    }
                                                )

                                            if "sha256" in urls["hashes"].keys():
                                                ret.append(
                                                    {
                                                        "types": ["sha256"],
                                                        "values": [urls["hashes"]["sha256"]],
                                                        "comment": "Related to: " + itemToInclude,
                                                    }
                                                )

                                                strsha256 = "SHA256: " + urls["hashes"]["sha256"]
                                                retHover.append(
                                                    {
                                                        "types": ["text"],
                                                        "values": [strsha256],
                                                    }
                                                )

                                        headReports = "Online Reports (availability depends on retention)"
                                        retHover.append({"types": ["text"], "values": [linedotty]})
                                        retHover.append({"types": ["text"], "values": [headReports]})
                                        onlierepor = urls["online_reports"]
                                        ret.append(
                                            {
                                                "category": "External analysis",
                                                "types": ["link"],
                                                "values": [onlierepor["MISP_EVENT"]],
                                                "comment": "MISP Event related to: " + item["item"],
                                            }
                                        )
                                        ret.append(
                                            {
                                                "category": "External analysis",
                                                "types": ["link"],
                                                "values": [onlierepor["MISP_CSV"]],
                                                "comment": "MISP CSV related to: " + item["item"],
                                            }
                                        )
                                        ret.append(
                                            {
                                                "category": "External analysis",
                                                "types": ["link"],
                                                "values": [onlierepor["OSINTDS_REPORT"]],
                                                "comment": "DigitalSide report related to: " + item["item"],
                                            }
                                        )
                                        ret.append(
                                            {
                                                "category": "External analysis",
                                                "types": ["link"],
                                                "values": [onlierepor["STIX"]],
                                                "comment": "STIX2 report related to: " + item["item"],
                                            }
                                        )

                                        MISPEVENT = "MISP Event => " + onlierepor["MISP_EVENT"]
                                        MISPCSV = "MISP CSV => " + onlierepor["MISP_CSV"]
                                        OSINTDS = "DigitalSide report => " + onlierepor["OSINTDS_REPORT"]
                                        STIX = "STIX report => " + onlierepor["STIX"]

                                        retHover.append({"types": ["text"], "values": [MISPEVENT]})
                                        retHover.append({"types": ["text"], "values": [MISPCSV]})
                                        retHover.append({"types": ["text"], "values": [OSINTDS]})
                                        retHover.append({"types": ["text"], "values": [STIX]})

                                        if stix and onlierepor:
                                            if "STIXDETAILS" in onlierepor:
                                                retHover.append(
                                                    {
                                                        "types": ["text"],
                                                        "values": [linedotty],
                                                    }
                                                )
                                                headStix = "STIX2 report details"
                                                stixobj = onlierepor["STIXDETAILS"]
                                                stxdet = (
                                                    "TLP:"
                                                    + stixobj["tlp"]
                                                    + " | Observation: "
                                                    + str(stixobj["number_observed"])
                                                    + " | First seen: "
                                                    + stixobj["first_observed"]
                                                    + " | First seen: "
                                                    + stixobj["last_observed"]
                                                )
                                                ret.append(
                                                    {
                                                        "types": ["comment"],
                                                        "values": [stxdet],
                                                        "comment": "STIX2 details for: " + item["item"],
                                                    }
                                                )
                                                retHover.append(
                                                    {
                                                        "types": ["text"],
                                                        "values": [headStix],
                                                    }
                                                )
                                                retHover.append(
                                                    {
                                                        "types": ["text"],
                                                        "values": [stxdet],
                                                    }
                                                )

                                                if stixobj["observed_time_frame"] != False:
                                                    obstf = "Observation time frame: " + str(
                                                        stixobj["observed_time_frame"]
                                                    )
                                                    ret.append(
                                                        {
                                                            "types": ["comment"],
                                                            "values": [obstf],
                                                            "comment": "STIX2 details for: " + item["item"],
                                                        }
                                                    )
                                                    retHover.append(
                                                        {
                                                            "types": ["text"],
                                                            "values": [obstf],
                                                        }
                                                    )

                                                filename = stixobj["filename"]
                                                ret.append(
                                                    {
                                                        "category": "Payload delivery",
                                                        "types": ["filename"],
                                                        "values": [filename],
                                                        "comment": "STIX2 details for: " + item["item"],
                                                    }
                                                )

                                                Hovefilename = "Filename: " + filename
                                                retHover.append(
                                                    {
                                                        "types": ["text"],
                                                        "values": [Hovefilename],
                                                    }
                                                )

                                                filesize = stixobj["filesize"]
                                                ret.append(
                                                    {
                                                        "types": ["size-in-bytes"],
                                                        "values": [filesize],
                                                        "comment": "STIX2 details for: " + item["item"],
                                                    }
                                                )

                                                Hovefilesize = "Filesize in bytes: " + str(filesize)
                                                retHover.append(
                                                    {
                                                        "types": ["text"],
                                                        "values": [Hovefilesize],
                                                    }
                                                )

                                                filetype = stixobj["mime_type"]
                                                ret.append(
                                                    {
                                                        "category": "Payload delivery",
                                                        "types": ["mime-type"],
                                                        "values": [filetype],
                                                        "comment": "STIX2 details for: " + item["item"],
                                                    }
                                                )

                                                Hovemime = "Filetype: " + filetype
                                                retHover.append(
                                                    {
                                                        "types": ["text"],
                                                        "values": [Hovemime],
                                                    }
                                                )

                                                if "virus_total" in stixobj:
                                                    if stixobj["virus_total"] != False:
                                                        VTratio = (
                                                            "VirusTotal Ratio: "
                                                            + stixobj["virus_total"]["vt_detection_ratio"]
                                                        )
                                                        ret.append(
                                                            {
                                                                "types": ["comment"],
                                                                "values": [VTratio],
                                                                "comment": "STIX2 details for: " + item["item"],
                                                            }
                                                        )
                                                        retHover.append(
                                                            {
                                                                "types": ["text"],
                                                                "values": [VTratio],
                                                            }
                                                        )

                                                        VTReport = stixobj["virus_total"]["vt_report"]
                                                        ret.append(
                                                            {
                                                                "category": "External analysis",
                                                                "types": ["link"],
                                                                "values": [VTReport],
                                                                "comment": "VirusTotal Report for: " + item["item"],
                                                            }
                                                        )
                                    else:
                                        ret.append(
                                            {
                                                "types": ["url"],
                                                "values": [urls],
                                                "comment": "Download URL for: " + item["item"],
                                            }
                                        )
                                        urlHover = "URL => " + urls
                                        retHover.append({"types": ["text"], "values": [urlHover]})
                    else:
                        notfound = (
                            item["item"]
                            + " IS NOT listed by OSINT.digitalside.it. Date list: "
                            + response[key]["list"]["date"]
                        )
                        ret.append({"types": ["comment"], "values": [notfound]})
                        retHover.append({"types": ["comment"], "values": [notfound]})

    if ispersistent == 0:
        return ret
    return retHover


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
