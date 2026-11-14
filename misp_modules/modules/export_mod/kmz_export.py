"""Export preserved geographic packages and geolocations as KMZ."""

from misp_modules.lib import kml, kml_exporter

moduleconfig = []
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "KMZ Export",
    "description": "Export original KML/KMZ datasets and geolocations as a KMZ package.",
    "module-type": ["export"],
    "logo": "",
    "requirements": [],
    "features": (
        "Returns a single stored KMZ unchanged or packages KML datasets, KMZ assets and standalone locations."
        " Combined packages use a doc.kml index with local NetworkLinks to separate dataset directories, keeping"
        " styles, IDs and relative asset paths scoped to their original documents. Linked geolocations are not"
        " duplicated. No network access or extra dependency is required. See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/export_mod/kml_export.md)."
    ),
    "references": ["https://developers.google.com/kml/documentation/kmzarchives"],
    "input": "MISP kml and geolocation objects; include attachment data when fetching events.",
    "output": "Base64-encoded KMZ archive.",
}


def handler(q=False):
    return kml_exporter.handler(q, "kmz")


def introspection():
    return {
        "inputSource": ["event", "event-collection"],
        "outputFileExtension": "kmz",
        "responseType": kml.MIME["kmz"],
        "userConfig": {},
    }


def version():
    return dict(moduleinfo, config=moduleconfig)
