"""Export standalone geolocations or a single preserved KML document."""

from misp_modules.lib import kml, kml_exporter

moduleconfig = []
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "KML Export",
    "description": "Export geolocations as KML or return a single original KML attachment unchanged.",
    "module-type": ["export"],
    "logo": "",
    "requirements": [],
    "features": (
        "Exports WGS84 geolocations as Point Placemarks with observation times and contextual ExtendedData."
        " Returns a single stored KML document unchanged when no additional points are needed. Use kmz_export"
        " for KMZ inputs or combinations of source datasets and additional locations. No network access or extra"
        " dependency is required. See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/export_mod/kml_export.md)."
    ),
    "references": ["https://www.ogc.org/standards/kml/"],
    "input": "MISP kml or geolocation objects; include attachment data when fetching events.",
    "output": "Base64-encoded KML XML.",
}


def handler(q=False):
    return kml_exporter.handler(q, "kml")


def introspection():
    return {
        "inputSource": ["event", "event-collection"],
        "outputFileExtension": "kml",
        "responseType": kml.MIME["kml"],
        "userConfig": {},
    }


def version():
    return dict(moduleinfo, config=moduleconfig)
