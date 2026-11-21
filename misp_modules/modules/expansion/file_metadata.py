"""Extract metadata locally from an existing MISP attachment."""

from misp_modules.lib import file_metadata

mispattributes = {"input": ["attachment"], "format": "misp_standard"}
moduleconfig = ["scan_embedded"]
moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "File and Media Metadata",
    "description": "Extract selected file, document and media metadata locally with ExifTool.",
    "module-type": ["expansion"],
    "data-source": "internal",
    "requirements": file_metadata.REQUIREMENTS,
    "features": (
        "Preserves grouped EXIF, XMP, PDF, Office and media-container tags and raw parser values. Records the ExifTool"
        " version and SHA-256, flags embedded time and location claims for corroboration and links the results to the"
        " original attachment. Correlates selected names, identifiers and software across files. Optional embedded"
        " stream scanning. See the [usage"
        " guide](https://github.com/MISP/misp-modules/blob/main/documentation/expansion/file_metadata.md)."
    ),
    "references": file_metadata.REFERENCES,
    "input": "A MISP attachment with base64 data.",
    "output": "Linked file and file-metadata objects.",
}


def handler(q=False):
    return False if q is False else file_metadata.run(q, expansion=True)


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)
