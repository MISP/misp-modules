"""Import metadata from a locally supplied file."""

from misp_modules.lib import file_metadata

moduleinfo = {
    "version": "1.0",
    "author": "MISP Project",
    "name": "File and Media Metadata Import",
    "description": "Import metadata from an uploaded file without an external service.",
    "module-type": ["import"],
    "data-source": "internal",
    "requirements": file_metadata.REQUIREMENTS,
    "features": (
        "Reads documents, images, audio and video with ExifTool. Preserves grouped raw parser values and "
        "unverified timestamp and location claims. Optional embedded stream scanning and original file "
        "attachment. See the "
        "[usage guide](https://github.com/MISP/misp-modules/blob/main/documentation/expansion/file_metadata.md)."
    ),
    "references": file_metadata.REFERENCES,
    "input": "An uploaded file or base64 file data.",
    "output": "A source file object and linked file-metadata object.",
}


def handler(q=False):
    return False if q is False else file_metadata.run(q, expansion=False)


def introspection():
    return {
        "inputSource": ["file"],
        "output": ["MISP objects"],
        "format": "misp_standard",
        "userConfig": {
            "scan_embedded": {"type": "Boolean", "message": "Scan embedded streams and metadata with ExifTool"},
            "include_original": {"type": "Boolean", "message": "Attach the original uploaded file"},
        },
    }


def version():
    return dict(moduleinfo, config=[])
