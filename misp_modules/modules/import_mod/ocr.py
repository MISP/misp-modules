import base64
import json
import logging
import sys
from io import BytesIO

log = logging.getLogger("ocr")
log.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
ch.setFormatter(formatter)
log.addHandler(ch)

misperrors = {"error": "Error"}
userConfig = {}

inputSource = ["file"]

moduleinfo = {
    "version": "0.2",
    "author": "Alexandre Dulaunoy",
    "description": "Optical Character Recognition (OCR) module for MISP.",
    "module-type": ["import"],
    "name": "OCR Import",
    "logo": "",
    "requirements": [],
    "features": (
        "The module tries to recognize some text from an image and import the result as a freetext attribute, there is"
        " then no special feature asked to users to make it work."
    ),
    "references": [],
    "input": "Image",
    "output": "freetext MISP attribute",
}

moduleconfig = []


def handler(q=False):
    # try to import modules and return errors if module not found
    try:
        from PIL import Image
    except ImportError:
        misperrors["error"] = "Please pip(3) install pillow"
        return misperrors

    try:
        # Official ImageMagick module
        from wand.image import Image as WImage
    except ImportError:
        misperrors["error"] = "Please pip(3) install wand"
        return misperrors

    try:
        from pytesseract import image_to_string
    except ImportError:
        misperrors["error"] = "Please pip(3) install pytesseract"
        return misperrors

    if q is False:
        return False
    r = {"results": []}
    request = json.loads(q)
    document = base64.b64decode(request["data"])
    document = WImage(blob=document)
    if document.format == "PDF":
        with document as pdf:
            # Get number of pages
            pages = len(pdf.sequence)
            log.debug("PDF with {} page(s) detected".format(pages))
            # Create new image object where the height will be the number of pages. With huge PDFs this will overflow, break, consume silly memory etc…
            img = WImage(width=pdf.width, height=pdf.height * pages)
            # Cycle through pages and stitch it together to one big file
            for p in range(pages):
                log.debug("Stitching page {}".format(p + 1))
                image = img.composite(pdf.sequence[p], top=pdf.height * p, left=0)
            # Create a png blob
            image = img.make_blob("png")
            log.debug("Final image size is {}x{}".format(pdf.width, pdf.height * (p + 1)))
    else:
        image = base64.b64decode(request["data"])

    image_file = BytesIO(image)
    image_file.seek(0)

    try:
        im = Image.open(image_file)
    except IOError:
        misperrors["error"] = "Corrupt or not an image file."
        return misperrors

    ocrized = image_to_string(im)

    freetext = {}
    freetext["values"] = ocrized
    freetext["types"] = ["freetext"]
    r["results"].append(freetext)
    return r


def introspection():
    modulesetup = {}
    try:
        userConfig
        modulesetup["userConfig"] = userConfig
    except NameError:
        pass
    try:
        inputSource
        modulesetup["inputSource"] = inputSource
    except NameError:
        pass
    return modulesetup


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo


if __name__ == "__main__":
    x = open("test.json", "r")
    handler(q=x.read())
