# -*- coding: utf-8 -*-
import argparse
import sys
import xml.etree.ElementTree as ET
from zipfile import ZipFile

if sys.platform == "win32":
    import win32_unicode_argv


def textOrTail(elem):
    total = ""
    tort = elem.text or elem.tail
    if tort:
        total += tort
    for child in elem:
        total += textOrTail(child)
    return total


def odtToText(odtPath):
    with ZipFile(odtPath, "r") as odtArchive:
        try:
            with odtArchive.open("content.xml") as f:
                odtContent = f.read()
        except Exception as e:
            print("Could not find 'content.xml': {}".format(str(e)))
            return

        root = ET.fromstring(odtContent)
        total = ""
        for child in root.find("{urn:oasis:names:tc:opendocument:xmlns:office:1.0}body").find(
            "{urn:oasis:names:tc:opendocument:xmlns:office:1.0}text"
        ):
            if child.tag == "{urn:oasis:names:tc:opendocument:xmlns:text:1.0}p":
                total += textOrTail(child) + "\n"
        if total and total[-1] == "\n":
            total = total[:-1]
        return total


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("odtPath", help="Path to the .odt file to read")
    parser.add_argument(
        "-o",
        "--out",
        help="If the output is to be written to a file, path to the file (otherwise STDOUT is used)",
    )
    args = parser.parse_args()

    output = odtToText(args.odtPath)
    if args.out:
        with open(args.out, "w") as outFile:
            outFile.write(output)
    else:
        print(output)
