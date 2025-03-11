#!/usr/bin/env python\

import base64
import json
import os
import random
import shutil
import string
import subprocess

import pandoc

installationNotes = """
1. Install pandoc for your distribution
2. Install wkhtmltopdf
    - Ensure You have install the version with patched qt
    - Ensure it supports margin options
    - You can check the above by inspecting the extended help `wkhtmltopdf --extended-help`
3. Install mermaid
    - `npm install --global @mermaid-js/mermaid-cli`
4. Install the pandoc-mermaid-filter from https://github.com/DavidCruciani/pandoc-mermaid-filter
    - Easiest is to install the following:
    ```bash
        pip3 install git+https://github.com/DavidCruciani/pandoc-mermaid-filter
    ```
"""

misperrors = {"error": "Error"}
mispattributes = {"input": ["text"], "output": ["text"]}
moduleinfo = {
    "version": "0.3",
    "author": "Sami Mokaddem",
    "description": (
        "Render the markdown (under GFM) into PDF. Requires pandoc (https://pandoc.org/), wkhtmltopdf"
        " (https://wkhtmltopdf.org/) and mermaid dependencies."
    ),
    "module-type": ["expansion"],
    "name": "Markdown to PDF converter",
    "logo": "",
    "requirements": ["pandoc"],
    "features": "",
    "references": [installationNotes],
    "input": "",
    "output": "",
}

moduleconfig = []


def randomFilename(length=10):
    characters = string.ascii_lowercase + string.digits  # Lowercase letters and digits
    return "".join(random.choices(characters, k=length))


def convert(markdown, margin="3"):
    doc = pandoc.read(markdown, format="gfm")

    elt = doc

    # wrap/unwrap Inline or MetaInlines into [Inline]
    if isinstance(elt, pandoc.types.Inline):
        inline = elt
        elt = [inline]
    elif isinstance(elt, pandoc.types.MetaInlines):
        meta_inlines = elt
        elt = meta_inlines[0]

    # wrap [Inline] into a Plain element
    if isinstance(elt, list) and all(isinstance(elt_, pandoc.types.Inline) for elt_ in elt):
        inlines = elt
        elt = pandoc.types.Plain(inlines)

    # wrap/unwrap Block or MetaBlocks into [Block]
    if isinstance(elt, pandoc.types.Block):
        block = elt
        elt = [block]
    elif isinstance(elt, pandoc.types.MetaBlocks):
        meta_blocks = elt
        elt = meta_blocks[0]

    # wrap [Block] into a Pandoc element
    if isinstance(elt, list) and all(isinstance(elt_, pandoc.types.Block) for elt_ in elt):
        blocks = elt
        elt = pandoc.types.Pandoc(pandoc.types.Meta({}), blocks)

    if not isinstance(elt, pandoc.types.Pandoc):
        raise TypeError(f"{elt!r} is not a Pandoc, Block or Inline instance.")

    doc = elt

    # options = [
    #     '--pdf-engine=wkhtmltopdf',
    #     f'-V margin-left={margin}',
    #     f'-V margin-right={margin}',
    #     f'-V margin-top={margin}',
    #     f'-V margin-bottom={margin}',
    #     '--pdf-engine-opt="--disable-smart-shrinking"',
    # ]
    randomFn = randomFilename()
    command = [
        "/usr/bin/pandoc",
        "-t",
        "pdf",
        "-o",
        f"/tmp/{randomFn}/output",
        "--pdf-engine=wkhtmltopdf",
        "-V",
        f"margin-left={margin}",
        "-V",
        f"margin-right={margin}",
        "-V",
        f"margin-top={margin}",
        "-V",
        f"margin-bottom={margin}",
        "--pdf-engine-opt=--disable-smart-shrinking",
        "--pdf-engine-opt=--disable-javascript",
        "--pdf-engine-opt=--no-images",
        "--pdf-engine-opt=--disable-local-file-access",
        "--filter=pandoc-mermaid",
        "-f",
        "json",
        f"/tmp/{randomFn}/input.js",
    ]
    # try:
    #     # For some reasons, options are not passed correctly or not parsed correctly by wkhtmltopdf..
    #     # converted = pandoc.write(doc, format='pdf', options=options)
    # except Exception as e:
    #     print(e)

    os.makedirs(f"/tmp/{randomFn}", exist_ok=True)
    # Write parsed file structure to be fed to the converter
    with open(f"/tmp/{randomFn}/input.js", "bw") as f:
        configuration = pandoc.configure(read=True)
        if pandoc.utils.version_key(configuration["pandoc_types_version"]) < [1, 17]:
            json_ = pandoc.write_json_v1(doc)
        else:
            json_ = pandoc.write_json_v2(doc)
        json_str = json.dumps(json_)
        f.write(json_str.encode("utf-8"))

    # Do conversion by manually invoking pandoc
    try:
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Command failed with error: {e}")

    # Read output and returns it
    with open(f"/tmp/{randomFn}/output", "br") as f:
        converted = f.read()

    # Clean up generated files
    folderPath = f"/tmp/{randomFn}"
    try:
        shutil.rmtree(folderPath)
        print(f"Folder '{folderPath}' deleted successfully.")
    except FileNotFoundError:
        print(f"Folder '{folderPath}' does not exist.")
    except Exception as e:
        print(f"Error deleting folder '{folderPath}': {e}")

    return base64.b64encode(converted).decode()


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if request.get("text"):
        data = request["text"]
    else:
        return False
    data = json.loads(data)
    markdown = data.get("markdown")
    try:
        margin = "3"
        if "config" in request.get("config", []):
            if request["config"].get("margin"):
                margin = request["config"].get("margin")
        rendered = convert(markdown, margin=margin)
    except Exception as e:
        rendered = f"Error: {e}"

    r = {"results": [{"types": mispattributes["output"], "values": [rendered]}]}
    return r


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
