"""Run the local Manalyze PE analyzer and preserve its plugin-specific verdicts."""

import base64
import binascii
import hashlib
import io
import json
import re
import subprocess
import tempfile
import zipfile
import zlib
from pathlib import Path
from uuid import UUID

from pymisp import MISPEvent, MISPObject

mispattributes = {"input": ["attachment", "malware-sample"], "format": "misp_standard"}
moduleconfig = ["binary", "timeout", "max_size_mb"]
moduleinfo = {
    "version": "1",
    "author": "MISP Project",
    "name": "Manalyze",
    "description": "Analyze PE attachments and malware samples with a local Manalyze installation.",
    "module-type": ["expansion"],
    "logo": "",
    "requirements": ["Manalyze executable and its rules/plugins installed on the module server"],
    "features": (
        "Runs local static analysis using an explicit set of offline plugins. Returns a file object, one"
        " malware-analysis object per plugin verdict, and an annotation containing the complete JSON report."
        " Supports MISP malware-sample ZIPs with password infected. Configuration: binary (default manalyze),"
        " timeout (default 60 seconds, 1-300), max_size_mb (default 25, 1-100)."
    ),
    "references": ["https://github.com/JusticeRage/Manalyze", "https://docs.manalyzer.org/en/latest/"],
    "input": "An attachment or malware-sample attribute with base64 data, type, value and uuid.",
    "output": "Linked file, malware-analysis and annotation objects in misp_standard format.",
}
PLUGINS = "imports,mitigation,resources,peid,compilers,findcrypt,strings"
VERDICTS = {0: "benign", 1: "unknown", 2: "suspicious", 3: "malicious"}
MAX_REPORT_BYTES = 20 * 1024 * 1024


class ModuleError(ValueError):
    """An error suitable for returning to the caller."""


def _limit(config, name, default, maximum):
    value = config.get(name)
    if value is None or value == "":
        return default
    if isinstance(value, bool) or not str(value).isdigit() or not 1 <= int(value) <= maximum:
        raise ModuleError(f"{name} must be an integer between 1 and {maximum}.")
    return int(value)


def _sample(attribute, maximum):
    encoded = attribute.get("data")
    if not isinstance(encoded, str) or not encoded:
        raise ModuleError("Attribute data must be a nonempty base64 string.")
    if len(encoded) > 4 * ((maximum + 2) // 3):
        raise ModuleError("Attribute data exceeds max_size_mb.")
    try:
        content = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        raise ModuleError("Attribute data is not valid base64.") from None
    if len(content) > maximum:
        raise ModuleError("Attribute data exceeds max_size_mb.")
    if attribute["type"] == "malware-sample":
        filename, separator, digest = attribute["value"].rpartition("|")
        if not separator or not filename or not re.fullmatch(r"[a-fA-F0-9]{32}", digest):
            raise ModuleError("A malware-sample value must be filename|md5.")
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as archive:
                members = [m for m in archive.infolist() if not m.is_dir() and not m.filename.endswith(".filename.txt")]
                if len(members) != 1:
                    raise ModuleError("The malware-sample ZIP must contain exactly one sample.")
                if members[0].file_size > maximum:
                    raise ModuleError("The extracted sample exceeds max_size_mb.")
                with archive.open(members[0], pwd=b"infected") as sample:
                    content = sample.read(maximum + 1)
        except (zipfile.BadZipFile, RuntimeError, NotImplementedError, EOFError, zlib.error):
            raise ModuleError("Unable to read the malware-sample ZIP (password: infected).") from None
        if len(content) > maximum:
            raise ModuleError("The extracted sample exceeds max_size_mb.")
        if hashlib.md5(content, usedforsecurity=False).hexdigest() != digest.lower():
            raise ModuleError("The extracted sample MD5 does not match the malware-sample attribute.")
    if not content.startswith(b"MZ"):
        raise ModuleError("Manalyze requires a PE file with an MZ header.")
    return content


def _analyze(content, binary, timeout):
    with tempfile.TemporaryDirectory(prefix="misp-manalyze-") as directory:
        sample = Path(directory) / "sample.exe"
        sample.write_bytes(content)
        with tempfile.TemporaryFile() as output:
            try:
                completed = subprocess.run(
                    [binary, "--output=json", "--dump=all", "--hashes", f"--plugins={PLUGINS}", str(sample)],
                    stdin=subprocess.DEVNULL,
                    stdout=output,
                    stderr=subprocess.DEVNULL,
                    timeout=timeout,
                    check=False,
                )
            except FileNotFoundError:
                raise ModuleError("Manalyze executable not found; configure binary on the module server.") from None
            except subprocess.TimeoutExpired:
                raise ModuleError("Manalyze analysis timed out.") from None
            if completed.returncode:
                raise ModuleError("Manalyze analysis failed; check the server installation and plugins.")
            if output.tell() > MAX_REPORT_BYTES:
                raise ModuleError("Manalyze report exceeds the 20 MiB limit.")
            output.seek(0)
            try:
                reports = json.load(output)
            except (ValueError, UnicodeError):
                raise ModuleError("Manalyze returned invalid JSON.") from None
        # The native CLI keys its reports by the absolute input path.
        if not isinstance(reports, dict) or set(reports) != {str(sample)}:
            raise ModuleError("Manalyze did not produce a report for the sample; it may not be a valid PE.")
        report = reports[str(sample)]
        if not isinstance(report, dict) or not isinstance(report.get("Summary"), dict):
            raise ModuleError("Manalyze returned an invalid report.")
        return report


def _results(attribute, content, report):
    plugins = report.get("Plugins", {})
    if not isinstance(plugins, dict):
        raise ModuleError("Manalyze returned invalid plugin results.")
    event = MISPEvent()
    event.add_attribute(**attribute)
    file_object = MISPObject("file")
    filename = attribute["value"].rsplit("|", 1)[0] if attribute["type"] == "malware-sample" else attribute["value"]
    file_object.add_attribute("filename", value=filename, to_ids=False)
    file_object.add_attribute("size-in-bytes", value=len(content), to_ids=False)
    for kind in ("md5", "sha1", "sha256"):
        file_object.add_attribute(
            kind, value=hashlib.new(kind, content, usedforsecurity=False).hexdigest(), to_ids=False
        )
    file_object.add_reference(attribute["uuid"], "related-to")
    event.add_object(file_object)
    annotation = MISPObject("annotation")
    annotation.add_attribute(
        "text", value="Manalyze static analysis report. Plugin verdicts have independent scopes.", to_ids=False
    )
    annotation.add_attribute("type", value="Full Report", to_ids=False)
    annotation.add_attribute(
        "attachment",
        value="manalyze.json",
        data=io.BytesIO(json.dumps(report, ensure_ascii=True).encode()),
        to_ids=False,
    )
    annotation.add_reference(file_object.uuid, "annotates")
    event.add_object(annotation)
    for name, result in plugins.items():
        if not isinstance(result, dict) or type(result.get("level")) is not int or result["level"] not in VERDICTS:
            raise ModuleError("Manalyze returned an invalid plugin verdict.")
        summary = result.get("summary")
        if summary is not None and not isinstance(summary, str):
            raise ModuleError("Manalyze returned an invalid plugin summary.")
        analysis = MISPObject("malware-analysis")
        analysis.add_attribute("product", value="Manalyze", to_ids=False)
        analysis.add_attribute("module", value=name, to_ids=False)
        analysis.add_attribute("result", value=VERDICTS[result["level"]], to_ids=False)
        if summary:
            analysis.add_attribute("result_name", value=summary, to_ids=False)
        analysis.add_reference(file_object.uuid, "analyses")
        analysis.add_reference(annotation.uuid, "documented-by")
        event.add_object(analysis)
    data = json.loads(event.to_json())
    return {"results": {key: data.get(key, []) for key in ("Attribute", "Object")}}


def handler(q=False):
    if q is False:
        return False
    try:
        request = json.loads(q)
        if not isinstance(request, dict):
            raise ModuleError("The request must be a JSON object.")
        attribute = request.get("attribute")
        if not isinstance(attribute, dict) or not all(
            isinstance(attribute.get(k), str) and attribute[k] for k in ("type", "value", "uuid")
        ):
            raise ModuleError("An attribute containing type, value and uuid is required.")
        if attribute["type"] not in mispattributes["input"]:
            raise ModuleError("Unsupported attribute type; expected attachment or malware-sample.")
        try:
            UUID(attribute["uuid"])
        except ValueError:
            raise ModuleError("The attribute uuid must be a valid UUID.") from None
        config = request.get("config")
        if config is None:
            config = {}
        if not isinstance(config, dict):
            raise ModuleError("The config must be a JSON object.")
        binary = config.get("binary")
        if binary is None or binary == "":
            binary = "manalyze"
        if not isinstance(binary, str) or not binary.strip() or "\x00" in binary:
            raise ModuleError("binary must be an executable name or path.")
        timeout = _limit(config, "timeout", 60, 300)
        maximum = _limit(config, "max_size_mb", 25, 100) * 1024 * 1024
        content = _sample(attribute, maximum)
        report = _analyze(content, binary, timeout)
        return _results(attribute, content, report)
    except ModuleError as exc:
        return {"error": str(exc)}
    except (ValueError, TypeError, OSError, OverflowError):
        return {"error": "Invalid request or unable to run Manalyze on the module server."}


def introspection():
    return mispattributes


def version():
    return dict(moduleinfo, config=moduleconfig)
