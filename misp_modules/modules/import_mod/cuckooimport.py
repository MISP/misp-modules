import base64
import binascii
import io
import json
import logging
import posixpath
import stat
import tarfile
import zipfile
from collections import OrderedDict
from contextlib import ExitStack

from pymisp import MISPAttribute, MISPEvent, MISPObject
from pymisp.exceptions import PyMISPError
from pymisp.tools import make_binary_objects

log = logging.getLogger(__name__)

misperrors = {"error": "Error"}

moduleinfo = {
    "version": "1.2",
    "author": "Pierre-Jean Grenier",
    "module-type": ["import"],
    "name": "Cuckoo Sandbox Import",
    "description": "Module to import Cuckoo and CAPE JSON reports or analysis archives.",
    "logo": "cuckoo.png",
    "requirements": [],
    "features": (
        "Import a standalone Cuckoo/CAPE JSON report or an analysis archive (ZIP or bzip2 tarball) containing"
        " reports/report.json. Without bundled binaries, file metadata is imported without attachments."
    ),
    "references": [
        "https://cuckoosandbox.org/",
        "https://github.com/cuckoosandbox/cuckoo",
        "https://capev2.readthedocs.io/en/latest/usage/api.html",
    ],
    "input": "Cuckoo/CAPE JSON report, ZIP archive or bzip2 tarball",
    "output": "MISP Event attributes",
}

moduleconfig = []

mispattributes = {
    "inputSource": ["file"],
    "output": ["MISP objects", "malware-sample"],
    "format": "misp_standard",
}

# Attributes for which we can set the "Artifacts dropped"
# category if we want to
ARTIFACTS_DROPPED = (
    "filename",
    "md5",
    "sha1",
    "sha256",
    "sha512",
    "malware-sample",
    "mimetype",
    "ssdeep",
)

# Same for the category "Payload delivery"
PAYLOAD_DELIVERY = ARTIFACTS_DROPPED


class ReportError(ValueError):
    """An input error safe to display to the user."""


class PrettyDict(OrderedDict):
    """
    This class is just intended for a pretty print
    of its keys and values.
    """

    MAX_SIZE = 30

    def __str__(self):
        tmp = []
        for k, v in self.items():
            v = str(v)
            if len(v) > self.MAX_SIZE:
                k += ",cut"
                v = v[: self.MAX_SIZE]
            v.replace("\n", " ")
            tmp.append((k, v))
        return "; ".join(f"({k}) {v}" for k, v in tmp)


def search_objects(event, name, attributes=[]):
    """
    Search for objects in event, which name is `name` and
    contain at least the attributes given.
    Return a generator.
    @ param attributes: a list of (object_relation, value)
    """
    match = filter(
        lambda obj: all(
            obj.name == name
            and (obj_relation, str(attr_value))
            in map(lambda attr: (attr.object_relation, str(attr.value)), obj.attributes)
            for obj_relation, attr_value in attributes
        ),
        event.objects,
    )
    return match


def find_process_by_pid(event, pid):
    """
    Find a 'process' MISPObject by its PID. If multiple objects are found,
    only return the first one.
    @ param pid: integer or str
    """
    generator = search_objects(event, "process", (("pid", pid),))
    return next(generator, None)


class CuckooParser:
    # This dict is used to generate the userConfig and link the different
    # options to the corresponding method of the parser. This way, we avoid
    # redundancy and make future changes easier (instead of for instance
    # defining all the options in userConfig directly, and then making a
    # switch when running the parser).
    # Careful about the order here, as we create references between
    # MISPObjects/MISPAttributes at the same time we generate them.
    # Hence when we create object B, which we want to reference to
    # object A, we should already have created object A.
    # TODO create references only after all parsing is done
    options = {
        "Sandbox info": {
            "method": lambda self: self.add_sandbox_info(),
            "userConfig": {
                "type": "Boolean",
                "message": "Add info related to the sandbox",
                "checked": "true",
            },
        },
        "Upload sample": {
            "method": lambda self: self.add_sample(),
            "userConfig": {
                "type": "Boolean",
                "message": "Upload the sample",
                "checked": "true",
            },
        },
        "Processes": {
            "method": lambda self: self.add_process_tree(),
            "userConfig": {
                "type": "Boolean",
                "message": "Add info related to the processes",
                "checked": "true",
            },
        },
        "DNS": {
            "method": lambda self: self.add_dns(),
            "userConfig": {
                "type": "Boolean",
                "message": "Add DNS queries/answers",
                "checked": "true",
            },
        },
        "TCP": {
            "method": lambda self: self.add_network("tcp"),
            "userConfig": {
                "type": "Boolean",
                "message": "Add TCP connections",
                "checked": "true",
            },
        },
        "UDP": {
            "method": lambda self: self.add_network("udp"),
            "userConfig": {
                "type": "Boolean",
                "message": "Add UDP connections",
                "checked": "true",
            },
        },
        "HTTP": {
            "method": lambda self: self.add_http(),
            "userConfig": {
                "type": "Boolean",
                "message": "Add HTTP requests",
                "checked": "true",
            },
        },
        "Signatures": {
            "method": lambda self: self.add_signatures(),
            "userConfig": {
                "type": "Boolean",
                "message": "Add Cuckoo's triggered signatures",
                "checked": "true",
            },
        },
        "Screenshots": {
            "method": lambda self: self.add_screenshots(),
            "userConfig": {
                "type": "Boolean",
                "message": "Upload the screenshots",
                "checked": "true",
            },
        },
        "Dropped files": {
            "method": lambda self: self.add_dropped_files(),
            "userConfig": {
                "type": "Boolean",
                "message": "Upload the dropped files",
                "checked": "true",
            },
        },
        "Dropped buffers": {
            "method": lambda self: self.add_dropped_buffers(),
            "userConfig": {
                "type": "Boolean",
                "message": "Upload the dropped buffers",
                "checked": "true",
            },
        },
        "CAPE configurations": {
            "method": lambda self: self.add_cape_configurations(),
            "userConfig": {
                "type": "Boolean",
                "message": "Add extracted CAPE configurations",
                "checked": "true",
            },
        },
    }

    def __init__(self, config):
        self.event = MISPEvent()
        self.files = {}
        self.resources = ExitStack()
        self.malware_binary = None
        self.report = None
        # Missing options use the defaults advertised to the MISP UI.
        self.config = {
            key: int(config[key]) if config.get(key) is not None else option["userConfig"]["checked"] == "true"
            for key, option in self.options.items()
        }

    def close(self):
        self.resources.close()

    @property
    def sandbox_name(self):
        return "cape" if "CAPE" in self.report or "CAPE_current_commit" in self.report.get("info", {}) else "cuckoo"

    def get_file(self, relative_filepath):
        """Return an archive member, or an empty in-memory stream if absent."""
        return self.files.get(relative_filepath, io.BytesIO())

    def read_archive(self, archive_encoded):
        """Read a standalone report or the archive exported from Cuckoo/CAPE."""
        # archive_encoded is base 64 encoded content
        # we extract the info about each file but do not retrieve
        # it automatically, as it may take too much space in memory
        try:
            content = base64.b64decode(archive_encoded, validate=True)
        except (binascii.Error, ValueError, TypeError):
            raise ReportError("The uploaded report must contain valid base64 data.") from None
        buf_io = io.BytesIO(content)
        if zipfile.is_zipfile(buf_io):
            # the archive was probably downloaded from the WebUI
            buf_io.seek(0)  # don't forget this not to read an empty buffer
            z = self.resources.enter_context(zipfile.ZipFile(buf_io, "r"))
            self.files = {
                info.filename: self.resources.enter_context(z.open(info))
                for info in z.filelist
                # Keep regular files, including ZIPs without Unix type bits.
                if not info.is_dir()
                and (stat.S_ISREG(info.external_attr >> 16) or stat.S_IFMT(info.external_attr >> 16) == 0)
            }
        elif content.startswith(b"BZh"):
            # the archive was probably downloaded from the API
            buf_io.seek(0)  # don't forget this not to read an empty buffer
            f = self.resources.enter_context(tarfile.open(fileobj=buf_io, mode="r:bz2"))
            self.files = {
                info.name: self.resources.enter_context(f.extractfile(info))
                for info in f.getmembers()
                # Never follow symbolic links or hard links.
                if info.isreg()
            }
        else:
            buf_io.seek(0)
            self._read_report(buf_io)
            return

        # We want to keep the order of the keys of sub-dicts in the report,
        # eg. the signatures have marks with unknown keys such as
        #     {'marks': [
        #        {"suspicious_features": "Connection to IP address",
        #         "suspicious_request": "OPTIONS http://85.20.18.18/doc"}
        #     ]}
        # To render those marks properly, we can only hope the developpers
        # thought about the order in which they put the keys, and keep this
        # order so that the signature makes sense to the reader.
        # We use PrettyDict, a customization of OrderedDict to do so.
        # It will be instanced iteratively when parsing the json (ie. subdicts
        # will also be instanced as PrettyDict)
        report = self.files.get("reports/report.json", self.files.get("report.json"))
        if report is None:
            raise ReportError("The archive must contain reports/report.json or report.json as a regular file.")
        self._read_report(report)

    def _read_report(self, report):
        try:
            self.report = json.load(report, object_pairs_hook=PrettyDict)
        except (ValueError, UnicodeError):
            raise ReportError("Expected a valid Cuckoo/CAPE JSON report, ZIP archive or bzip2 tarball.") from None
        if not isinstance(self.report, dict) or not any(
            key in self.report for key in ("info", "target", "network", "behavior", "signatures", "CAPE")
        ):
            raise ReportError("The JSON must be a Cuckoo/CAPE report object containing analysis sections.")
        for key in ("info", "target", "network", "behavior", "CAPE"):
            if key in self.report and not isinstance(self.report[key], dict):
                raise ReportError(f"The report section '{key}' must be a JSON object.")

    def read_malware(self):
        self.malware_binary = self.get_file("binary").read()
        if not self.malware_binary:
            log.warning("No malware binary found; importing file metadata only")

    def add_sandbox_info(self):
        info = self.report.get("info", {})
        if not info:
            log.warning("The 'info' field was not found in the report, skipping")
            return False

        o = MISPObject(name="sandbox-report")
        score = info.get("score", self.report.get("malscore"))
        if score is not None:
            o.add_attribute("score", score)
        o.add_attribute("sandbox-type", "on-premise")
        o.add_attribute("on-premise-sandbox", self.sandbox_name)
        machine = info.get("machine") or {}
        if not isinstance(machine, dict):
            machine = {"name": machine}
        o.add_attribute(
            "raw-report",
            f'started on:{info.get("started", machine.get("started_on", "unknown"))} '
            f'duration:{info.get("duration", "unknown")}s '
            f'vm:{machine.get("name", "unknown")}/{machine.get("label", "unknown")}',
        )
        self.event.add_object(o)

    def add_sample(self):
        """Add the sample/target of the analysis"""
        target = self.report.get("target", {})
        category = target.get("category", "")
        if not category:
            log.warning("Could not find info about the sample in the report, skipping")
            return False

        if category in ("file", "static"):
            log.debug("Sample is a file, uploading it")
            self.read_malware()
            file_o, bin_type_o, bin_section_li = self._file_objects(
                target["file"],
                self.malware_binary,
            )

            file_o.comment = "Submitted sample"
            # fix categories
            for obj in filter(
                None,
                (
                    file_o,
                    bin_type_o,
                    *bin_section_li,
                ),
            ):
                for attr in obj.attributes:
                    if attr.type in PAYLOAD_DELIVERY:
                        attr.category = "Payload delivery"
                self.event.add_object(obj)

        elif category == "url":
            log.debug("Sample is a URL")
            o = MISPObject(name="url")
            o.add_attribute("url", target["url"])
            o.add_attribute("text", "Submitted URL")
            self.event.add_object(o)

    def _file_objects(self, metadata, content=b"", filename=None):
        """Keep reported hashes when the upload does not contain the binary."""
        filename = filename or metadata.get("name")
        if isinstance(filename, list):
            filename = next((name for name in filename if name), None)
        if content:
            return make_binary_objects(pseudofile=io.BytesIO(content), filename=filename)
        obj = MISPObject("file")
        if filename:
            obj.add_attribute("filename", filename)
        for relation in ("md5", "sha1", "sha256", "sha512", "ssdeep", "tlsh"):
            if metadata.get(relation):
                obj.add_attribute(relation, metadata[relation])
        if metadata.get("size") is not None:
            obj.add_attribute("size-in-bytes", metadata["size"])
        if metadata.get("type"):
            obj.add_attribute("magic", metadata["type"])
        return obj, None, []

    def add_http(self):
        """Add the HTTP requests"""
        network = self.report.get("network", {})
        http = network.get("http", [])
        if not http:
            log.info("No HTTP connection found in the report, skipping")
            return False

        for request in http:
            o = MISPObject(name="http-request")
            o.add_attribute("host", request["host"])
            o.add_attribute("method", request["method"])
            o.add_attribute("uri", request["uri"])
            o.add_attribute("user-agent", request["user-agent"])
            o.add_attribute("text", f"count:{request['count']} port:{request['port']}")
            self.event.add_object(o)

    def add_network(self, proto=None):
        """
        Add UDP/TCP traffic
        proto must be one of "tcp", "udp"
        """
        network = self.report.get("network", {})
        li_conn = network.get(proto, [])
        if not li_conn:
            log.info(f"No {proto} connection found in the report, skipping")
            return False

        from_to = []
        # sort by time to get the "first packet seen" right
        li_conn.sort(key=lambda x: x["time"])
        for conn in li_conn:
            src = conn["src"]
            dst = conn["dst"]
            sport = conn["sport"]
            dport = conn["dport"]
            if (src, sport, dst, dport) in from_to:
                continue

            from_to.append((src, sport, dst, dport))

            o = MISPObject(name="network-connection")
            o.add_attribute("ip-src", src)
            o.add_attribute("ip-dst", dst)
            o.add_attribute("src-port", sport)
            o.add_attribute("dst-port", dport)
            o.add_attribute("layer3-protocol", "IP")
            o.add_attribute("layer4-protocol", proto.upper())
            # CAPE stores seconds since the first captured packet. The capture
            # start is not exported in JSON and can differ from info.started.
            if self.sandbox_name == "cape":
                o.comment = f'First packet observed {conn["time"]} seconds after capture start'
            else:
                o.add_attribute("first-packet-seen", conn["time"])
            self.event.add_object(o)

    def add_dns(self):
        """Add DNS records"""
        network = self.report.get("network", {})
        dns = network.get("dns", [])
        if not dns:
            log.info("No DNS connection found in the report, skipping")
            return False

        for record in dns:
            o = MISPObject(name="dns-record")
            o.add_attribute("text", f"request type:{record['type']}")
            o.add_attribute("queried-domain", record["request"])
            for answer in record.get("answers", []):
                if answer["type"] in ("A", "AAAA"):
                    o.add_attribute("a-record", answer["data"])
                # TODO implement MX/NS

            self.event.add_object(o)

    def _get_marks_str(self, marks):
        marks_strings = []
        for m in marks:
            m = m.copy()
            m_type = m.pop("type")

            if m_type == "generic":
                marks_strings.append(str(m))

            elif m_type == "ioc":
                marks_strings.append(m["ioc"])

            elif m_type == "call":
                call = m["call"]
                arguments = call.get("arguments", {})
                flags = call.get("flags", {})
                info = ""
                for details in (arguments, flags):
                    info += f" {details}"
                marks_strings.append(f"Call API '{call['api']}'%s" % info)

            else:
                logging.debug(f"Unknown mark type '{m_type}', skipping")

            # TODO implemented marks 'config' and 'volatility'
        return marks_strings

    def _add_ttp(self, attribute, ttp_short, ttp_num):
        """
        Internal wrapper to add the TTP tag from the MITRE galaxy.
        @ params
            - attribute: MISPAttribute
            - ttp_short: short description of the TTP
              (eg. "Credential Dumping")
            - ttp_num: formatted as "T"+int
              (eg. T1003)
        """
        attribute.add_tag(f"misp-galaxy:mitre-attack-pattern=" f'"{ttp_short} - {ttp_num}"')

    def add_signatures(self):
        """Add the Cuckoo signatures, with as many details as possible
        regarding the marks"""
        signatures = self.report.get("signatures", [])
        if not signatures:
            log.info("No signature found in the report")
            return False

        o = MISPObject(name="sb-signature")
        o.add_attribute("software", "CAPE" if self.sandbox_name == "cape" else "Cuckoo")

        for sign in signatures:
            marks = sign.get("marks", [])
            marks_strings = self._get_marks_str(marks)
            # CAPE signatures use data/new_data rather than Cuckoo's marks.
            for key in ("data", "new_data"):
                if sign.get(key):
                    marks_strings.append(json.dumps(sign[key], ensure_ascii=False))
            for entry in self.report.get("ttps", []):
                if entry.get("signature") == sign.get("name"):
                    marks_strings.append("ATT&CK: " + ", ".join(entry.get("ttps", [])))
            summary = sign["description"]
            if marks_strings:
                summary += "\n---\n"

            marks_strings = dict.fromkeys(marks_strings)
            description = summary + "\n".join(marks_strings)

            a = MISPAttribute()
            a.from_dict(type="text", value=description)
            for ttp_num, desc in sign.get("ttp", {}).items():
                ttp_short = desc["short"]
                self._add_ttp(a, ttp_short, ttp_num)

            # this signature was triggered by the processes with the following
            # PIDs, we can create references
            triggered_by_pids = filter(None, (m.get("pid", None) for m in marks))
            # remove redundancy
            triggered_by_pids = set(triggered_by_pids)
            for pid in triggered_by_pids:
                process_o = find_process_by_pid(self.event, pid)
                if process_o:
                    process_o.add_reference(a, "triggers")

            o.add_attribute("signature", **a)

        self.event.add_object(o)

    def _handle_process(self, proc, accu):
        """
        This is an internal recursive function to handle one process
        from a process tree and then iterate on its children.
        List the objects to be added, based on the tree, into the `accu` list.
        The `accu` list uses a DFS-like order.
        """
        o = MISPObject(name="process")
        accu.append(o)
        o.add_attribute("pid", proc["pid"])
        fields = {
            "command-line": proc.get("command_line") or (proc.get("environ") or {}).get("CommandLine"),
            "name": proc.get("process_name", proc.get("name")),
            "parent-pid": proc.get("ppid", proc.get("parent_id")),
            "image": proc.get("module_path"),
        }
        for relation, value in fields.items():
            if value is not None and value != "":
                o.add_attribute(relation, value)
        for child in proc.get("children", []):
            pos_child = len(accu)
            o.add_attribute("child-pid", child["pid"])
            self._handle_process(child, accu)
            child_obj = accu[pos_child]
            child_obj.add_reference(o, "child-of")

        return o

    def add_process_tree(self):
        """Add process tree from the report, as separated process objects"""
        behavior = self.report.get("behavior", {})
        tree = behavior.get("processtree", [])
        if not tree:
            log.warning("No process tree found in the report, skipping")
            return False

        for proc in tree:
            objs = []
            self._handle_process(proc, objs)
            for o in objs:
                self.event.add_object(o)

    def get_relpath(self, path):
        """
        Transform an absolute or relative path into a path relative to the
        correct cuckoo analysis directory, without knowing the cuckoo
        working directory.
        Return an empty string if the path given does not refer to a
        file from the analysis directory.
        """
        # Archives need not contain separate directory entries. Match suffixes
        # against actual members instead of recursing through those entries.
        candidate = path.lstrip("/")
        while candidate:
            if candidate in self.files:
                return candidate
            _, separator, candidate = candidate.partition("/")
            if not separator:
                break
        return ""

    def add_screenshots(self):
        """Add the screenshots taken by Cuckoo in a sandbox-report object"""
        screenshots = [shot["path"] for shot in self.report.get("screenshots", [])]
        if not screenshots:
            screenshots = [path for path in self.files if path.startswith("shots/") and path.endswith((".jpg", ".png"))]
        if not screenshots:
            log.info("No screenshot found in the report, skipping")
            return False

        o = MISPObject(name="sandbox-report")
        o.add_attribute("sandbox-type", "on-premise")
        o.add_attribute("on-premise-sandbox", self.sandbox_name)
        for shot in screenshots:
            # The path given by Cuckoo is an absolute path, but we need a path
            # relative to the analysis folder.
            path = self.get_relpath(shot)
            if not path:
                continue
            img = self.get_file(path)
            # .decode('utf-8') in order to avoid the b'' format
            img_data = base64.b64encode(img.read()).decode("utf-8")
            filename = posixpath.basename(path)

            o.add_attribute(
                "sandbox-file",
                value=filename,
                data=img_data,
                type="attachment",
                category="External analysis",
            )

        if o.get_attributes_by_relation("sandbox-file"):
            self.event.add_object(o)

    def _get_dropped_objs(self, path, filename=None, comment=None, metadata=None):
        """
        Internal wrapper to get dropped files/buffers as file objects
        @ params
            - path: relative to the cuckoo analysis directory
            - filename: if not specified, deduced from the path
        """
        if not filename:
            filename = posixpath.basename(path)

        dropped_file = self.get_file(path)
        dropped_binary = dropped_file.read()
        # create ad hoc objects
        file_o, bin_type_o, bin_section_li = self._file_objects(metadata or {}, dropped_binary, filename)

        if comment:
            file_o.comment = comment
        # fix categories
        for obj in filter(
            None,
            (
                file_o,
                bin_type_o,
                *bin_section_li,
            ),
        ):
            for attr in obj.attributes:
                if attr.type in ARTIFACTS_DROPPED:
                    attr.category = "Artifacts dropped"

        return file_o, bin_type_o, bin_section_li

    def _add_yara(self, obj, yara_dict):
        """Internal wrapper to add Yara matches to an MISPObject"""
        for yara in yara_dict:
            description = yara.get("meta", {}).get("description", "")
            name = yara.get("name", "")
            obj.add_attribute(
                "text",
                f"Yara match\n(name) {name}\n(description) {description}",
                comment="Yara match",
            )

    def add_dropped_files(self):
        """Upload the dropped files as file objects"""
        dropped = self.report.get("dropped", [])
        if not dropped:
            log.info("No dropped file found, skipping")
            return False

        for d in dropped:
            # Cuckoo logs three things that are of interest for us:
            #   - 'filename' which is not the original name of the file
            #     but is formatted as follow:
            #        8 first bytes of SHA265 + _ + original name in lower case
            #   - 'filepath' which is the original filepath on the VM,
            #     where the file was dropped
            #   - 'path' which is the local path of the stored file,
            #     in the cuckoo archive
            filename = d.get("name", "")
            if isinstance(filename, list):
                filename = next((name for name in filename if name), "")
            original_path = d.get("filepath", "")
            guest_paths = d.get("guest_paths", [])
            if not original_path and guest_paths:
                original_path = guest_paths[0]
            sha256 = d.get("sha256", "")
            if original_path and sha256:
                log.debug(f"Will now try to restore original filename from path {original_path}")
                try:
                    s = filename.split("_")
                    if not s:
                        raise Exception("unexpected filename read in the report")
                    sha256_first_8_bytes = s[0]
                    original_name = s[1]
                    # check our assumptions are valid, if so we can safely
                    # restore the filename, if not the format may have changed
                    # so we'll keep the filename of the report
                    if (
                        sha256.startswith(sha256_first_8_bytes)
                        and original_path.lower().endswith(original_name)
                        and filename not in original_path.lower()
                    ):
                        # we can restore the original case of the filename
                        position = original_path.lower().rindex(original_name)
                        filename = original_path[position:]
                        log.debug(f"Successfully restored original filename: {filename}")
                    else:
                        raise Exception("our assumptions were wrong, filename format may have changed")
                except Exception as e:
                    log.debug(f"Cannot restore filename: {e}")

            if not filename:
                filename = "NO NAME FOUND IN THE REPORT"
                log.warning(f"No filename found for dropped file! " f'Will use "{filename}"')

            file_o, bin_type_o, bin_section_o = self._get_dropped_objs(
                self.get_relpath(d.get("path", "")), filename=filename, comment="Dropped file", metadata=d
            )

            self._add_yara(file_o, d.get("yara", []))

            for path in dict.fromkeys([original_path, *guest_paths]):
                if path:
                    file_o.add_attribute("fullpath", path, category="Artifacts dropped")

            # why is this a list? for when various programs drop the same file?
            for pid in d.get("pids", []):
                # if we have an object for the process that dropped the file,
                # we can link the two (we just take the first result from
                # the search)
                process_o = find_process_by_pid(self.event, pid)
                if process_o:
                    file_o.add_reference(process_o, "dropped-by")

            self.event.add_object(file_o)

    def add_dropped_buffers(self):
        """ "Upload the dropped buffers as file objects"""
        buffer = self.report.get("buffer", [])
        if not buffer:
            log.info("No dropped buffer found, skipping")
            return False

        for i, buf in enumerate(buffer):
            file_o, bin_type_o, bin_section_o = self._get_dropped_objs(
                self.get_relpath(buf["path"]),
                filename=f"buffer {i}",
                comment="Dropped buffer",
                metadata=buf,
            )
            self._add_yara(file_o, buf.get("yara", []))
            self.event.add_object(file_o)

    def add_cape_configurations(self):
        for config in self.report.get("CAPE", {}).get("configs", []):
            obj = MISPObject("annotation")
            obj.add_attribute("text", json.dumps(config, ensure_ascii=False), to_ids=False)
            obj.comment = "CAPE extracted configuration"
            self.event.add_object(obj)

    def parse(self):
        """Run the parsing"""
        for name, active in self.config.items():
            if active:
                self.options[name]["method"](self)

    def get_misp_event(self):
        log.debug("Running MISP expansions")
        self.event.run_expansions()
        return self.event


def handler(q=False):
    # In case there's no data
    if q is False:
        return False

    parser = None
    try:
        try:
            request = json.loads(q)
        except (ValueError, TypeError):
            raise ReportError("The import request must be a JSON object containing base64 report data.") from None
        if not isinstance(request, dict) or not isinstance(request.get("data"), str):
            raise ReportError("The import request must contain base64 report data in 'data'.")
        config = request.get("config", {})
        if config is None:
            config = {}
        if not isinstance(config, dict):
            raise ReportError("The import configuration must be a JSON object.")
        for key in CuckooParser.options:
            if config.get(key) not in (None, True, False, 0, 1, "0", "1"):
                raise ReportError(f"The import option '{key}' must be 0 or 1.")
        parser = CuckooParser(config)
        parser.read_archive(request["data"])
        parser.parse()
        event = json.loads(parser.get_misp_event().to_json())
        results = {key: event[key] for key in ("Attribute", "Object") if (key in event and event[key])}
        return {"results": results}
    except ReportError as exc:
        return {"error": str(exc)}
    except (tarfile.TarError, zipfile.BadZipFile, EOFError, OSError, RuntimeError):
        log.exception("Unable to read Cuckoo/CAPE analysis archive")
        return {"error": "Unable to read the analysis archive; check that it is complete and not encrypted."}
    except (KeyError, TypeError, ValueError, AttributeError, IndexError, PyMISPError):
        log.exception("Invalid or unsupported Cuckoo/CAPE report structure")
        return {"error": "Invalid or unsupported Cuckoo/CAPE report structure; see the server log for details."}
    finally:
        if parser is not None:
            parser.close()


def introspection():
    userConfig = {key: o["userConfig"] for key, o in CuckooParser.options.items()}
    mispattributes["userConfig"] = userConfig
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
