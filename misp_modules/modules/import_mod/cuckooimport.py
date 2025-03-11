import base64
import io
import json
import logging
import posixpath
import stat
import tarfile
import zipfile
from collections import OrderedDict

from pymisp import MISPAttribute, MISPEvent, MISPObject
from pymisp.tools import make_binary_objects

log = logging.getLogger(__name__)

misperrors = {"error": "Error"}

moduleinfo = {
    "version": "1.1",
    "author": "Pierre-Jean Grenier",
    "module-type": ["import"],
    "name": "Cuckoo Sandbox Import",
    "description": "Module to import Cuckoo JSON.",
    "logo": "cuckoo.png",
    "requirements": [],
    "features": (
        "Import a Cuckoo archive (zipfile or bzip2 tarball), either downloaded manually or exported from the API"
        " (/tasks/report/<task_id>/all)."
    ),
    "references": [
        "https://cuckoosandbox.org/",
        "https://github.com/cuckoosandbox/cuckoo",
    ],
    "input": "Cuckoo JSON file",
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
    }

    def __init__(self, config):
        self.event = MISPEvent()
        self.files = None
        self.malware_binary = None
        self.report = None
        self.config = {
            # if an option is missing (we receive None as a value),
            # fall back to the default specified in the options
            key: int(on if on is not None else self.options[key]["userConfig"]["checked"] == "true")
            for key, on in config.items()
        }

    def get_file(self, relative_filepath):
        """Return an io.BufferedIOBase for the corresponding relative_filepath
        in the Cuckoo archive. If not found, return an empty io.BufferedReader
        to avoid fatal errors."""
        blackhole = io.BufferedReader(open("/dev/null", "rb"))
        res = self.files.get(relative_filepath, blackhole)
        if res == blackhole:
            log.debug(f"Did not find file {relative_filepath}, returned an empty file instead")
        return res

    def read_archive(self, archive_encoded):
        """Read the archive exported from Cuckoo and initialize the class"""
        # archive_encoded is base 64 encoded content
        # we extract the info about each file but do not retrieve
        # it automatically, as it may take too much space in memory
        buf_io = io.BytesIO(base64.b64decode(archive_encoded))
        if zipfile.is_zipfile(buf_io):
            # the archive was probably downloaded from the WebUI
            buf_io.seek(0)  # don't forget this not to read an empty buffer
            z = zipfile.ZipFile(buf_io, "r")
            self.files = {
                info.filename: z.open(info)
                for info in z.filelist
                # only extract the regular files and dirs, we don't
                # want any symbolic link
                if stat.S_ISREG(info.external_attr >> 16) or stat.S_ISDIR(info.external_attr >> 16)
            }
        else:
            # the archive was probably downloaded from the API
            buf_io.seek(0)  # don't forget this not to read an empty buffer
            f = tarfile.open(fileobj=buf_io, mode="r:bz2")
            self.files = {
                info.name: f.extractfile(info)
                for info in f.getmembers()
                # only extract the regular files and dirs, we don't
                # want any symbolic link
                if info.isreg() or info.isdir()
            }

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
        self.report = json.load(
            self.get_file("reports/report.json"),
            object_pairs_hook=PrettyDict,
        )

    def read_malware(self):
        self.malware_binary = self.get_file("binary").read()
        if not self.malware_binary:
            log.warn("No malware binary found")

    def add_sandbox_info(self):
        info = self.report.get("info", {})
        if not info:
            log.warning("The 'info' field was not found in the report, skipping")
            return False

        o = MISPObject(name="sandbox-report")
        o.add_attribute("score", info["score"])
        o.add_attribute("sandbox-type", "on-premise")
        o.add_attribute("on-premise-sandbox", "cuckoo")
        o.add_attribute(
            "raw-report",
            f'started on:{info["machine"]["started_on"]} '
            f'duration:{info["duration"]}s '
            f'vm:{info["machine"]["name"]}/'
            f'{info["machine"]["label"]}',
        )
        self.event.add_object(o)

    def add_sample(self):
        """Add the sample/target of the analysis"""
        target = self.report.get("target", {})
        category = target.get("category", "")
        if not category:
            log.warning("Could not find info about the sample in the report, skipping")
            return False

        if category == "file":
            log.debug("Sample is a file, uploading it")
            self.read_malware()
            file_o, bin_type_o, bin_section_li = make_binary_objects(
                pseudofile=io.BytesIO(self.malware_binary),
                filename=target["file"]["name"],
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

    def add_http(self):
        """Add the HTTP requests"""
        network = self.report.get("network", [])
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
        network = self.report.get("network", [])
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
            o.add_attribute("first-packet-seen", conn["time"])
            self.event.add_object(o)

    def add_dns(self):
        """Add DNS records"""
        network = self.report.get("network", [])
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
            m_type = m.pop("type")  # temporarily remove the type

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

            m["type"] = m_type  # restore key 'type'
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
        o.add_attribute("software", "Cuckoo")

        for sign in signatures:
            marks = sign["marks"]
            marks_strings = self._get_marks_str(marks)
            summary = sign["description"]
            if marks_strings:
                summary += "\n---\n"

            marks_strings = set(marks_strings)
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
        o.add_attribute("command-line", proc["command_line"])
        o.add_attribute("name", proc["process_name"])
        o.add_attribute("parent-pid", proc["ppid"])
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
        head, tail = posixpath.split(path)
        if not tail:
            return ""
        prev = self.get_relpath(head)
        longer = posixpath.join(prev, tail)
        if longer in self.files:
            return longer
        elif tail in self.files:
            return tail
        else:
            return ""

    def add_screenshots(self):
        """Add the screenshots taken by Cuckoo in a sandbox-report object"""
        screenshots = self.report.get("screenshots", [])
        if not screenshots:
            log.info("No screenshot found in the report, skipping")
            return False

        o = MISPObject(name="sandbox-report")
        o.add_attribute("sandbox-type", "on-premise")
        o.add_attribute("on-premise-sandbox", "cuckoo")
        for shot in screenshots:
            # The path given by Cuckoo is an absolute path, but we need a path
            # relative to the analysis folder.
            path = self.get_relpath(shot["path"])
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

        self.event.add_object(o)

    def _get_dropped_objs(self, path, filename=None, comment=None):
        """
        Internal wrapper to get dropped files/buffers as file objects
        @ params
            - path: relative to the cuckoo analysis directory
            - filename: if not specified, deduced from the path
        """
        if not filename:
            filename = posixpath.basename(path)

        dropped_file = self.get_file(path)
        dropped_binary = io.BytesIO(dropped_file.read())
        # create ad hoc objects
        file_o, bin_type_o, bin_section_li = make_binary_objects(
            pseudofile=dropped_binary,
            filename=filename,
        )

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
            original_path = d.get("filepath", "")
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
                self.get_relpath(d["path"]), filename=filename, comment="Dropped file"
            )

            self._add_yara(file_o, d.get("yara", []))

            file_o.add_attribute("fullpath", original_path, category="Artifacts dropped")

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
            )
            self._add_yara(file_o, buf.get("yara", []))
            self.event.add_object(file_o)

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

    q = json.loads(q)
    data = q["data"]

    parser = CuckooParser(q["config"])
    parser.read_archive(data)
    parser.parse()
    event = parser.get_misp_event()

    event = json.loads(event.to_json())
    results = {key: event[key] for key in ("Attribute", "Object") if (key in event and event[key])}
    return {"results": results}


def introspection():
    userConfig = {key: o["userConfig"] for key, o in CuckooParser.options.items()}
    mispattributes["userConfig"] = userConfig
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
