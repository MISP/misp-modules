import base64
import json
import re
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import PureWindowsPath
from typing import Any, Dict, Iterator, List, Optional, Tuple, Union

from pymisp import MISPAttribute, MISPEvent, MISPObject

from .rest_api import VMRayRESTAPI, VMRayRESTAPIError

USER_RE = re.compile(r".:.Users\\(.*?)\\", re.IGNORECASE)
DOC_RE = re.compile(r".:.DOCUME~1.\\(.*?)\\", re.IGNORECASE)
DOC_AND_SETTINGS_RE = re.compile(r".:.Documents and Settings\\(.*?)\\", re.IGNORECASE)
USERPROFILES = [USER_RE, DOC_RE, DOC_AND_SETTINGS_RE]


def classifications_to_str(classifications: List[str]) -> Optional[str]:
    if classifications:
        return "Classifications: " + ", ".join(classifications)
    return None


def merge_lists(target: List[Any], source: List[Any]):
    return list({*target, *source})


@dataclass
class Attribute:
    type: str
    value: str
    category: Optional[str] = None
    comment: Optional[str] = None
    to_ids: bool = False

    def __eq__(self, other: Dict[str, Any]) -> bool:
        return asdict(self) == other


@dataclass
class Artifact:
    is_ioc: bool
    verdict: Optional[str]

    @abstractmethod
    def to_attributes(self) -> Iterator[Attribute]:
        raise NotImplementedError()

    @abstractmethod
    def to_misp_object(self, tag: bool) -> MISPObject:
        raise NotImplementedError()

    @abstractmethod
    def merge(self, other: "Artifact") -> None:
        raise NotImplementedError()

    @abstractmethod
    def __eq__(self, other: "Artifact") -> bool:
        raise NotImplementedError()

    def tag_artifact_attribute(self, attribute: MISPAttribute) -> None:
        if self.is_ioc:
            attribute.add_tag('vmray:artifact="IOC"')

        if self.verdict:
            attribute.add_tag(f'vmray:verdict="{self.verdict}"')


@dataclass
class DomainArtifact(Artifact):
    domain: str
    sources: List[str]
    ips: List[str] = field(default_factory=list)
    classifications: List[str] = field(default_factory=list)

    def to_attributes(self) -> Iterator[Attribute]:
        value = self.domain
        comment = ", ".join(self.sources) if self.sources else None

        attr = Attribute(type="domain", value=value, comment=comment)
        yield attr

    def to_misp_object(self, tag: bool) -> MISPObject:
        obj = MISPObject(name="domain-ip")

        classifications = classifications_to_str(self.classifications)
        attr = obj.add_attribute("domain", value=self.domain, to_ids=self.is_ioc, comment=classifications)
        if tag and attr:
            self.tag_artifact_attribute(attr)

        for ip in self.ips:
            obj.add_attribute("ip", value=ip, to_ids=self.is_ioc)

        return obj

    def merge(self, other: Artifact) -> None:
        if not isinstance(other, DomainArtifact):
            return

        self.ips = merge_lists(self.ips, other.ips)
        self.classifications = merge_lists(self.classifications, other.classifications)

    def __eq__(self, other: Artifact) -> bool:
        if not isinstance(other, DomainArtifact):
            return NotImplemented

        return self.domain == other.domain


@dataclass
class EmailArtifact(Artifact):
    sender: Optional[str]
    subject: Optional[str]
    recipients: List[str] = field(default_factory=list)
    classifications: List[str] = field(default_factory=list)

    def to_attributes(self) -> Iterator[Attribute]:
        if self.sender:
            classifications = classifications_to_str(self.classifications)
            yield Attribute(type="email-src", value=self.sender, comment=classifications)

        if self.subject:
            yield Attribute(type="email-subject", value=self.subject, to_ids=False)

        for recipient in self.recipients:
            yield Attribute(type="email-dst", value=recipient, to_ids=False)

    def to_misp_object(self, tag: bool) -> MISPObject:
        obj = MISPObject(name="email")

        if self.sender:
            classifications = classifications_to_str(self.classifications)
            attr = obj.add_attribute("from", value=self.sender, to_ids=self.is_ioc, comment=classifications)
            if tag and attr:
                self.tag_artifact_attribute(attr)

        if self.subject:
            obj.add_attribute("subject", value=self.subject, to_ids=False)

        for recipient in self.recipients:
            obj.add_attribute("to", value=recipient, to_ids=False)

        return obj

    def merge(self, other: Artifact) -> None:
        if not isinstance(other, EmailArtifact):
            return

        self.recipients = merge_lists(self.recipients, other.recipients)
        self.classifications = merge_lists(self.classifications, other.classifications)

    def __eq__(self, other: Artifact) -> bool:
        if not isinstance(other, EmailArtifact):
            return NotImplemented

        return self.sender == other.sender and self.subject == other.subject


@dataclass
class FileArtifact(Artifact):
    filenames: List[str]
    operations: List[str]
    md5: str
    sha1: str
    sha256: str
    ssdeep: str
    imphash: Optional[str]
    classifications: List[str]
    size: Optional[int]
    mimetype: Optional[str] = None

    def to_attributes(self) -> Iterator[Attribute]:
        operations = ", ".join(self.operations)
        comment = f"File operations: {operations}"

        for filename in self.filenames:
            attr = Attribute(type="filename", value=filename, comment=comment)
            yield attr

        for hash_type in ("md5", "sha1", "sha256", "ssdeep", "imphash"):
            for filename in self.filenames:
                value = getattr(self, hash_type)
                if value is not None:
                    attr = Attribute(
                        type=f"filename|{hash_type}",
                        value=f"{filename}|{value}",
                        category="Payload delivery",
                        to_ids=True,
                    )
                    yield attr

    def to_misp_object(self, tag: bool) -> MISPObject:
        obj = MISPObject(name="file")

        if self.size:
            obj.add_attribute("size-in-bytes", value=self.size)

        classifications = classifications_to_str(self.classifications)
        hashes = [
            ("md5", self.md5),
            ("sha1", self.sha1),
            ("sha256", self.sha256),
            ("ssdeep", self.ssdeep),
        ]
        for key, value in hashes:
            if not value:
                continue

            attr = obj.add_attribute(key, value=value, to_ids=self.is_ioc, comment=classifications)

            if tag and attr:
                self.tag_artifact_attribute(attr)

        if self.mimetype:
            obj.add_attribute("mimetype", value=self.mimetype, to_ids=False)

        operations = None
        if self.operations:
            operations = "Operations: " + ", ".join(self.operations)

        for filename in self.filenames:
            filename = PureWindowsPath(filename)
            obj.add_attribute("filename", value=filename.name, comment=operations)

            fullpath = str(filename)
            for regex in USERPROFILES:
                fullpath = regex.sub(r"%USERPROFILE%\\", fullpath)

            obj.add_attribute("fullpath", fullpath)

        return obj

    def merge(self, other: Artifact) -> None:
        if not isinstance(other, FileArtifact):
            return

        self.filenames = merge_lists(self.filenames, other.filenames)
        self.operations = merge_lists(self.operations, other.operations)
        self.classifications = merge_lists(self.classifications, other.classifications)

    def __eq__(self, other: Artifact) -> bool:
        if not isinstance(other, FileArtifact):
            return NotImplemented

        return self.sha256 == other.sha256


@dataclass
class IpArtifact(Artifact):
    ip: str
    sources: List[str]
    classifications: List[str] = field(default_factory=list)

    def to_attributes(self) -> Iterator[Attribute]:
        sources = ", ".join(self.sources)
        comment = f"Found in: {sources}"

        attr = Attribute(type="ip-dst", value=self.ip, comment=comment)
        yield attr

    def to_misp_object(self, tag: bool) -> MISPObject:
        obj = MISPObject(name="ip-port")

        classifications = classifications_to_str(self.classifications)
        attr = obj.add_attribute("ip", value=self.ip, comment=classifications, to_ids=self.is_ioc)
        if tag and attr:
            self.tag_artifact_attribute(attr)

        return obj

    def merge(self, other: Artifact) -> None:
        if not isinstance(other, IpArtifact):
            return

        self.sources = merge_lists(self.sources, other.sources)
        self.classifications = merge_lists(self.classifications, other.classifications)

    def __eq__(self, other: Artifact) -> bool:
        if not isinstance(other, IpArtifact):
            return NotImplemented

        return self.ip == other.ip


@dataclass
class MutexArtifact(Artifact):
    name: str
    operations: List[str]
    classifications: List[str] = field(default_factory=list)

    def to_attributes(self) -> Iterator[Attribute]:
        operations = ", ".join(self.operations)
        comment = f"Operations: {operations}"

        attr = Attribute(type="mutex", value=self.name, comment=comment)
        yield attr

    def to_misp_object(self, tag: bool) -> MISPObject:
        obj = MISPObject(name="mutex")

        classifications = classifications_to_str(self.classifications)
        attr = obj.add_attribute(
            "name",
            value=self.name,
            category="External analysis",
            to_ids=False,
            comment=classifications,
        )
        if tag and attr:
            self.tag_artifact_attribute(attr)

        operations = None
        if self.operations:
            operations = "Operations: " + ", ".join(self.operations)
        obj.add_attribute("description", value=operations, to_ids=False)

        return obj

    def merge(self, other: Artifact) -> None:
        if not isinstance(other, MutexArtifact):
            return

        self.operations = merge_lists(self.operations, other.operations)
        self.classifications = merge_lists(self.classifications, other.classifications)

    def __eq__(self, other: Artifact) -> bool:
        if not isinstance(other, MutexArtifact):
            return NotImplemented

        return self.name == other.name


@dataclass
class ProcessArtifact(Artifact):
    filename: str
    pid: Optional[int] = None
    parent_pid: Optional[int] = None
    cmd_line: Optional[str] = None
    operations: List[str] = field(default_factory=list)
    classifications: List[str] = field(default_factory=list)

    def to_attributes(self) -> Iterator[Attribute]:
        process_desc = f"Process created: {self.filename}\nPID: {self.pid}"
        classifications = classifications_to_str(self.classifications)
        yield Attribute(type="text", value=process_desc, comment=classifications)

    def to_misp_object(self, tag: bool) -> MISPObject:
        obj = MISPObject(name="process")

        if self.pid:
            obj.add_attribute("pid", value=self.pid, category="External analysis")

        if self.parent_pid:
            obj.add_attribute("parent-pid", value=self.parent_pid, category="External analysis")

        classifications = classifications_to_str(self.classifications)
        name_attr = obj.add_attribute("name", self.filename, category="External analysis", comment=classifications)

        cmd_attr = obj.add_attribute("command-line", value=self.cmd_line)

        if tag:
            if name_attr:
                self.tag_artifact_attribute(name_attr)
            if cmd_attr:
                self.tag_artifact_attribute(cmd_attr)

        return obj

    def merge(self, other: Artifact) -> None:
        if not isinstance(other, ProcessArtifact):
            return

        self.operations = merge_lists(self.operations, other.operations)
        self.classifications = merge_lists(self.classifications, other.classifications)

    def __eq__(self, other: Artifact) -> bool:
        if not isinstance(other, ProcessArtifact):
            return NotImplemented

        return self.filename == other.filename and self.cmd_line == other.cmd_line


@dataclass
class RegistryArtifact(Artifact):
    key: str
    operations: List[str]

    def to_attributes(self) -> Iterator[Attribute]:
        operations = ", ".join(self.operations)
        comment = f"Operations: {operations}"

        attr = Attribute(type="regkey", value=self.key, comment=comment)
        yield attr

    def to_misp_object(self, tag: bool) -> MISPObject:
        obj = MISPObject(name="registry-key")

        operations = None
        if self.operations:
            operations = "Operations: " + ", ".join(self.operations)

        attr = obj.add_attribute("key", value=self.key, to_ids=self.is_ioc, comment=operations)
        if tag and attr:
            self.tag_artifact_attribute(attr)

        return obj

    def merge(self, other: Artifact) -> None:
        if not isinstance(other, RegistryArtifact):
            return

        self.operations = merge_lists(self.operations, other.operations)

    def __eq__(self, other: Artifact) -> bool:
        if not isinstance(other, RegistryArtifact):
            return NotImplemented

        return self.key == other.key


@dataclass
class UrlArtifact(Artifact):
    url: str
    operations: List[str]
    domain: Optional[str] = None
    ips: List[str] = field(default_factory=list)

    def to_attributes(self) -> Iterator[Attribute]:
        operations = ", ".join(self.operations)
        comment = f"Operations: {operations}"

        attr = Attribute(type="url", value=self.url, comment=comment)
        yield attr

    def to_misp_object(self, tag: bool) -> MISPObject:
        obj = MISPObject(name="url")

        operations = None
        if self.operations:
            operations = "Operations: " + ", ".join(self.operations)

        attr = obj.add_attribute(
            "url",
            value=self.url,
            comment=operations,
            category="External analysis",
            to_ids=False,
        )
        if tag and attr:
            self.tag_artifact_attribute(attr)

        if self.domain:
            obj.add_attribute("domain", self.domain, category="External analysis", to_ids=False)

        for ip in self.ips:
            obj.add_attribute("ip", ip, category="External analysis", to_ids=False)

        return obj

    def merge(self, other: Artifact) -> None:
        if not isinstance(other, UrlArtifact):
            return

        self.ips = merge_lists(self.ips, other.ips)
        self.operations = merge_lists(self.operations, other.operations)

    def __eq__(self, other: Artifact) -> bool:
        if not isinstance(other, UrlArtifact):
            return NotImplemented

        return self.url == other.url and self.domain == other.domain


@dataclass
class MitreAttack:
    description: str
    id: str

    def to_misp_galaxy(self) -> str:
        return f'misp-galaxy:mitre-attack-pattern="{self.description} - {self.id}"'


@dataclass
class VTI:
    category: str
    operation: str
    technique: str
    score: int


class ReportVersion(Enum):
    v1 = "v1"
    v2 = "v2"


class VMRayParseError(Exception):
    pass


class ReportParser(ABC):
    @abstractmethod
    def __init__(self, api: VMRayRESTAPI, analysis_id: int):
        raise NotImplementedError()

    @abstractmethod
    def is_static_report(self) -> bool:
        raise NotImplementedError()

    @abstractmethod
    def artifacts(self) -> Iterator[Artifact]:
        raise NotImplementedError()

    @abstractmethod
    def classifications(self) -> Optional[str]:
        raise NotImplementedError()

    @abstractmethod
    def details(self) -> Iterator[str]:
        raise NotImplementedError()

    @abstractmethod
    def mitre_attacks(self) -> Iterator[MitreAttack]:
        raise NotImplementedError()

    @abstractmethod
    def sandbox_type(self) -> str:
        raise NotImplementedError()

    @abstractmethod
    def score(self) -> str:
        raise NotImplementedError()

    @abstractmethod
    def vtis(self) -> Iterator[VTI]:
        raise NotImplementedError()


class Summary(ReportParser):
    def __init__(self, analysis_id: int, api: VMRayRESTAPI = None, report: Dict[str, Any] = None):
        self.analysis_id = analysis_id

        if report:
            self.report = report
        else:
            data = api.call(
                "GET",
                f"/rest/analysis/{analysis_id}/archive/logs/summary.json",
                raw_data=True,
            )
            self.report = json.load(data)

    @staticmethod
    def to_verdict(score: Union[int, str]) -> Optional[str]:
        if isinstance(score, int):
            if 0 <= score <= 24:
                return "clean"
            if 25 <= score <= 74:
                return "suspicious"
            if 75 <= score <= 100:
                return "malicious"
            return "n/a"
        if isinstance(score, str):
            score = score.lower()
            if score in ("not_suspicious", "whitelisted"):
                return "clean"
            if score == "blacklisted":
                return "malicious"
            if score in ("not_available", "unknown"):
                return "n/a"
            return score
        return None

    def is_static_report(self) -> bool:
        return self.report["vti"]["vti_rule_type"] == "Static"

    def artifacts(self) -> Iterator[Artifact]:
        artifacts = self.report["artifacts"]
        domains = artifacts.get("domains", [])
        for domain in domains:
            classifications = domain.get("classifications", [])
            is_ioc = domain.get("ioc", False)
            verdict = self.to_verdict(domain.get("severity"))
            ips = domain.get("ip_addresses", [])
            artifact = DomainArtifact(
                domain=domain["domain"],
                sources=domain["sources"],
                ips=ips,
                classifications=classifications,
                is_ioc=is_ioc,
                verdict=verdict,
            )
            yield artifact

        emails = artifacts.get("emails", [])
        for email in emails:
            sender = email.get("sender")
            subject = email.get("subject")
            verdict = self.to_verdict(email.get("severity"))
            recipients = email.get("recipients", [])
            classifications = email.get("classifications", [])
            is_ioc = email.get("ioc", False)

            artifact = EmailArtifact(
                sender=sender,
                subject=subject,
                verdict=verdict,
                recipients=recipients,
                classifications=classifications,
                is_ioc=is_ioc,
            )
            yield artifact

        files = artifacts.get("files", [])
        for file_ in files:
            if file_["filename"] is None:
                continue

            filenames = [file_["filename"]]
            if "filenames" in file_:
                filenames += file_["filenames"]

            hashes = file_["hashes"]
            classifications = file_.get("classifications", [])
            operations = file_.get("operations", [])
            is_ioc = file_.get("ioc", False)
            mimetype = file_.get("mime_type")
            verdict = self.to_verdict(file_.get("severity"))

            for hash_dict in hashes:
                imp = hash_dict.get("imp_hash")

                artifact = FileArtifact(
                    filenames=filenames,
                    imphash=imp,
                    md5=hash_dict["md5_hash"],
                    ssdeep=hash_dict["ssdeep_hash"],
                    sha256=hash_dict["sha256_hash"],
                    sha1=hash_dict["sha1_hash"],
                    operations=operations,
                    classifications=classifications,
                    size=file_.get("file_size"),
                    is_ioc=is_ioc,
                    mimetype=mimetype,
                    verdict=verdict,
                )
                yield artifact

        ips = artifacts.get("ips", [])
        for ip in ips:
            is_ioc = ip.get("ioc", False)
            verdict = self.to_verdict(ip.get("severity"))
            classifications = ip.get("classifications", [])
            artifact = IpArtifact(
                ip=ip["ip_address"],
                sources=ip["sources"],
                classifications=classifications,
                verdict=verdict,
                is_ioc=is_ioc,
            )
            yield artifact

        mutexes = artifacts.get("mutexes", [])
        for mutex in mutexes:
            verdict = self.to_verdict(mutex.get("severity"))
            is_ioc = mutex.get("ioc", False)
            artifact = MutexArtifact(
                name=mutex["mutex_name"],
                operations=mutex["operations"],
                classifications=[],
                verdict=verdict,
                is_ioc=is_ioc,
            )
            yield artifact

        processes = artifacts.get("processes", [])
        for process in processes:
            classifications = process.get("classifications", [])
            cmd_line = process.get("cmd_line")
            name = process.get("image_name")
            verdict = self.to_verdict(process.get("severity"))
            is_ioc = process.get("ioc", False)

            artifact = ProcessArtifact(
                filename=name,
                classifications=classifications,
                cmd_line=cmd_line,
                verdict=verdict,
                is_ioc=is_ioc,
            )
            yield artifact

        registry = artifacts.get("registry", [])
        for reg in registry:
            is_ioc = reg.get("ioc", False)
            verdict = self.to_verdict(reg.get("severity"))
            artifact = RegistryArtifact(
                key=reg["reg_key_name"],
                operations=reg["operations"],
                verdict=verdict,
                is_ioc=is_ioc,
            )
            yield artifact

        urls = artifacts.get("urls", [])
        for url in urls:
            ips = url.get("ip_addresses", [])
            is_ioc = url.get("ioc", False)
            verdict = self.to_verdict(url.get("severity"))

            artifact = UrlArtifact(
                url=url["url"],
                operations=url.get("operations", []),
                ips=ips,
                is_ioc=is_ioc,
                verdict=verdict,
            )
            yield artifact

    def classifications(self) -> Optional[str]:
        classifications = self.report["classifications"]
        if classifications:
            str_classifications = ", ".join(classifications)
            return f"Classifications: {str_classifications}"
        return None

    def details(self) -> Iterator[str]:
        details = self.report["analysis_details"]
        execution_successful = details["execution_successful"]
        termination_reason = details["termination_reason"]
        result = details["result_str"]

        if self.analysis_id == 0:
            analysis = ""
        else:
            analysis = f" {self.analysis_id}"

        yield f"Analysis{analysis}: execution_successful: {execution_successful}"
        yield f"Analysis{analysis}: termination_reason: {termination_reason}"
        yield f"Analysis{analysis}: result: {result}"

    def mitre_attacks(self) -> Iterator[MitreAttack]:
        mitre_attack = self.report["mitre_attack"]
        techniques = mitre_attack.get("techniques", [])

        for technique in techniques:
            mitre_attack = MitreAttack(description=technique["description"], id=technique["id"])
            yield mitre_attack

    def sandbox_type(self) -> str:
        vm_name = self.report["vm_and_analyzer_details"]["vm_name"]
        sample_type = self.report["sample_details"]["sample_type"]
        return f"{vm_name} | {sample_type}"

    def score(self) -> str:
        vti_score = self.report["vti"]["vti_score"]
        return self.to_verdict(vti_score)

    def vtis(self) -> Iterator[VTI]:
        try:
            vtis = self.report["vti"]["vti_rule_matches"]
        except KeyError:
            vtis = []

        for vti in vtis:
            new_vti = VTI(
                category=vti["category_desc"],
                operation=vti["operation_desc"],
                technique=vti["technique_desc"],
                score=vti["rule_score"],
            )

            yield new_vti


class SummaryV2(ReportParser):
    def __init__(self, analysis_id: int, api: VMRayRESTAPI = None, report: Dict[str, Any] = None):
        self.analysis_id = analysis_id

        if report:
            self.report = report
        else:
            self.api = api
            data = api.call(
                "GET",
                f"/rest/analysis/{analysis_id}/archive/logs/summary_v2.json",
                raw_data=True,
            )
            self.report = json.load(data)

    def _resolve_refs(self, data: Union[List[Dict[str, Any]], Dict[str, Any]]) -> Iterator[Dict[str, Any]]:
        if not data:
            return []

        if isinstance(data, dict):
            data = [data]

        for ref in data:
            yield self._resolve_ref(ref)

    def _resolve_ref(self, data: Dict[str, Any]) -> Dict[str, Any]:
        if data == {}:
            return {}

        if data["_type"] != "reference" or data["source"] != "logs/summary_v2.json":
            return {}

        resolved_ref = self.report
        paths = data["path"]
        for path_part in paths:
            try:
                resolved_ref = resolved_ref[path_part]
            except KeyError:
                return {}

        return resolved_ref

    @staticmethod
    def convert_verdict(verdict: Optional[str]) -> str:
        if verdict == "not_available" or not verdict:
            return "n/a"

        return verdict

    def is_static_report(self) -> bool:
        return self.report["vti"]["score_type"] == "static"

    def artifacts(self) -> Iterator[Artifact]:
        artifacts = self.report["artifacts"]

        ref_domains = artifacts.get("ref_domains", [])
        for domain in self._resolve_refs(ref_domains):
            classifications = domain.get("classifications", [])
            artifact = DomainArtifact(
                domain=domain["domain"],
                sources=domain["sources"],
                classifications=classifications,
                is_ioc=domain["is_ioc"],
                verdict=domain["verdict"],
            )

            ref_ip_addresses = domain.get("ref_ip_addresses", [])
            if not ref_ip_addresses:
                continue

            for ip_address in self._resolve_refs(ref_ip_addresses):
                ip = ip_address.get("ip_address")
                if ip is not None:
                    artifact.ips.append(ip)

            yield artifact

        ref_emails = artifacts.get("ref_emails", [])
        for email in self._resolve_refs(ref_emails):
            sender = email.get("sender")
            subject = email.get("subject")
            recipients = email.get("recipients", [])
            verdict = email["verdict"]
            is_ioc = email["is_ioc"]
            classifications = email.get("classifications", [])

            artifact = EmailArtifact(
                sender=sender,
                subject=subject,
                recipients=recipients,
                classifications=classifications,
                verdict=verdict,
                is_ioc=is_ioc,
            )

            yield artifact

        ref_files = artifacts.get("ref_files", [])
        for file_ in self._resolve_refs(ref_files):
            filenames = []

            if "ref_filenames" in file_:
                for filename in self._resolve_refs(file_["ref_filenames"]):
                    if not filename:
                        continue
                    filenames.append(filename["filename"])

            artifact = FileArtifact(
                operations=file_.get("operations", []),
                md5=file_["hash_values"]["md5"],
                sha1=file_["hash_values"]["sha1"],
                sha256=file_["hash_values"]["sha256"],
                ssdeep=file_["hash_values"]["ssdeep"],
                imphash=None,
                mimetype=file_.get("mime_type"),
                filenames=filenames,
                is_ioc=file_["is_ioc"],
                classifications=file_.get("classifications", []),
                size=file_["size"],
                verdict=file_["verdict"],
            )
            yield artifact

        ref_ip_addresses = artifacts.get("ref_ip_addresses", [])
        for ip in self._resolve_refs(ref_ip_addresses):
            classifications = ip.get("classifications", [])
            verdict = ip["verdict"]
            is_ioc = ip["is_ioc"]
            artifact = IpArtifact(
                ip=ip["ip_address"],
                sources=ip["sources"],
                classifications=classifications,
                verdict=verdict,
                is_ioc=is_ioc,
            )
            yield artifact

        ref_mutexes = artifacts.get("ref_mutexes", [])
        for mutex in self._resolve_refs(ref_mutexes):
            is_ioc = mutex["is_ioc"]
            classifications = mutex.get("classifications", [])
            artifact = MutexArtifact(
                name=mutex["name"],
                operations=mutex["operations"],
                verdict=mutex["verdict"],
                classifications=classifications,
                is_ioc=is_ioc,
            )
            yield artifact

        ref_processes = artifacts.get("ref_processes", [])
        for process in self._resolve_refs(ref_processes):
            cmd_line = process.get("cmd_line")
            classifications = process.get("classifications", [])
            verdict = process.get("verdict")
            artifact = ProcessArtifact(
                pid=process["os_pid"],
                parent_pid=process["origin_monitor_id"],
                filename=process.get("filename"),
                is_ioc=process["is_ioc"],
                cmd_line=cmd_line,
                classifications=classifications,
                verdict=verdict,
            )
            yield artifact

        ref_registry_records = artifacts.get("ref_registry_records", [])
        for reg in self._resolve_refs(ref_registry_records):
            artifact = RegistryArtifact(
                key=reg["reg_key_name"],
                operations=reg["operations"],
                is_ioc=reg["is_ioc"],
                verdict=reg["verdict"],
            )
            yield artifact

        url_refs = artifacts.get("ref_urls", [])
        for url in self._resolve_refs(url_refs):
            domain = None
            ref_domain = url.get("ref_domain", {})
            if ref_domain and self._resolve_ref(ref_domain).get("domain") is not None:
                domain = self._resolve_ref(ref_domain)["domain"]

            ips = []
            ref_ip_addresses = url.get("ref_ip_addresses", [])
            for ip_address in self._resolve_refs(ref_ip_addresses):
                ip = ip_address.get("ip_address")
                if ip is not None:
                    ips.append(ip)

            artifact = UrlArtifact(
                url=url["url"],
                operations=url.get("operations", []),
                is_ioc=url["is_ioc"],
                domain=domain,
                ips=ips,
                verdict=url["verdict"],
            )
            yield artifact

    def classifications(self) -> Optional[str]:
        try:
            classifications = ", ".join(self.report["classifications"])
            return f"Classifications: {classifications}"
        except KeyError:
            return None

    def details(self) -> Iterator[str]:
        details = self.report["analysis_metadata"]
        is_execution_successful = details["is_execution_successful"]
        termination_reason = details["termination_reason"]
        result = details["result_str"]

        yield f"Analysis {self.analysis_id}: execution_successful: {is_execution_successful}"
        yield f"Analysis {self.analysis_id}: termination_reason: {termination_reason}"
        yield f"Analysis {self.analysis_id}: result: {result}"

    def mitre_attacks(self) -> Iterator[MitreAttack]:
        mitre_attack = self.report["mitre_attack"]
        techniques = mitre_attack["v4"]["techniques"]

        for technique_id, technique in techniques.items():
            mitre_attack = MitreAttack(
                description=technique["description"],
                id=technique_id.replace("technique_", ""),
            )
            yield mitre_attack

    def sandbox_type(self) -> str:
        vm_information = self.report["virtual_machine"]["description"]
        sample_type = self.report["analysis_metadata"]["sample_type"]
        return f"{vm_information} | {sample_type}"

    def score(self) -> str:
        verdict = self.report["analysis_metadata"]["verdict"]
        return self.convert_verdict(verdict)

    def vtis(self) -> Iterator[VTI]:
        if "matches" not in self.report["vti"]:
            return

        vti_matches = self.report["vti"]["matches"]
        for vti in vti_matches.values():
            new_vti = VTI(
                category=vti["category_desc"],
                operation=vti["operation_desc"],
                technique=vti["technique_desc"],
                score=vti["analysis_score"],
            )

            yield new_vti


class VMRayParser:
    def __init__(self) -> None:
        # required for api import
        self.api: Optional[VMRayRESTAPI] = None
        self.sample_id: Optional[int] = None

        # required for file import
        self.report: Optional[Dict[str, Any]] = None
        self.report_name: Optional[str] = None
        self.include_report = False

        # required by API import and file import
        self.report_version = ReportVersion.v2

        self.use_misp_object = True
        self.ignore_analysis_finished = False
        self.tag_objects = True

        self.include_analysis_id = True
        self.include_vti_details = True
        self.include_iocs = True
        self.include_all_artifacts = False
        self.include_analysis_details = True

        # a new event if we use misp objects
        self.event = MISPEvent()

        # new attributes if we don't use misp objects
        self.attributes: List[Attribute] = []

    def from_api(self, config: Dict[str, Any]) -> None:
        url = self._read_config_key(config, "url")
        api_key = self._read_config_key(config, "apikey")

        try:
            self.sample_id = int(self._read_config_key(config, "Sample ID"))
        except ValueError:
            raise VMRayParseError("Could not convert sample id to integer.")

        self.api = VMRayRESTAPI(url, api_key, False)

        self.ignore_analysis_finished = self._config_from_string(config.get("ignore_analysis_finished"))
        self._setup_optional_config(config)
        self.report_version = self._get_report_version()

    def from_base64_string(self, config: Dict[str, Any], data: str, filename: str) -> None:
        """read base64 encoded summary json"""

        buffer = base64.b64decode(data)
        self.report = json.loads(buffer)
        self.report_name = filename

        if "analysis_details" in self.report:
            self.report_version = ReportVersion.v1
        elif "analysis_metadata" in self.report:
            self.report_version = ReportVersion.v2
        else:
            raise VMRayParseError("Uploaded file is not a summary.json")

        self._setup_optional_config(config)
        self.include_report = bool(int(config.get("Attach Report", "0")))

    def _setup_optional_config(self, config: Dict[str, Any]) -> None:
        self.include_analysis_id = bool(int(config.get("Analysis ID", "1")))
        self.include_vti_details = bool(int(config.get("VTI", "1")))
        self.include_iocs = bool(int(config.get("IOCs", "1")))
        self.include_all_artifacts = bool(int(config.get("Artifacts", "0")))
        self.include_analysis_details = bool(int(config.get("Analysis Details", "1")))

        self.use_misp_object = not self._config_from_string(config.get("disable_misp_objects"))
        self.tag_objects = not self._config_from_string(config.get("disable_tags"))

    @staticmethod
    def _config_from_string(text: Optional[str]) -> bool:
        if not text:
            return False

        text = text.lower()
        return text in ("yes", "true")

    @staticmethod
    def _read_config_key(config: Dict[str, Any], key: str) -> str:
        try:
            value = config[key]
            return value
        except KeyError:
            raise VMRayParseError(f"VMRay config is missing a value for `{key}`.")

    @staticmethod
    def _analysis_score_to_taxonomies(analysis_score: int) -> Optional[str]:
        mapping = {
            -1: "-1",
            1: "1/5",
            2: "2/5",
            3: "3/5",
            4: "4/5",
            5: "5/5",
        }

        try:
            return mapping[analysis_score]
        except KeyError:
            return None

    def _get_report_version(self) -> ReportVersion:
        info = self._vmary_api_call("/rest/system_info")
        if info["version_major"] >= 4:
            return ReportVersion.v2

        # version 3.2 an less do not tag artifacts as ICOs
        # so we extract all artifacts
        if info["version_major"] == 3 and info["version_minor"] < 3:
            self.include_all_artifacts = True
        return ReportVersion.v1

    def _vmary_api_call(
        self, api_path: str, params: Dict[str, Any] = None, raw_data: bool = False
    ) -> Union[Dict[str, Any], bytes]:
        try:
            return self.api.call("GET", api_path, params=params, raw_data=raw_data)
        except (VMRayRESTAPIError, ValueError) as exc:
            raise VMRayParseError(str(exc))

    def _get_analysis(self) -> Dict[str, Any]:
        return self._vmary_api_call(f"/rest/analysis/sample/{self.sample_id}")

    def _analysis_finished(self) -> bool:
        result = self._vmary_api_call(f"/rest/submission/sample/{self.sample_id}")

        all_finished = []
        for submission in result:
            finished = submission["submission_finished"]
            all_finished.append(finished)

        return all(all_finished)

    def _online_reports(self) -> Iterator[Tuple[ReportParser, str]]:
        # check if sample id exists
        try:
            self._vmary_api_call(f"/rest/sample/{self.sample_id}")
        except VMRayRESTAPIError:
            raise VMRayParseError(f"Could not find sample id `{self.sample_id}` on server.")

        # check if all submission are finished
        if not self.ignore_analysis_finished and not self._analysis_finished():
            raise VMRayParseError(
                f"Not all analysis for `{self.sample_id}` are finished. Try it again in a few minutes."
            )

        analysis_results = self._get_analysis()
        for analysis in analysis_results:
            analysis_id = analysis["analysis_id"]
            permalink = analysis["analysis_webif_url"]

            # the summary json could not exist, due to a VM error
            try:
                if self.report_version == ReportVersion.v1:
                    report_parser = Summary(api=self.api, analysis_id=analysis_id)
                else:
                    report_parser = SummaryV2(api=self.api, analysis_id=analysis_id)
            except VMRayRESTAPIError:
                continue

            yield report_parser, permalink

    def _offline_report(self) -> ReportParser:
        if self.report_version == ReportVersion.v1:
            analysis_id = 0
            return Summary(report=self.report, analysis_id=analysis_id)
        else:
            analysis_id = self.report["analysis_metadata"]["analysis_id"]
            return SummaryV2(report=self.report, analysis_id=analysis_id)

    def _reports(self) -> Iterator[Tuple[ReportParser, Optional[str]]]:
        if self.report:
            yield self._offline_report(), None
        else:
            yield from self._online_reports()

    def _get_sample_verdict(self) -> Optional[str]:
        if self.report:
            if self.report_version == ReportVersion.v2:
                verdict = SummaryV2.convert_verdict(self.report["analysis_metadata"]["verdict"])
                return verdict
            return None

        data = self._vmary_api_call(f"/rest/sample/{self.sample_id}")
        if "sample_verdict" in data:
            verdict = SummaryV2.convert_verdict(data["sample_verdict"])
            return verdict

        if "sample_severity" in data:
            verdict = Summary.to_verdict(data["sample_severity"])
            return verdict

        return None

    def parse(self) -> None:
        """Convert analysis results to MISP Objects"""

        if self.use_misp_object:
            self.parse_as_misp_object()
        else:
            self.parse_as_attributes()

    def parse_as_attributes(self) -> None:
        """
        Parse report as attributes
        This method is compatible with the implementation provided
        by Koen Van Impe
        """

        for report, permalink in self._reports():
            if report.is_static_report():
                continue

            if self.include_analysis_details:
                for detail in report.details():
                    attr = Attribute(type="text", value=detail)
                    self.attributes.append(attr)

            classifications = report.classifications()
            if classifications:
                attr = Attribute(type="text", value=classifications)
                self.attributes.append(attr)

            if self.include_vti_details:
                for vti in report.vtis():
                    attr = Attribute(type="text", value=vti.operation)
                    self.attributes.append(attr)

            for artifact in report.artifacts():
                if self.include_all_artifacts or (self.include_iocs and artifact.is_ioc):
                    for attr in artifact.to_attributes():
                        self.attributes.append(attr)

            if self.include_analysis_id and permalink:
                attr = Attribute(type="link", value=permalink)
                self.attributes.append(attr)

    def parse_as_misp_object(self):
        mitre_attacks = []
        vtis = []
        artifacts = []

        # add sandbox signature
        sb_sig = MISPObject(name="sb-signature")
        sb_sig.add_attribute("software", "VMRay Platform")

        for report, permalink in self._reports():
            if report.is_static_report():
                continue

            # create sandbox object
            obj = MISPObject(name="sandbox-report")
            obj.add_attribute("on-premise-sandbox", "vmray")

            if permalink:
                obj.add_attribute("permalink", permalink)

            if self.include_report and self.report:
                report_data = base64.b64encode(json.dumps(self.report, indent=2).encode("utf-8")).decode("utf-8")
                obj.add_attribute("sandbox-file", value=self.report_name, data=report_data)

            score = report.score()
            attr_score = obj.add_attribute("score", score)

            if self.tag_objects:
                attr_score.add_tag(f'vmray:verdict="{score}"')

            sandbox_type = report.sandbox_type()
            obj.add_attribute("sandbox-type", sandbox_type)

            classifications = report.classifications()
            if classifications:
                obj.add_attribute("results", classifications)

            self.event.add_object(obj)

            if self.include_vti_details:
                for vti in report.vtis():
                    if vti not in vtis:
                        vtis.append(vti)

            for artifact in report.artifacts():
                if self.include_all_artifacts or (self.include_iocs and artifact.is_ioc):
                    if artifact not in artifacts:
                        artifacts.append(artifact)
                    else:
                        idx = artifacts.index(artifact)
                        dup = artifacts[idx]
                        dup.merge(artifact)

            for mitre_attack in report.mitre_attacks():
                if mitre_attack not in mitre_attacks:
                    mitre_attacks.append(mitre_attack)

        # process VTI's
        for vti in vtis:
            vti_text = f"{vti.category}: {vti.operation}. {vti.technique}"
            vti_attr = sb_sig.add_attribute("signature", value=vti_text)

            if self.tag_objects:
                value = self._analysis_score_to_taxonomies(vti.score)
                if value:
                    vti_attr.add_tag(f'vmray:vti_analysis_score="{value}"')

        self.event.add_object(sb_sig)

        # process artifacts
        for artifact in artifacts:
            artifact_obj = artifact.to_misp_object(self.tag_objects)
            self.event.add_object(artifact_obj)

        # tag event with Mitre Att&ck
        for mitre_attack in mitre_attacks:
            self.event.add_tag(mitre_attack.to_misp_galaxy())

        # tag event
        if self.tag_objects:
            verdict = self._get_sample_verdict()
            if verdict:
                self.event.add_tag(f'vmray:verdict="{verdict}"')

    def to_json(self) -> Dict[str, Any]:
        """Convert parsed results into JSON"""

        if not self.use_misp_object:
            results = []

            # remove duplicates
            for attribute in self.attributes:
                if attribute not in results:
                    results.append(asdict(attribute))

            # add attributes to event
            for attribute in results:
                self.event.add_attribute(**attribute)

        self.event.run_expansions()
        event = json.loads(self.event.to_json())

        return {"results": event}
