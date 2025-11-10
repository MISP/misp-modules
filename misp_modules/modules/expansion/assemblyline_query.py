# -*- coding: utf-8 -*-
import json
from collections import defaultdict
from urllib.parse import urlparse

from pymisp import MISPAttribute, MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message
from ._assemblyline_api import AssemblyLineAPI, AssemblyLineError

misperrors = {"error": "Error"}
mispattributes = {"input": ["link"], "format": "misp_standard"}

moduleinfo = {
    "version": "1",
    "author": "Christian Studer",
    "description": (
        "A module tu query the AssemblyLine API with a submission ID to get the submission report and parse it."
    ),
    "module-type": ["expansion"],
    "name": "AssemblyLine Query",
    "logo": "assemblyline.png",
    "requirements": [],
    "features": (
        "The module requires the address of the AssemblyLine server you want to query as well as your credentials used"
        " for this instance. Credentials include the used-ID and an API key or the password associated to the"
        " user-ID.\n\nThe submission ID extracted from the submission link is then used to query AssemblyLine and get"
        " the full submission report. This report is parsed to extract file objects and the associated IPs, domains or"
        " URLs the files are connecting to.\n\nSome more data may be parsed in the future."
    ),
    "references": ["https://www.cyber.gc.ca/en/assemblyline"],
    "input": "Link of an AssemblyLine submission report.",
    "output": "MISP attributes & objects parsed from the AssemblyLine submission.",
}
moduleconfig = ["apiurl", "user_id", "apikey", "password", "verifyssl"]


class AssemblyLineParser:
    def __init__(self):
        self.misp_event = MISPEvent()
        self.results = {}
        self.attribute = {"to_ids": True}
        self._results_mapping = {
            "NET_DOMAIN_NAME": "domain",
            "NET_FULL_URI": "url",
            "NET_IP": "ip-dst",
        }
        self._file_mapping = {
            "entropy": {"type": "float", "object_relation": "entropy"},
            "md5": {"type": "md5", "object_relation": "md5"},
            "mime": {"type": "mime-type", "object_relation": "mimetype"},
            "sha1": {"type": "sha1", "object_relation": "sha1"},
            "sha256": {"type": "sha256", "object_relation": "sha256"},
            "size": {"type": "size-in-bytes", "object_relation": "size-in-bytes"},
            "ssdeep": {"type": "ssdeep", "object_relation": "ssdeep"},
        }

    def get_submission(self, attribute, client):
        value = attribute.get("value", "")
        sid = _extract_submission_id(value)
        if not sid:
            self.results["error"] = (
                "Unable to extract a submission identifier from the provided attribute. "
                "Expected a link such as /submission/detail/<sid> or a URL containing sid=<sid>."
            )
            return
        try:
            is_completed = client.get_json(f"/api/v4/submission/is_completed/{sid}/")
        except AssemblyLineError as e:
            self.results["error"] = (
                "Something went wrong while trying to check if the submission in AssemblyLine is completed:"
                f" {e}"
            )
            return
        if isinstance(is_completed, dict):
            completed = is_completed.get("completed")
        else:
            completed = bool(is_completed)
        if not completed:
            self.results["error"] = "Submission not completed on AssemblyLine yet, please retry later."
            return
        try:
            submission = client.get_json(f"/api/v4/submission/full/{sid}/")
        except AssemblyLineError as e:
            self.results["error"] = f"Something went wrong while getting the submission from AssemblyLine: {e}"
            return
        self._parse_report(submission)

    def finalize_results(self):
        if "error" in self.results:
            return self.results
        event = json.loads(self.misp_event.to_json())
        try:
            with open("/tmp/assemblyline_query_debug.json", "w", encoding="utf-8") as debug_file:
                json.dump(event, debug_file, indent=2)
        except Exception:
            pass
        results = {key: event[key] for key in ("Attribute", "Object", "Tag") if (key in event and event[key])}
        if not results:
            return {
                "error": "AssemblyLine query completed but no enrichment data was returned.",
            }
        return {"results": results}

    def _create_attribute(self, result, attribute_type):
        attribute = MISPAttribute()
        attribute.from_dict(type=attribute_type, value=result["value"], **self.attribute)
        if result["classification"] != "UNCLASSIFIED":
            attribute.add_tag(result["classification"].lower())
        self.misp_event.add_attribute(**attribute)
        return {
            "referenced_uuid": attribute.uuid,
            "relationship_type": "-".join(result["context"].lower().split(" ")),
        }

    def _create_file_object(self, file_info):
        file_object = MISPObject("file")
        filename_attribute = {"type": "filename"}
        filename_attribute.update(self.attribute)
        if file_info["classification"] != "UNCLASSIFIED":
            tag = {"Tag": [{"name": file_info["classification"].lower()}]}
            filename_attribute.update(tag)
            for feature, attribute in self._file_mapping.items():
                attribute_payload = attribute.copy()
                attribute_payload.update(tag)
                file_object.add_attribute(value=file_info[feature], **attribute_payload)
            return filename_attribute, file_object
        for feature, attribute in self._file_mapping.items():
            if feature not in file_info:
                continue
            attribute_payload = attribute.copy()
            file_object.add_attribute(value=file_info[feature], **attribute_payload)
        return filename_attribute, file_object

    @staticmethod
    def _get_results(submission_results):
        results = defaultdict(list)
        for k, values in submission_results.items():
            h = k.split(".")[0]
            tags = values.get("result", {}).get("tags") if isinstance(values, dict) else None
            if not tags or not isinstance(tags, list):
                continue
            for t in tags:
                context = t.get("context") if isinstance(t, dict) else None
                if context:
                    results[h].append(t)
        return results

    def _get_scores(self, file_tree):
        scores = {}
        for h, f in file_tree.items():
            score = f["score"]
            if score > 0:
                scores[h] = {"name": f["name"], "score": score}
            if f["children"]:
                scores.update(self._get_scores(f["children"]))
        return scores

    def _parse_report(self, submission):
        if submission.get("classification") and submission["classification"] != "UNCLASSIFIED":
            self.misp_event.add_tag(submission["classification"].lower())
        filtered_results = self._get_results(submission.get("results", {}))
        scores = self._get_scores(submission.get("file_tree", {}))
        file_infos = submission.get("file_infos", {})
        for file_hash, file_info in file_infos.items():
            filename_attribute, file_object = self._create_file_object(file_info)
            filenames = scores.get(file_hash, {}).get("name", [])
            if isinstance(filenames, str):
                filenames = [filenames]
            for filename in filenames:
                file_object.add_attribute("filename", value=filename, **filename_attribute)
            for reference in self._parse_results(filtered_results.get(file_hash, [])):
                file_object.add_reference(**reference)
            if file_object.attributes:
                self.misp_event.add_object(**file_object)

    def _parse_results(self, results):
        references = []
        for result in results:
            if not isinstance(result, dict):
                continue
            attribute_type = self._results_mapping.get(result.get("type"))
            if not attribute_type or "value" not in result:
                continue
            references.append(self._create_attribute(result, attribute_type))
        return references


def parse_config(apiurl, user_id, config):
    verify = _coerce_verify_flag(config.get("verifyssl"), default=True)
    api_key = config.get("apikey")
    password = config.get("password")
    errors = []
    if api_key:
        client = AssemblyLineAPI(apiurl, verify=verify)
        try:
            client.authenticate(user=user_id, apikey=api_key)
            return client
        except AssemblyLineError as e:
            errors.append(f"API key authentication failed: {e}")
    if password:
        client = AssemblyLineAPI(apiurl, verify=verify)
        try:
            client.authenticate(user=user_id, password=password)
            return client
        except AssemblyLineError as e:
            errors.append(f"Password authentication failed: {e}")
    if errors:
        return {"error": " ".join(errors)}
    return {"error": "Please provide your AssemblyLine API key or Password."}


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get("attribute") or not check_input_attribute(request["attribute"]):
        return {"error": f"{standard_error_message}, which should contain at least a type, a value and an uuid."}
    if request["attribute"]["type"] not in mispattributes["input"]:
        return {"error": "Unsupported attribute type."}
    if not request.get("config"):
        return {"error": "Missing configuration."}
    if not request["config"].get("apiurl"):
        return {"error": "No AssemblyLine server address provided."}
    apiurl = request["config"]["apiurl"]
    if not request["config"].get("user_id"):
        return {"error": "Please provide your AssemblyLine User ID."}
    user_id = request["config"]["user_id"]
    client = parse_config(apiurl, user_id, request["config"])
    if isinstance(client, dict):
        return client
    assemblyline_parser = AssemblyLineParser()
    assemblyline_parser.get_submission(request["attribute"], client)
    return assemblyline_parser.finalize_results()


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo


def _extract_submission_id(value):
    if not value:
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    parsed = urlparse(cleaned)
    if parsed.path:
        segments = [segment for segment in parsed.path.split("/") if segment]
        if len(segments) >= 3 and segments[-3:-1] == ["submission", "detail"]:
            return segments[-1]
    if "sid=" in cleaned:
        return cleaned.split("sid=")[-1].split("&")[0]
    if parsed.path and "/" not in parsed.path.strip("/") and parsed.path.strip("/"):
        return parsed.path.strip("/")
    if "/" not in cleaned and " " not in cleaned:
        return cleaned
    return None


def _coerce_verify_flag(value, default=True):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        normalised = value.strip().lower()
        if normalised in {"true", "1", "yes", "on"}:
            return True
        if normalised in {"false", "0", "no", "off"}:
            return False
    return default
