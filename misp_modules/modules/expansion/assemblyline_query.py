# -*- coding: utf-8 -*-
import json
from collections import defaultdict

from assemblyline_client import Client, ClientError
from pymisp import MISPAttribute, MISPEvent, MISPObject

from . import check_input_attribute, standard_error_message

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
    "requirements": ["assemblyline_client: Python library to query the AssemblyLine rest API."],
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
        sid = attribute["value"].split("=")[-1]
        try:
            if not client.submission.is_completed(sid):
                self.results["error"] = "Submission not completed, please try again later."
                return
        except Exception as e:
            self.results["error"] = (
                "Something went wrong while trying to check if the submission in AssemblyLine is completed:"
                f" {e.__str__()}"
            )
            return
        try:
            submission = client.submission.full(sid)
        except Exception as e:
            self.results["error"] = (
                f"Something went wrong while getting the submission from AssemblyLine: {e.__str__()}"
            )
            return
        self._parse_report(submission)

    def finalize_results(self):
        if "error" in self.results:
            return self.results
        event = json.loads(self.misp_event.to_json())
        results = {key: event[key] for key in ("Attribute", "Object", "Tag") if (key in event and event[key])}
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
                attribute.update(tag)
                file_object.add_attribute(value=file_info[feature], **attribute)
            return filename_attribute, file_object
        for feature, attribute in self._file_mapping.items():
            file_object.add_attribute(value=file_info[feature], **attribute)
        return filename_attribute, file_object

    @staticmethod
    def _get_results(submission_results):
        results = defaultdict(list)
        for k, values in submission_results.items():
            h = k.split(".")[0]
            for t in values["result"]["tags"]:
                if t["context"] is not None:
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
        if submission["classification"] != "UNCLASSIFIED":
            self.misp_event.add_tag(submission["classification"].lower())
        filtered_results = self._get_results(submission["results"])
        scores = self._get_scores(submission["file_tree"])
        for h, results in filtered_results.items():
            if h in scores:
                attribute, file_object = self._create_file_object(submission["file_infos"][h])
                print(file_object)
                for filename in scores[h]["name"]:
                    file_object.add_attribute("filename", value=filename, **attribute)
                for reference in self._parse_results(results):
                    file_object.add_reference(**reference)
                self.misp_event.add_object(**file_object)

    def _parse_results(self, results):
        references = []
        for result in results:
            try:
                attribute_type = self._results_mapping[result["type"]]
            except KeyError:
                continue
            references.append(self._create_attribute(result, attribute_type))
        return references


def parse_config(apiurl, user_id, config):
    error = {"error": "Please provide your AssemblyLine API key or Password."}
    if config.get("apikey"):
        try:
            return Client(apiurl, apikey=(user_id, config["apikey"]), verify=config["verifyssl"])
        except ClientError as e:
            error["error"] = f"Error while initiating a connection with AssemblyLine: {e.__str__()}"
    if config.get("password"):
        try:
            return Client(apiurl, auth=(user_id, config["password"]))
        except ClientError as e:
            error["error"] = f"Error while initiating a connection with AssemblyLine: {e.__str__()}"
    return error


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
