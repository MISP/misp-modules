# -*- coding: utf-8 -*-
import json
from collections import defaultdict
from datetime import datetime

from joe_mapping import (
    arch_type_mapping,
    domain_object_mapping,
    dropped_file_mapping,
    dropped_hash_mapping,
    elf_object_mapping,
    elf_section_flags_mapping,
    file_object_fields,
    file_object_mapping,
    file_references_mapping,
    network_behavior_fields,
    network_connection_object_mapping,
    pe_object_fields,
    pe_object_mapping,
    pe_section_object_mapping,
    process_object_fields,
    protocols,
    registry_references_mapping,
    regkey_object_mapping,
    signerinfo_object_mapping,
)
from pymisp import MISPAttribute, MISPEvent, MISPObject


class JoeParser:
    def __init__(self, config):
        self.misp_event = MISPEvent()
        self.references = defaultdict(list)
        self.attributes = defaultdict(lambda: defaultdict(set))
        self.process_references = {}

        self.import_executable = config["import_executable"]
        self.create_mitre_attack = config["mitre_attack"]

    def parse_data(self, data):
        self.data = data
        if self.analysis_type() == "file":
            self.parse_fileinfo()
        else:
            self.parse_url_analysis()

        self.parse_system_behavior()
        self.parse_network_behavior()
        self.parse_screenshot()
        self.parse_network_interactions()
        self.parse_dropped_files()

        if self.attributes:
            self.handle_attributes()

        if self.create_mitre_attack:
            self.parse_mitre_attack()

    def build_references(self):
        for misp_object in self.misp_event.objects:
            object_uuid = misp_object.uuid
            if object_uuid in self.references:
                for reference in self.references[object_uuid]:
                    misp_object.add_reference(**reference)

    def handle_attributes(self):
        for attribute_type, attribute in self.attributes.items():
            for attribute_value, references in attribute.items():
                attribute_uuid = self.create_attribute(attribute_type, attribute_value)
                for reference in references:
                    source_uuid, relationship = reference
                    self.references[source_uuid].append(
                        dict(
                            referenced_uuid=attribute_uuid,
                            relationship_type=relationship,
                        )
                    )

    def parse_dropped_files(self):
        droppedinfo = self.data["droppedinfo"]
        if droppedinfo:
            for droppedfile in droppedinfo["hash"]:
                file_object = MISPObject("file")
                for key, mapping in dropped_file_mapping.items():
                    if droppedfile.get(key) is not None:
                        attribute = {"value": droppedfile[key], "to_ids": False}
                        attribute.update(mapping)
                        file_object.add_attribute(**attribute)
                if droppedfile["@malicious"] == "true":
                    file_object.add_attribute(
                        **{
                            "type": "text",
                            "object_relation": "state",
                            "value": "Malicious",
                            "to_ids": False,
                        }
                    )
                for h in droppedfile["value"]:
                    hash_type = dropped_hash_mapping[h["@algo"]]
                    file_object.add_attribute(
                        **{
                            "type": hash_type,
                            "object_relation": hash_type,
                            "value": h["$"],
                            "to_ids": False,
                        }
                    )
                self.misp_event.add_object(file_object)
                reference_key = (int(droppedfile["@targetid"]), droppedfile["@process"])
                if reference_key in self.process_references:
                    self.references[self.process_references[reference_key]].append(
                        {
                            "referenced_uuid": file_object.uuid,
                            "relationship_type": "drops",
                        }
                    )

    def parse_mitre_attack(self):
        mitreattack = self.data.get("mitreattack", {})
        if mitreattack:
            for tactic in mitreattack["tactic"]:
                if tactic.get("technique"):
                    for technique in tactic["technique"]:
                        self.misp_event.add_tag(
                            f'misp-galaxy:mitre-attack-pattern="{technique["name"]} - {technique["id"]}"'
                        )

    def parse_network_behavior(self):
        network = self.data["behavior"]["network"]
        connections = defaultdict(lambda: defaultdict(set))
        for protocol, layer in protocols.items():
            if network.get(protocol):
                for packet in network[protocol]["packet"]:
                    timestamp = datetime.strptime(
                        self.parse_timestamp(packet["timestamp"]),
                        "%b %d, %Y %H:%M:%S.%f",
                    )
                    connections[tuple(packet.get(field) for field in network_behavior_fields)][protocol].add(timestamp)
        for connection, data in connections.items():
            attributes = self.prefetch_attributes_data(connection)
            if len(data.keys()) == len(set(protocols[protocol] for protocol in data.keys())):
                network_connection_object = MISPObject("network-connection")
                for attribute in attributes:
                    network_connection_object.add_attribute(**attribute)
                network_connection_object.add_attribute(
                    **{
                        "type": "datetime",
                        "object_relation": "first-packet-seen",
                        "value": min(tuple(min(timestamp) for timestamp in data.values())),
                        "to_ids": False,
                    }
                )
                for protocol in data.keys():
                    network_connection_object.add_attribute(
                        **{
                            "type": "text",
                            "object_relation": f"layer{protocols[protocol]}-protocol",
                            "value": protocol,
                            "to_ids": False,
                        }
                    )
                self.misp_event.add_object(network_connection_object)
                self.references[self.analysisinfo_uuid].append(
                    dict(
                        referenced_uuid=network_connection_object.uuid,
                        relationship_type="initiates",
                    )
                )
            else:
                for protocol, timestamps in data.items():
                    network_connection_object = MISPObject("network-connection")
                    for attribute in attributes:
                        network_connection_object.add_attribute(**attribute)
                    network_connection_object.add_attribute(
                        **{
                            "type": "datetime",
                            "object_relation": "first-packet-seen",
                            "value": min(timestamps),
                            "to_ids": False,
                        }
                    )
                    network_connection_object.add_attribute(
                        **{
                            "type": "text",
                            "object_relation": f"layer{protocols[protocol]}-protocol",
                            "value": protocol,
                            "to_ids": False,
                        }
                    )
                    self.misp_event.add_object(network_connection_object)
                    self.references[self.analysisinfo_uuid].append(
                        dict(
                            referenced_uuid=network_connection_object.uuid,
                            relationship_type="initiates",
                        )
                    )

    def parse_screenshot(self):
        if self.data["behavior"].get("screenshotdata", {}).get("interesting") is not None:
            screenshotdata = self.data["behavior"]["screenshotdata"]["interesting"]["$"]
            self.misp_event.add_attribute(
                **{
                    "type": "attachment",
                    "value": "screenshot.jpg",
                    "data": screenshotdata,
                    "disable_correlation": True,
                    "to_ids": False,
                }
            )

    def parse_system_behavior(self):
        if not "system" in self.data["behavior"]:
            return
        system = self.data["behavior"]["system"]
        if system.get("processes"):
            process_activities = {
                "fileactivities": self.parse_fileactivities,
                "registryactivities": self.parse_registryactivities,
            }
            for process in system["processes"]["process"]:
                general = process["general"]
                process_object = MISPObject("process")
                for feature, relation in process_object_fields.items():
                    process_object.add_attribute(
                        **{
                            "type": "text",
                            "object_relation": relation,
                            "value": general[feature],
                            "to_ids": False,
                        }
                    )
                start_time = datetime.strptime(f"{general['date']} {general['time']}", "%d/%m/%Y %H:%M:%S")
                process_object.add_attribute(
                    **{
                        "type": "datetime",
                        "object_relation": "start-time",
                        "value": start_time,
                        "to_ids": False,
                    }
                )
                self.misp_event.add_object(process_object)
                for field, to_call in process_activities.items():
                    if process.get(field):
                        to_call(process_object.uuid, process[field])
                self.references[self.analysisinfo_uuid].append(
                    dict(referenced_uuid=process_object.uuid, relationship_type="calls")
                )
                self.process_references[(general["targetid"], general["path"])] = process_object.uuid

    def parse_fileactivities(self, process_uuid, fileactivities):
        for feature, files in fileactivities.items():
            # ignore unknown features
            if feature not in file_references_mapping:
                continue

            if files:
                for call in files["call"]:
                    self.attributes["filename"][call["path"]].add((process_uuid, file_references_mapping[feature]))

    def analysis_type(self):
        generalinfo = self.data["generalinfo"]

        if generalinfo["target"]["sample"]:
            return "file"
        elif generalinfo["target"]["url"]:
            return "url"
        else:
            raise Exception("Unknown analysis type")

    def parse_url_analysis(self):
        generalinfo = self.data["generalinfo"]

        url_object = MISPObject("url")
        self.analysisinfo_uuid = url_object.uuid
        url_object.add_attribute(
            **{
                "type": "url",
                "object_relation": "url",
                "value": generalinfo["target"]["url"],
                "to_ids": False,
            }
        )
        self.misp_event.add_object(url_object)

    def parse_fileinfo(self):
        fileinfo = self.data["fileinfo"]

        file_object = MISPObject("file")
        self.analysisinfo_uuid = file_object.uuid

        for field in file_object_fields:
            file_object.add_attribute(
                **{
                    "type": field,
                    "object_relation": field,
                    "value": fileinfo[field],
                    "to_ids": False,
                }
            )
        for field, mapping in file_object_mapping.items():
            if fileinfo.get(field) is not None:
                attribute = {"value": fileinfo[field], "to_ids": False}
                attribute.update(mapping)
                file_object.add_attribute(**attribute)
        arch = self.data["generalinfo"]["arch"]
        if self.import_executable and arch in arch_type_mapping:
            to_call = arch_type_mapping[arch]
            getattr(self, to_call)(fileinfo, file_object)
        else:
            self.misp_event.add_object(file_object)

    def parse_apk(self, fileinfo, file_object):
        apkinfo = fileinfo["apk"]
        self.misp_event.add_object(file_object)
        permission_lists = defaultdict(list)
        for permission in apkinfo["requiredpermissions"]["permission"]:
            permission = permission["@name"].split(".")
            permission_lists[" ".join(permission[:-1])].append(permission[-1])
        attribute_type = "text"
        for comment, permissions in permission_lists.items():
            permission_object = MISPObject("android-permission")
            permission_object.add_attribute(
                **{
                    "type": attribute_type,
                    "object_relation": "comment",
                    "value": comment,
                    "to_ids": False,
                }
            )
            for permission in permissions:
                permission_object.add_attribute(
                    **{
                        "type": attribute_type,
                        "object_relation": "permission",
                        "value": permission,
                        "to_ids": False,
                    }
                )
            self.misp_event.add_object(permission_object)
            self.references[file_object.uuid].append(
                dict(referenced_uuid=permission_object.uuid, relationship_type="grants")
            )

    def parse_elf(self, fileinfo, file_object):
        elfinfo = fileinfo["elf"]
        self.misp_event.add_object(file_object)
        attribute_type = "text"
        relationship = "includes"
        size = "size-in-bytes"
        for fileinfo in elfinfo["file"]:
            elf_object = MISPObject("elf")
            self.references[file_object.uuid].append(
                dict(referenced_uuid=elf_object.uuid, relationship_type=relationship)
            )
            elf = fileinfo["main"][0]["header"][0]
            if elf.get("type"):
                # Haven't seen anything but EXEC yet in the files I tested
                attribute_value = "EXECUTABLE" if elf["type"] == "EXEC (Executable file)" else elf["type"]
                elf_object.add_attribute(
                    **{
                        "type": attribute_type,
                        "object_relation": "type",
                        "value": attribute_value,
                        "to_ids": False,
                    }
                )
            for feature, relation in elf_object_mapping.items():
                if elf.get(feature):
                    elf_object.add_attribute(
                        **{
                            "type": attribute_type,
                            "object_relation": relation,
                            "value": elf[feature],
                            "to_ids": False,
                        }
                    )
            sections_number = len(fileinfo["sections"]["section"])
            elf_object.add_attribute(
                **{
                    "type": "counter",
                    "object_relation": "number-sections",
                    "value": sections_number,
                    "to_ids": False,
                }
            )
            self.misp_event.add_object(elf_object)
            for section in fileinfo["sections"]["section"]:
                section_object = MISPObject("elf-section")
                for feature in ("name", "type"):
                    if section.get(feature):
                        section_object.add_attribute(
                            **{
                                "type": attribute_type,
                                "object_relation": feature,
                                "value": section[feature],
                                "to_ids": False,
                            }
                        )
                if section.get("size"):
                    section_object.add_attribute(
                        **{
                            "type": size,
                            "object_relation": size,
                            "value": int(section["size"], 16),
                            "to_ids": False,
                        }
                    )
                for flag in section["flagsdesc"]:
                    try:
                        attribute_value = elf_section_flags_mapping[flag]
                        section_object.add_attribute(
                            **{
                                "type": attribute_type,
                                "object_relation": "flag",
                                "value": attribute_value,
                                "to_ids": False,
                            }
                        )
                    except KeyError:
                        print(f"Unknown elf section flag: {flag}")
                        continue
                self.misp_event.add_object(section_object)
                self.references[elf_object.uuid].append(
                    dict(
                        referenced_uuid=section_object.uuid,
                        relationship_type=relationship,
                    )
                )

    def parse_pe(self, fileinfo, file_object):
        try:
            peinfo = fileinfo["pe"]
        except KeyError:
            self.misp_event.add_object(file_object)
            return
        pe_object = MISPObject("pe")
        relationship = "includes"
        file_object.add_reference(pe_object.uuid, relationship)
        self.misp_event.add_object(file_object)
        for field, mapping in pe_object_fields.items():
            if peinfo.get(field) is not None:
                attribute = {"value": peinfo[field], "to_ids": False}
                attribute.update(mapping)
                pe_object.add_attribute(**attribute)
        pe_object.add_attribute(
            **{
                "type": "datetime",
                "object_relation": "compilation-timestamp",
                "value": int(peinfo["timestamp"].split()[0], 16),
                "to_ids": False,
            }
        )
        program_name = fileinfo["filename"]
        if peinfo["versions"]:
            for feature in peinfo["versions"]["version"]:
                name = feature["name"]
                if name == "InternalName":
                    program_name = feature["value"]
                if name in pe_object_mapping:
                    pe_object.add_attribute(
                        **{
                            "type": "text",
                            "object_relation": pe_object_mapping[name],
                            "value": feature["value"],
                            "to_ids": False,
                        }
                    )
        sections_number = len(peinfo["sections"]["section"])
        pe_object.add_attribute(
            **{
                "type": "counter",
                "object_relation": "number-sections",
                "value": sections_number,
                "to_ids": False,
            }
        )
        signatureinfo = peinfo["signature"]
        if signatureinfo["signed"]:
            signerinfo_object = MISPObject("authenticode-signerinfo")
            pe_object.add_reference(signerinfo_object.uuid, "signed-by")
            self.misp_event.add_object(pe_object)
            signerinfo_object.add_attribute(
                **{
                    "type": "text",
                    "object_relation": "program-name",
                    "value": program_name,
                    "to_ids": False,
                }
            )
            for feature, mapping in signerinfo_object_mapping.items():
                if signatureinfo.get(feature) is not None:
                    attribute = {"value": signatureinfo[feature], "to_ids": False}
                    attribute.update(mapping)
                    signerinfo_object.add_attribute(**attribute)
            self.misp_event.add_object(signerinfo_object)
        else:
            self.misp_event.add_object(pe_object)
        for section in peinfo["sections"]["section"]:
            section_object = self.parse_pe_section(section)
            self.references[pe_object.uuid].append(
                dict(referenced_uuid=section_object.uuid, relationship_type=relationship)
            )
            self.misp_event.add_object(section_object)

    def parse_pe_section(self, section):
        section_object = MISPObject("pe-section")
        for feature, mapping in pe_section_object_mapping.items():
            if section.get(feature) is not None:
                attribute = {"value": section[feature], "to_ids": False}
                attribute.update(mapping)
                section_object.add_attribute(**attribute)
        return section_object

    def parse_network_interactions(self):
        domaininfo = self.data["domaininfo"]
        if domaininfo:
            for domain in domaininfo["domain"]:
                if domain["@ip"] != "unknown":
                    domain_object = MISPObject("domain-ip")
                    for key, mapping in domain_object_mapping.items():
                        if domain.get(key) is not None:
                            attribute = {"value": domain[key], "to_ids": False}
                            attribute.update(mapping)
                            domain_object.add_attribute(**attribute)
                    self.misp_event.add_object(domain_object)
                    reference = dict(referenced_uuid=domain_object.uuid, relationship_type="contacts")
                    self.add_process_reference(domain["@targetid"], domain["@currentpath"], reference)
                else:
                    attribute = MISPAttribute()
                    attribute.from_dict(**{"type": "domain", "value": domain["@name"], "to_ids": False})
                    self.misp_event.add_attribute(**attribute)
                    reference = dict(referenced_uuid=attribute.uuid, relationship_type="contacts")
                    self.add_process_reference(domain["@targetid"], domain["@currentpath"], reference)
        ipinfo = self.data["ipinfo"]
        if ipinfo:
            for ip in ipinfo["ip"]:
                attribute = MISPAttribute()
                attribute.from_dict(**{"type": "ip-dst", "value": ip["@ip"], "to_ids": False})
                self.misp_event.add_attribute(**attribute)
                reference = dict(referenced_uuid=attribute.uuid, relationship_type="contacts")
                self.add_process_reference(ip["@targetid"], ip["@currentpath"], reference)
        urlinfo = self.data["urlinfo"]
        if urlinfo:
            for url in urlinfo["url"]:
                target_id = int(url["@targetid"])
                current_path = url["@currentpath"]
                attribute = MISPAttribute()
                attribute_dict = {"type": "url", "value": url["@name"], "to_ids": False}
                if target_id != -1 and current_path != "unknown":
                    self.references[self.process_references[(target_id, current_path)]].append(
                        {
                            "referenced_uuid": attribute.uuid,
                            "relationship_type": "contacts",
                        }
                    )
                else:
                    attribute_dict["comment"] = "From Memory - Enriched via the joe_import module"
                attribute.from_dict(**attribute_dict)
                self.misp_event.add_attribute(**attribute)

    def parse_registryactivities(self, process_uuid, registryactivities):
        if registryactivities["keyCreated"]:
            for call in registryactivities["keyCreated"]["call"]:
                self.attributes["regkey"][call["path"]].add((process_uuid, "creates"))
        for feature, relationship in registry_references_mapping.items():
            if registryactivities[feature]:
                for call in registryactivities[feature]["call"]:
                    registry_key = MISPObject("registry-key")
                    for field, mapping in regkey_object_mapping.items():
                        if call.get(field) is not None:
                            attribute = {"value": call[field], "to_ids": False}
                            attribute.update(mapping)
                            registry_key.add_attribute(**attribute)
                    registry_key.add_attribute(
                        **{
                            "type": "text",
                            "object_relation": "data-type",
                            "value": f"REG_{call['type'].upper()}",
                            "to_ids": False,
                        }
                    )
                    self.misp_event.add_object(registry_key)
                    self.references[process_uuid].append(
                        dict(
                            referenced_uuid=registry_key.uuid,
                            relationship_type=relationship,
                        )
                    )

    def add_process_reference(self, target, currentpath, reference):
        try:
            self.references[self.process_references[(int(target), currentpath)]].append(reference)
        except KeyError:
            self.references[self.analysisinfo_uuid].append(reference)

    def create_attribute(self, attribute_type, attribute_value):
        attribute = MISPAttribute()
        attribute.from_dict(**{"type": attribute_type, "value": attribute_value, "to_ids": False})
        self.misp_event.add_attribute(**attribute)
        return attribute.uuid

    def finalize_results(self):
        if self.references:
            self.build_references()
        event = json.loads(self.misp_event.to_json())
        self.results = {key: event[key] for key in ("Attribute", "Object", "Tag") if (key in event and event[key])}

    @staticmethod
    def parse_timestamp(timestamp):
        timestamp = timestamp.split(":")
        timestamp[-1] = str(round(float(timestamp[-1].split(" ")[0]), 6))
        return ":".join(timestamp)

    @staticmethod
    def prefetch_attributes_data(connection):
        attributes = []
        for field, value in zip(network_behavior_fields, connection):
            attribute = {"value": value, "to_ids": False}
            attribute.update(network_connection_object_mapping[field])
            attributes.append(attribute)
        return attributes
