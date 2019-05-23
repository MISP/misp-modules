# -*- coding: utf-8 -*-
from collections import defaultdict
from datetime import datetime
from pymisp import MISPAttribute, MISPEvent, MISPObject
import json
import base64

misperrors = {'error': 'Error'}
userConfig = {}
inputSource = ['file']

moduleinfo = {'version': '0.1', 'author': 'Christian Studer',
              'description': 'Import for Joe Sandbox JSON reports',
              'module-type': ['import']}

moduleconfig = []

domain_object_mapping = {'@ip': ('ip-dst', 'ip'), '@name': ('domain', 'domain')}
dropped_file_mapping = {'@entropy': ('float', 'entropy'),
                        '@file': ('filename', 'filename'),
                        '@size': ('size-in-bytes', 'size-in-bytes'),
                        '@type': ('mime-type', 'mimetype')}
dropped_hash_mapping = {'MD5': 'md5', 'SHA': 'sha1', 'SHA-256': 'sha256', 'SHA-512': 'sha512'}
file_object_fields = ['filename', 'md5', 'sha1', 'sha256', 'sha512', 'ssdeep']
file_object_mapping = {'entropy': ('float', 'entropy'),
                       'filesize': ('size-in-bytes', 'size-in-bytes'),
                       'filetype': ('mime-type', 'mimetype')}
file_references_mapping = {'fileCreated': 'creates', 'fileDeleted': 'deletes',
                           'fileMoved': 'moves', 'fileRead': 'reads', 'fileWritten': 'writes'}
network_behavior_fields = ('srcip', 'dstip', 'srcport', 'dstport')
network_connection_object_mapping = {'srcip': ('ip-src', 'ip-src'), 'dstip': ('ip-dst', 'ip-dst'),
                                     'srcport': ('port', 'src-port'), 'dstport': ('port', 'dst-port')}
pe_object_fields = {'entrypoint': ('text', 'entrypoint-address'),
                    'imphash': ('imphash', 'imphash')}
pe_object_mapping = {'CompanyName': 'company-name', 'FileDescription': 'file-description',
                     'FileVersion': 'file-version', 'InternalName': 'internal-filename',
                     'LegalCopyright': 'legal-copyright', 'OriginalFilename': 'original-filename',
                     'ProductName': 'product-filename', 'ProductVersion': 'product-version',
                     'Translation': 'lang-id'}
process_object_fields = {'cmdline': 'command-line', 'name': 'name',
                         'parentpid': 'parent-pid', 'pid': 'pid',
                         'path': 'current-directory'}
protocols = {'tcp': 4, 'udp': 4, 'icmp': 3,
             'http': 7, 'https': 7, 'ftp': 7}
section_object_mapping = {'characteristics': ('text', 'characteristic'),
                          'entropy': ('float', 'entropy'),
                          'name': ('text', 'name'), 'rawaddr': ('hex', 'offset'),
                          'rawsize': ('size-in-bytes', 'size-in-bytes'),
                          'virtaddr': ('hex', 'virtual_address'),
                          'virtsize': ('size-in-bytes', 'virtual_size')}
registry_references_mapping = {'keyValueCreated': 'creates', 'keyValueModified': 'modifies'}
regkey_object_mapping = {'name': ('text', 'name'), 'newdata': ('text', 'data'),
                         'path': ('regkey', 'key')}
signerinfo_object_mapping = {'sigissuer': ('text', 'issuer'),
                             'version': ('text', 'version')}


class JoeParser():
    def __init__(self, data):
        self.data = data
        self.misp_event = MISPEvent()
        self.references = defaultdict(list)
        self.attributes = defaultdict(lambda: defaultdict(set))
        self.process_references = {}

    def parse_joe(self):
        self.parse_fileinfo()
        self.parse_system_behavior()
        self.parse_network_behavior()
        self.parse_network_interactions()
        self.parse_dropped_files()
        if self.attributes:
            self.handle_attributes()
        if self.references:
            self.build_references()
        self.parse_mitre_attack()
        self.finalize_results()

    def build_references(self):
        for misp_object in self.misp_event.objects:
            object_uuid = misp_object.uuid
            if object_uuid in self.references:
                for reference in self.references[object_uuid]:
                    misp_object.add_reference(reference['idref'], reference['relationship'])

    def handle_attributes(self):
        for attribute_type, attribute in self.attributes.items():
            for attribute_value, references in attribute.items():
                attribute_uuid = self.create_attribute(attribute_type, attribute_value)
                for reference in references:
                    source_uuid, relationship = reference
                    self.references[source_uuid].append({'idref': attribute_uuid, 'relationship': relationship})

    def parse_dropped_files(self):
        droppedinfo = self.data['droppedinfo']
        if droppedinfo:
            for droppedfile in droppedinfo['hash']:
                file_object = MISPObject('file')
                for key, mapping in dropped_file_mapping.items():
                    attribute_type, object_relation = mapping
                    file_object.add_attribute(object_relation, **{'type': attribute_type, 'value': droppedfile[key]})
                if droppedfile['@malicious'] == 'true':
                    file_object.add_attribute('state', **{'type': 'text', 'value': 'Malicious'})
                for h in droppedfile['value']:
                    hash_type = dropped_hash_mapping[h['@algo']]
                    file_object.add_attribute(hash_type, **{'type': hash_type, 'value': h['$']})
                self.misp_event.add_object(**file_object)
                self.references[self.process_references[(int(droppedfile['@targetid']), droppedfile['@process'])]].append({
                    'idref': file_object.uuid,
                    'relationship': 'drops'
                })

    def parse_mitre_attack(self):
        mitreattack = self.data['mitreattack']
        if mitreattack:
            for tactic in mitreattack['tactic']:
                if tactic.get('technique'):
                    for technique in tactic['technique']:
                        self.misp_event.add_tag('misp-galaxy:mitre-attack-pattern="{} - {}"'.format(technique['name'], technique['id']))

    def parse_network_behavior(self):
        network = self.data['behavior']['network']
        connections = defaultdict(lambda: defaultdict(set))
        for protocol, layer in protocols.items():
            if network.get(protocol):
                for packet in network[protocol]['packet']:
                    timestamp = datetime.strptime(self.parse_timestamp(packet['timestamp']), '%B %d, %Y %H:%M:%S.%f')
                    connections[tuple(packet[field] for field in network_behavior_fields)][protocol].add(timestamp)
        for connection, data in connections.items():
            attributes = self.prefetch_attributes_data(connection)
            if len(data.keys()) == len(set(protocols[protocol] for protocol in data.keys())):
                network_connection_object = MISPObject('network-connection')
                for object_relation, attribute in attributes.items():
                    network_connection_object.add_attribute(object_relation, **attribute)
                network_connection_object.add_attribute('first-packet-seen',
                                                        **{'type': 'datetime', 'value': min(tuple(min(timestamp) for timestamp in data.values()))})
                for protocol in data.keys():
                    network_connection_object.add_attribute('layer{}-protocol'.format(protocols[protocol]), **{'type': 'text', 'value': protocol})
                self.misp_event.add_object(**network_connection_object)
                self.references[self.fileinfo_uuid].append({'idref': network_connection_object.uuid, 'relationship': 'initiates'})
            else:
                for protocol, timestamps in data.items():
                    network_connection_object = MISPObject('network-connection')
                    for object_relation, attribute in attributes.items():
                        network_connection_object.add_attribute(object_relation, **attribute)
                    network_connection_object.add_attribute('first-packet-seen', **{'type': 'datetime', 'value': min(timestamps)})
                    network_connection_object.add_attribute('layer{}-protocol'.format(protocols[protocol]), **{'type': 'text', 'value': protocol})
                    self.misp_event.add_object(**network_connection_object)
                    self.references[self.fileinfo_uuid].append({'idref': network_connection_object.uuid, 'relationship': 'initiates'})

    def parse_system_behavior(self):
        system = self.data['behavior']['system']
        if system.get('processes'):
            process_activities = {'fileactivities': self.parse_fileactivities,
                                  'registryactivities': self.parse_registryactivities}
            for process in system['processes']['process']:
                general = process['general']
                process_object = MISPObject('process')
                for feature, relation in process_object_fields.items():
                    process_object.add_attribute(relation, **{'type': 'text', 'value': general[feature]})
                start_time = datetime.strptime('{} {}'.format(general['date'], general['time']), '%d/%m/%Y %H:%M:%S')
                process_object.add_attribute('start-time', **{'type': 'datetime', 'value': start_time})
                self.misp_event.add_object(**process_object)
                for field, to_call in process_activities.items():
                    to_call(process_object.uuid, process[field])
                self.references[self.fileinfo_uuid].append({'idref': process_object.uuid, 'relationship': 'calls'})
                self.process_references[(general['targetid'], general['path'])] = process_object.uuid

    def parse_fileactivities(self, process_uuid, fileactivities):
        for feature, files in fileactivities.items():
            if files:
                for call in files['call']:
                    self.attributes['filename'][call['path']].add((process_uuid, file_references_mapping[feature]))

    def parse_fileinfo(self):
        fileinfo = self.data['fileinfo']
        file_object = MISPObject('file')
        for field in file_object_fields:
            file_object.add_attribute(field, **{'type': field, 'value': fileinfo[field]})
        for field, mapping in file_object_mapping.items():
            attribute_type, object_relation = mapping
            file_object.add_attribute(object_relation, **{'type': attribute_type, 'value': fileinfo[field]})
        self.fileinfo_uuid = file_object.uuid
        if not fileinfo.get('pe'):
            self.misp_event.add_object(**file_object)
            return
        peinfo = fileinfo['pe']
        pe_object = MISPObject('pe')
        file_object.add_reference(pe_object.uuid, 'included-in')
        self.misp_event.add_object(**file_object)
        for field, mapping in pe_object_fields.items():
            attribute_type, object_relation = mapping
            pe_object.add_attribute(object_relation, **{'type': attribute_type, 'value': peinfo[field]})
        pe_object.add_attribute('compilation-timestamp', **{'type': 'datetime', 'value': int(peinfo['timestamp'].split()[0], 16)})
        program_name = fileinfo['filename']
        if peinfo['versions']:
            for feature in peinfo['versions']['version']:
                name = feature['name']
                if name == 'InternalName':
                    program_name = feature['value']
                pe_object.add_attribute(pe_object_mapping[name], **{'type': 'text', 'value': feature['value']})
        sections_number = len(peinfo['sections']['section'])
        pe_object.add_attribute('number-sections', **{'type': 'counter', 'value': sections_number})
        signatureinfo = peinfo['signature']
        if signatureinfo['signed']:
            signerinfo_object = MISPObject('authenticode-signerinfo')
            pe_object.add_reference(signerinfo_object.uuid, 'signed-by')
            self.misp_event.add_object(**pe_object)
            signerinfo_object.add_attribute('program-name', **{'type': 'text', 'value': program_name})
            for feature, mapping in signerinfo_object_mapping.items():
                attribute_type, object_relation = mapping
                signerinfo_object.add_attribute(object_relation, **{'type': attribute_type, 'value': signatureinfo[feature]})
            self.misp_event.add_object(**signerinfo_object)
        else:
            self.misp_event.add_object(**pe_object)
        for section in peinfo['sections']['section']:
            section_object = self.parse_pe_section(section)
            self.references[pe_object.uuid].append({'idref': section_object.uuid, 'relationship': 'included-in'})
            self.misp_event.add_object(**section_object)

    def parse_network_interactions(self):
        domaininfo = self.data['domaininfo']
        if domaininfo:
            for domain in domaininfo['domain']:
                domain_object = MISPObject('domain-ip')
                for key, mapping in domain_object_mapping.items():
                    attribute_type, object_relation = mapping
                    domain_object.add_attribute(object_relation, **{'type': attribute_type, 'value': domain[key]})
                self.misp_event.add_object(**domain_object)
                self.references[self.process_references[(int(domain['@targetid']), domain['@currentpath'])]].append({
                    'idref': domain_object.uuid,
                    'relationship': 'contacts'
                })
        ipinfo = self.data['ipinfo']
        if ipinfo:
            for ip in ipinfo['ip']:
                attribute = MISPAttribute()
                attribute.from_dict(**{'type': 'ip-dst', 'value': ip['@ip']})
                self.misp_event.add_attribute(**attribute)
                self.references[self.process_references[(int(ip['@targetid']), ip['@currentpath'])]].append({
                    'idref': attribute.uuid,
                    'relationship': 'contacts'
                })
        urlinfo = self.data['urlinfo']
        if urlinfo:
            for url in urlinfo['url']:
                target_id = int(url['@targetid'])
                current_path = url['@currentpath']
                attribute = MISPAttribute()
                attribute_dict = {'type': 'url', 'value': url['@name']}
                if target_id != -1 and current_path != 'unknown':
                    self.references[self.process_references[(target_id, current_path)]].append({
                        'idref': attribute.uuid,
                        'relationship': 'contacts'
                    })
                else:
                    attribute_dict['comment'] = 'From Memory - Enriched via the joe_import module'
                attribute.from_dict(**attribute_dict)
                self.misp_event.add_attribute(**attribute)


    def parse_pe_section(self, section):
        section_object = MISPObject('pe-section')
        for feature, mapping in section_object_mapping.items():
            attribute_type, object_relation = mapping
            section_object.add_attribute(object_relation, **{'type': attribute_type, 'value': section[feature]})
        return section_object

    def parse_registryactivities(self, process_uuid, registryactivities):
        if registryactivities['keyCreated']:
            for call in registryactivities['keyCreated']['call']:
                self.attributes['regkey'][call['path']].add((process_uuid, 'creates'))
        for feature, relationship_type in registry_references_mapping.items():
            if registryactivities[feature]:
                for call in registryactivities[feature]['call']:
                    registry_key = MISPObject('registry-key')
                    for field, mapping in regkey_object_mapping.items():
                        attribute_type, object_relation = mapping
                        registry_key.add_attribute(object_relation, **{'type': attribute_type, 'value': call[field]})
                    registry_key.add_attribute('data-type', **{'type': 'text', 'value': 'REG_{}'.format(call['type'].upper())})
                    self.misp_event.add_object(**registry_key)
                    self.references[process_uuid].append({'idref': registry_key.uuid, 'relationship': relationship_type})

    def create_attribute(self, attribute_type, attribute_value):
        attribute = MISPAttribute()
        attribute.from_dict(**{'type': attribute_type, 'value': attribute_value})
        self.misp_event.add_attribute(**attribute)
        return attribute.uuid

    def finalize_results(self):
        event = json.loads(self.misp_event.to_json())['Event']
        self.results = {key: event[key] for key in ('Attribute', 'Object') if (key in event and event[key])}

    @staticmethod
    def parse_timestamp(timestamp):
        timestamp = timestamp.split(':')
        timestamp[-1] = str(round(float(timestamp[-1].split(' ')[0]), 6))
        return ':'.join(timestamp)

    @staticmethod
    def prefetch_attributes_data(connection):
        attributes = {}
        for field, value in zip(network_behavior_fields, connection):
            attribute_type, object_relation = network_connection_object_mapping[field]
            attributes[object_relation] = {'type': attribute_type, 'value': value}
        return attributes


def handler(q=False):
    if q is False:
        return False
    q = json.loads(q)
    data = base64.b64decode(q.get('data')).decode('utf-8')
    if not data:
        return json.dumps({'success': 0})
    joe_data = json.loads(data)['analysis']
    joe_parser = JoeParser(joe_data)
    joe_parser.parse_joe()
    return {'results': joe_parser.results}


def introspection():
    modulesetup = {}
    try:
        userConfig
        modulesetup['userConfig'] = userConfig
    except NameError:
        pass
    try:
        inputSource
        modulesetup['inputSource'] = inputSource
    except NameError:
        pass
    modulesetup['format'] = 'misp_standard'
    return modulesetup


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
