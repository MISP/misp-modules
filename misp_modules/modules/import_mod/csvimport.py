# -*- coding: utf-8 -*-
from collections import defaultdict
import csv
import io
import json
import os
import base64
import pymisp

misperrors = {'error': 'Error'}
moduleinfo = {'version': '0.1', 'author': 'Christian Studer',
              'description': 'Import Attributes from a csv file.',
              'module-type': ['import']}
moduleconfig = []
userConfig = {'header': {
    'type': 'String',
    'message': 'Define the header of the csv file, with types (included in MISP attribute types or attribute fields) separated by commas.\nFor fields that do not match these types, please use space or simply nothing between commas.\nFor instance: ip-src,domain, ,timestamp'},
    'has_header': {
        'type': 'Boolean',
        'message': 'Tick this box ONLY if there is a header line, NOT COMMENTED, in the file (which will be skipped atm).'
}}
mispattributes = {'userConfig': userConfig, 'inputSource': ['file'], 'format': 'misp_standard'}

duplicatedFields = {'mispType': {'mispComment': 'comment'},
                    'attrField': {'attrComment': 'comment'}}
attributesFields = ['type', 'value', 'category', 'to_ids', 'comment', 'distribution']
misp_standard_csv_header = ['uuid', 'event_id', 'category', 'type', 'value', 'comment', 'to_ids', 'date',
                            'object_relation', 'attribute_tag', 'object_uuid', 'object_name', 'object_meta_category']
misp_context_additional_fields = ['event_info','event_member_org','event_source_org','event_distribution',
                                  'event_threat_level_id','event_analysis','event_date','event_tag']
misp_extended_csv_header = misp_standard_csv_header + misp_context_additional_fields
delimiters = [',', ';', '|', '/', '\t', '    ']


class CsvParser():
    def __init__(self, header, has_header, data):
        data_header = data[0]
        if data_header == misp_standard_csv_header or data_header == misp_extended_csv_header:
            self.header = misp_standard_csv_header if data_header == misp_standard_csv_header else misp_extended_csv_header[:13]
            self.from_misp = True
            self.data = data[1:]
        else:
            self.from_misp = False
            self.has_header = has_header
            if header:
                self.header = header
                self.fields_number = len(header)
                self.parse_data(data)
            else:
                self.has_delimiter = True
                self.fields_number, self.delimiter, self.header = self.get_delimiter_from_header(data[0])
                self.data = data
            self.result = []

    def get_delimiter_from_header(self, data):
        delimiters_count = {}
        for d in delimiters:
            length = data.count(d)
            if length > 0:
                delimiters_count[d] = data.count(d)
        if len(delimiters_count) == 0:
            length = 0
            delimiter = None
            header = [data]
        else:
            length, delimiter = max((n, v) for v, n in delimiters_count.items())
            header = data.split(delimiter)
        return length + 1, delimiter, header

    def parse_data(self, data):
        return_data = []
        if self.fields_number == 1:
            for line in data:
                line = line.split('#')[0].strip()
                if line:
                    return_data.append(line)
            self.delimiter = None
        else:
            self.delimiter_count = dict([(d, 0) for d in delimiters])
            for line in data:
                line = line.split('#')[0].strip()
                if line:
                    self.parse_delimiter(line)
                    return_data.append(line)
            # find which delimiter is used
            self.delimiter = self.find_delimiter()
            if self.fields_number == 0: self.header = return_data[0].split(self.delimiter)
        self.data = return_data[1:] if self.has_header else return_data

    def parse_delimiter(self, line):
        for d in delimiters:
            if line.count(d) >= (self.fields_number - 1):
                self.delimiter_count[d] += 1

    def find_delimiter(self):
        _, delimiter = max((n, v) for v, n in self.delimiter_count.items())
        return delimiter

    def parse_csv(self):
        if self.from_misp:
            self.build_misp_event()
        else:
            self.buildAttributes()

    def build_misp_event(self):
        l_attributes = []
        l_objects = []
        objects = defaultdict(list)
        header_length = len(self.header)
        attribute_fields = self.header[:1] + self.header[2:6]
        for line in self.data:
            attribute = {}
            try:
                try:
                    a_uuid,_,a_category,a_type,value,comment,to_ids,_,relation,o_uuid,o_name,o_category = line[:header_length]
                except ValueError:
                    a_uuid,_,a_category,a_type,value,comment,to_ids,_,relation,tag,o_uuid,o_name,o_category = line[:header_length]
                    if tag: attribute['tags'] = tag
            except ValueError:
                continue
            for t, v in zip(attribute_fields, [a_uuid, a_category, a_type, value, comment]):
                attribute[t] = v.replace('"', '')
            attribute['to_ids'] = True if to_ids == '1' else False
            if relation:
                attribute["object_relation"] = relation.replace('"', '')
                object_index = tuple(o.replace('"', '') for o in (o_uuid,o_name,o_category))
                objects[object_index].append(attribute)
            else:
                l_attributes.append(attribute)
        for keys, attributes in objects.items():
            misp_object = {}
            for t, v in zip(['uuid','name','meta-category'], keys):
                misp_object[t] = v
            misp_object['Attribute'] = attributes
            l_objects.append(misp_object)
        self.result = {"Attribute": l_attributes, "Object": l_objects}

    def buildAttributes(self):
        # if there is only 1 field of data
        if self.delimiter is None:
            mispType = self.header[0]
            for data in self.data:
                d = data.strip()
                if d:
                    self.result.append({'types': mispType, 'values': d})
        else:
            # split fields that should be recognized as misp attribute types from the others
            list2pop, misp, head = self.findMispTypes()
            # for each line of data
            for data in self.data:
                datamisp = []
                datasplit = data.split(self.delimiter)
                # in case there is an empty line or an error
                if len(datasplit) != self.fields_number:
                    continue
                # pop from the line data that matches with a misp type, using the list of indexes
                for l in list2pop:
                    datamisp.append(datasplit.pop(l).strip())
                # for each misp type, we create an attribute
                for m, dm in zip(misp, datamisp):
                    attribute = {'types': m, 'values': dm}
                    for h, ds in zip(head, datasplit):
                        if h:
                            attribute[h] = ds.strip()
                    self.result.append(attribute)

    def findMispTypes(self):
        descFilename = os.path.join(pymisp.__path__[0], 'data/describeTypes.json')
        with open(descFilename, 'r') as f:
            MispTypes = json.loads(f.read())['result'].get('types')
        list2pop = []
        misp = []
        head = []
        for h in reversed(self.header):
            n = self.header.index(h)
            # fields that are misp attribute types
            if h in MispTypes:
                list2pop.append(n)
                misp.append(h)
            # handle confusions between misp attribute types and attribute fields
            elif h in duplicatedFields['mispType']:
                # fields that should be considered as misp attribute types
                list2pop.append(n)
                misp.append(duplicatedFields['mispType'].get(h))
            elif h in duplicatedFields['attrField']:
                # fields that should be considered as attribute fields
                head.append(duplicatedFields['attrField'].get(h))
            # or, it could be an attribute field
            elif h in attributesFields:
                head.append(h)
            # otherwise, it is not defined
            else:
                head.append('')
        # return list of indexes of the misp types, list of the misp types, remaining fields that will be attribute fields
        return list2pop, misp, list(reversed(head))


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if request.get('data'):
        data = base64.b64decode(request['data']).decode('utf-8')
        data = [line for line in csv.reader(io.TextIOWrapper(io.BytesIO(data.encode()), encoding='utf-8'))]
    else:
        misperrors['error'] = "Unsupported attributes type"
        return misperrors
    has_header = request['config'].get('has_header')
    has_header = True if has_header == '1' else False
    if not request.get('config') and not request['config'].get('header'):
        if has_header:
            header = []
        else:
            misperrors['error'] = "Configuration error"
            return misperrors
    else:
        header = request['config'].get('header').split(',')
        header = [c.strip() for c in header]
    csv_parser = CsvParser(header, has_header, data)
    # build the attributes
    csv_parser.parse_csv()
    r = {'results': csv_parser.result}
    return r


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
