# -*- coding: utf-8 -*-
from pymisp import MISPEvent, MISPObject
from pymisp import __path__ as pymisp_path
import csv
import io
import json
import os
import base64

misperrors = {'error': 'Error'}
moduleinfo = {'version': '0.2', 'author': 'Christian Studer',
              'description': 'Import Attributes from a csv file.',
              'module-type': ['import']}
moduleconfig = []
userConfig = {
    'header': {
        'type': 'String',
        'message': 'Define the header of the csv file, with types (included in MISP attribute types or attribute fields) separated by commas.\nFor fields that do not match these types or that you want to skip, please use space or simply nothing between commas.\nFor instance: ip-src,domain, ,timestamp'},
    'has_header': {
        'type': 'Boolean',
        'message': 'Tick this box ONLY if there is a header line, NOT COMMENTED, and all the fields of this header are respecting the recommendations above.'},
    'special_delimiter': {
        'type': 'String',
        'message': 'IF THE DELIMITERS ARE NOT COMMAS, please specify which ones are used (for instance: ";", "|", "/", "\t" for tabs, etc).'
    }
}
mispattributes = {'userConfig': userConfig, 'inputSource': ['file'], 'format': 'misp_standard'}

misp_standard_csv_header = ['uuid', 'event_id', 'category', 'type', 'value', 'comment', 'to_ids', 'date',
                            'object_relation', 'attribute_tag', 'object_uuid', 'object_name', 'object_meta_category']
misp_context_additional_fields = ['event_info', 'event_member_org', 'event_source_org', 'event_distribution',
                                  'event_threat_level_id', 'event_analysis', 'event_date', 'event_tag']
misp_extended_csv_header = misp_standard_csv_header + misp_context_additional_fields


class CsvParser():
    def __init__(self, header, has_header, delimiter, data, from_misp, MISPtypes, categories):
        self.misp_event = MISPEvent()
        self.header = header
        self.has_header = has_header
        self.delimiter = delimiter
        self.data = data
        self.from_misp = from_misp
        self.MISPtypes = MISPtypes
        self.categories = categories
        self.fields_number = len(self.header)
        self.__score_mapping = {0: self.__create_standard_attribute,
                                1: self.__create_attribute_with_ids,
                                2: self.__create_attribute_with_tags,
                                3: self.__create_attribute_with_ids_and_tags,
                                4: self.__create_attribute_check_category,
                                5: self.__create_attribute_check_category_and_ids,
                                6: self.__create_attribute_check_category_and_tags,
                                7: self.__create_attribute_check_category_with_ids_and_tags}

    def parse_csv(self):
        if self.from_misp:
            if self.header == misp_standard_csv_header:
                self.__parse_misp_csv()
            else:
                attribute_fields = misp_standard_csv_header[:1] + misp_standard_csv_header[2:10]
                object_fields = ['object_id'] + misp_standard_csv_header[10:]
                attribute_indexes = []
                object_indexes = []
                for i in range(len(self.header)):
                    if self.header[i] in attribute_fields:
                        attribute_indexes.append(i)
                    elif self.header[i] in object_fields:
                        object_indexes.append(i)
                if object_indexes:
                    if not any(field in self.header for field in ('object_uuid', 'object_id')) or 'object_name' not in self.header:
                        for line in self.data:
                            for index in object_indexes:
                                if line[index].strip():
                                    return {'error': 'It is not possible to import MISP objects from your csv file if you do not specify any object identifier and object name to separate each object from each other.'}
                    if 'object_relation' not in self.header:
                        return {'error': 'In order to import MISP objects, an object relation for each attribute contained in an object is required.'}
                self.__build_misp_event(attribute_indexes, object_indexes)
        else:
            attribute_fields = attribute_fields = misp_standard_csv_header[:1] + misp_standard_csv_header[2:9]
            attribute_indexes = []
            types_indexes = []
            for i in range(len(self.header)):
                if self.header[i] in attribute_fields:
                    attribute_indexes.append(i)
                elif self.header[i] in self.MISPtypes:
                    types_indexes.append(i)
            self.__parse_external_csv(attribute_indexes, types_indexes)
        self.__finalize_results()
        return {'success': 1}

    ################################################################################
    #                      Parsing csv data with MISP fields,                      #
    #                             but a custom header                              #
    ################################################################################

    def __build_misp_event(self, attribute_indexes, object_indexes):
        score = self.__get_score()
        if object_indexes:
            objects = {}
            id_name = 'object_id' if 'object_id' in self.header else 'object_uuid'
            object_id_index = self.header.index(id_name)
            name_index = self.header.index('object_name')
            for line in self.data:
                attribute = self.__score_mapping[score](line, attribute_indexes)
                object_id = line[object_id_index]
                if object_id:
                    if object_id not in objects:
                        misp_object = MISPObject(line[name_index])
                        if id_name == 'object_uuid':
                            misp_object.uuid = object_id
                        objects[object_id] = misp_object
                    objects[object_id].add_attribute(**attribute)
                else:
                    self.event.add_attribute(**attribute)
            for misp_object in objects.values():
                self.misp_event.add_object(**misp_object)
        else:
            for line in self.data:
                attribute = self.__score_mapping[score](line, attribute_indexes)
                self.misp_event.add_attribute(**attribute)

    ################################################################################
    #               Parsing csv data containing fields that are not                #
    #                  MISP attributes or objects standard fields                  #
    #                    (but should be MISP attribute types!!)                    #
    ################################################################################

    def __parse_external_csv(self, attribute_indexes, types_indexes):
        score = self.__get_score()
        if attribute_indexes:
            for line in self.data:
                try:
                    base_attribute = self.__score_mapping[score](line, attribute_indexes)
                except IndexError:
                    continue
                for index in types_indexes:
                    attribute = {'type': self.header[index], 'value': line[index]}
                    attribute.update(base_attribute)
                    self.misp_event.add_attribute(**attribute)
        else:
            for line in self.data:
                for index in types_indexes:
                    self.misp_event.add_attribute(**{'type': self.header[index], 'value': line[index]})

    ################################################################################
    #                       Parsing standard MISP csv format                       #
    ################################################################################

    def __parse_misp_csv(self):
        objects = {}
        attribute_fields = self.header[:1] + self.header[2:8]
        for line in self.data:
            a_uuid, _, category, _type, value, comment, ids, timestamp, relation, tag, o_uuid, name, _ = line[:self.fields_number]
            attribute = {t: v.strip('"') for t, v in zip(attribute_fields, (a_uuid, category, _type, value, comment, ids, timestamp))}
            attribute['to_ids'] = True if attribute['to_ids'] == '1' else False
            if tag:
                attribute['Tag'] = [{'name': t.strip()} for t in tag.split(',')]
            if relation:
                if o_uuid not in objects:
                    objects[o_uuid] = MISPObject(name)
                objects[o_uuid].add_attribute(relation, **attribute)
            else:
                self.misp_event.add_attribute(**attribute)
        for uuid, misp_object in objects.items():
            misp_object.uuid = uuid
            self.misp_event.add_object(**misp_object)

    ################################################################################
    #                              Utility functions                               #
    ################################################################################

    def __create_attribute_check_category(self, line, indexes):
        attribute = self.__create_standard_attribute(line, indexes)
        self.__check_category(attribute)
        return attribute

    def __create_attribute_check_category_and_ids(self, line, indexes):
        attribute = self.__create_attribute_with_ids(line, indexes)
        self.__check_category(attribute)
        return attribute

    def __create_attribute_check_category_and_tags(self, line, indexes):
        attribute = self.__create_attribute_with_tags(line, indexes)
        self.__check_category(attribute)
        return attribute

    def __create_attribute_check_category_with_ids_and_tags(self, line, indexes):
        attribute = self.__create_attribute_with_ids_and_tags(line, indexes)
        self.__check_category(attribute)
        return attribute

    def __create_attribute_with_ids(self, line, indexes):
        attribute = self.__create_standard_attribute(line, indexes)
        self.__deal_with_ids(attribute)
        return attribute

    def __create_attribute_with_ids_and_tags(self, line, indexes):
        attribute = self.__create_standard_attribute(line, indexes)
        self.__deal_with_ids(attribute)
        self.__deal_with_tags(attribute)
        return attribute

    def __create_attribute_with_tags(self, line, indexes):
        attribute = self.__create_standard_attribute(line, indexes)
        self.__deal_with_tags(attribute)
        return attribute

    def __create_standard_attribute(self, line, indexes):
        return {self.header[index]: line[index] for index in indexes if line[index]}

    def __check_category(self, attribute):
        category = attribute['category']
        if category in self.categories:
            return
        if category.capitalize() in self.categories:
            attribute['category'] = category.capitalize()
            return
        del attribute['category']

    @staticmethod
    def __deal_with_ids(attribute):
        attribute['to_ids'] = True if attribute['to_ids'] == '1' else False

    @staticmethod
    def __deal_with_tags(attribute):
        attribute['Tag'] = [{'name': tag.strip()} for tag in attribute['Tag'].split(',')]

    def __get_score(self):
        score = 1 if 'to_ids' in self.header else 0
        if 'attribute_tag' in self.header:
            score += 2
        if 'category' in self.header:
            score += 4
        return score

    def __finalize_results(self):
        event = json.loads(self.misp_event.to_json())
        self.results = {key: event[key] for key in ('Attribute', 'Object') if (key in event and event[key])}


def __any_mandatory_misp_field(header):
    return any(field in header for field in ('type', 'value'))


def __special_parsing(data, delimiter):
    return list(tuple(part.strip() for part in line[0].split(delimiter)) for line in csv.reader(io.TextIOWrapper(io.BytesIO(data.encode()), encoding='utf-8')) if line and not line[0].startswith('#'))


def __standard_parsing(data):
    return list(tuple(part.strip() for part in line) for line in csv.reader(io.TextIOWrapper(io.BytesIO(data.encode()), encoding='utf-8')) if line and not line[0].startswith('#'))


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if request.get('data'):
        try:
            data = base64.b64decode(request['data']).decode('utf-8')
        except UnicodeDecodeError:
            misperrors['error'] = "Input is not valid UTF-8"
            return misperrors
    else:
        misperrors['error'] = "Unsupported attributes type"
        return misperrors
    has_header = request['config'].get('has_header')
    has_header = True if has_header == '1' else False
    header = request['config']['header'].split(',') if request['config'].get('header').strip() else []
    delimiter = request['config']['special_delimiter'] if request['config'].get('special_delimiter').strip() else ','
    data = __standard_parsing(data) if delimiter == ',' else __special_parsing(data, delimiter)
    if not header:
        if has_header:
            header = data.pop(0)
        else:
            misperrors['error'] = "Configuration error. Provide a header or use the one within the csv file and tick the checkbox 'Has_header'."
            return misperrors
    else:
        header = [h.strip() for h in header]
        if has_header:
            del data[0]
    if header == misp_standard_csv_header or header == misp_extended_csv_header:
        header = misp_standard_csv_header
    descFilename = os.path.join(pymisp_path[0], 'data/describeTypes.json')
    with open(descFilename, 'r') as f:
        description = json.loads(f.read())['result']
    MISPtypes = description['types']
    for h in header:
        if not any((h in MISPtypes, h in misp_extended_csv_header, h in ('', ' ', '_', 'object_id'))):
            misperrors['error'] = 'Wrong header field: {}. Please use a header value that can be recognized by MISP (or alternatively skip it using a whitespace).'.format(h)
            return misperrors
    from_misp = all((h in misp_extended_csv_header or h in ('', ' ', '_', 'object_id') for h in header))
    if from_misp:
        if not __any_mandatory_misp_field(header):
            misperrors['error'] = 'Please make sure the data you try to import can be identified with a type/value combinaison.'
            return misperrors
    else:
        if __any_mandatory_misp_field(header):
            wrong_types = tuple(wrong_type for wrong_type in ('type', 'value') if wrong_type in header)
            misperrors['error'] = 'Error with the following header: {}. It contains the following field(s): {}, which is(are) already provided by the usage of at least on MISP attribute type in the header.'.format(header, 'and'.join(wrong_types))
            return misperrors
    csv_parser = CsvParser(header, has_header, delimiter, data, from_misp, MISPtypes, description['categories'])
    # build the attributes
    result = csv_parser.parse_csv()
    if 'error' in result:
        return result
    return {'results': csv_parser.results}


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
