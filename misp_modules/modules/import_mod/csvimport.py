# -*- coding: utf-8 -*-
import json, os, base64
import pymisp

misperrors = {'error': 'Error'}
moduleinfo = {'version': '0.1', 'author': 'Christian Studer',
              'description': 'Import Attributes from a csv file.',
              'module-type': ['import']}
moduleconfig = []
inputSource = ['file']
userConfig = {'header': {
                'type': 'String',
                'message': 'Define the header of the csv file, with types (included in MISP attribute types or attribute fields) separated by commas.\nFor fields that do not match these types, please use space or simply nothing between commas.\nFor instance: ip-src,domain, ,timestamp'},
              'has_header':{
                'type': 'Boolean',
                'message': 'Tick this box ONLY if there is a header line, NOT COMMENTED, in the file (which will be skipped atm).'
              }}

duplicatedFields = {'mispType': {'mispComment': 'comment'},
                    'attrField': {'attrComment': 'comment'}}
attributesFields = ['type', 'value', 'category', 'to_ids', 'comment', 'distribution']
delimiters = [',', ';', '|', '/', '\t', '    ']

class CsvParser():
    def __init__(self, header, has_header):
        self.header = header
        self.fields_number = len(header)
        self.has_header = has_header
        self.attributes = []

    def parse_data(self, data):
        return_data = []
        if self.fields_number == 1:
            for line in data:
                l = line.split('#')[0].strip()
                if l:
                    return_data.append(l)
            self.delimiter = None
        else:
            self.delimiter_count = dict([(d, 0) for d in delimiters])
            for line in data:
                l = line.split('#')[0].strip()
                if l:
                    self.parse_delimiter(l)
                    return_data.append(l)
            # find which delimiter is used
            self.delimiter = self.find_delimiter()
        self.data = return_data[1:] if self.has_header else return_data

    def parse_delimiter(self, line):
        for d in delimiters:
            if line.count(d) >= (self.fields_number - 1):
                self.delimiter_count[d] += 1

    def find_delimiter(self):
        _, delimiter = max((n, v) for v, n in self.delimiter_count.items())
        return delimiter

    def buildAttributes(self):
        # if there is only 1 field of data
        if self.delimiter is None:
            mispType = self.header[0]
            for data in self.data:
                d = data.strip()
                if d:
                    self.attributes.append({'types': mispType, 'values': d})
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
                    self.attributes.append(attribute)

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
    else:
        misperrors['error'] = "Unsupported attributes type"
        return misperrors
    if not request.get('config') and not request['config'].get('header'):
        misperrors['error'] = "Configuration error"
        return misperrors
    header = request['config'].get('header').split(',')
    header = [c.strip() for c in header]
    has_header = request['config'].get('has_header')
    has_header = True if has_header == '1' else False
    csv_parser = CsvParser(header, has_header)
    csv_parser.parse_data(data.split('\n'))
    # build the attributes
    csv_parser.buildAttributes()
    r = {'results': csv_parser.attributes}
    return r

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
    return modulesetup

def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
