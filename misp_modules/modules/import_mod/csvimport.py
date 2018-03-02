# -*- coding: utf-8 -*-
import json, os, base64
import pymisp

misperrors = {'error': 'Error'}
mispattributes = {'inputSource': ['file'], 'output': ['MISP attributes']}
moduleinfo = {'version': '0.1', 'author': 'Christian Studer',
              'description': 'Import Attributes from a csv file.',
              'module-type': ['import']}
moduleconfig = ['header']

duplicatedFields = {'mispType': {'mispComment': 'comment'},
                    'attrField': {'eventComment': 'comment'}}

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
    config = request['config'].get('header').split(',')
    config = [c.strip() for c in config]
    data = parse_data(data.split('\n'))
    # find which delimiter is used
    delimiter, length = findDelimiter(config, data)
    # build the attributes
    result = buildAttributes(config, data, delimiter, length)
    r = {'results': result}
    return r

def parse_data(data):
    return_data = []
    for line in data:
        l = line.split('#')[0].strip() if '#' in line else line.strip()
        if l:
            return_data.append(l)
    print(len(return_data))
    return return_data

def findDelimiter(header, data):
    n = len(header)
    if n > 1:
        tmpData = []
        for da in data:
            tmp = []
            for d in (';', '|', '/', ',', '\t', '    ',):
                if da.count(d) == (n-1):
                    tmp.append(d)
            if len(tmp) == 1 and tmp == tmpData:
                return tmpData[0], n
            else:
                tmpData = tmp
    else:
        return None, 1

def buildAttributes(header, dataValues, delimiter, length):
    attributes = []
    # if there is only 1 field of data
    if delimiter is None:
        mispType = header[0]
        for data in dataValues:
            d = data.strip()
            if d:
                attributes.append({'types': mispType, 'values': d})
    else:
        # split fields that should be recognized as misp attribute types from the others
        list2pop, misp, head = findMispTypes(header)
        # for each line of data
        for data in dataValues:
            datamisp = []
            datasplit = data.split(delimiter)
            # in case there is an empty line or an error
            if len(datasplit) != length:
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
                attributes.append(attribute)
    return attributes

def findMispTypes(header):
    descFilename = os.path.join(pymisp.__path__[0], 'data/describeTypes.json')
    with open(descFilename, 'r') as f:
        MispTypes = json.loads(f.read())['result'].get('types')
    list2pop = []
    misp = []
    head = []
    for h in reversed(header):
        n = header.index(h)
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
        # otherwise, it is an attribute field
        else:
            head.append(h)
    # return list of indexes of the misp types, list of the misp types, remaining fields that will be attribute fields
    return list2pop, misp, list(reversed(head))

def introspection():
    return mispattributes

def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
