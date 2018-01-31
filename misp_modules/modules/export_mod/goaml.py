import json
import pymisp
import base64

misperrors = {'error': 'Error'}
moduleinfo = {'version': '1', 'author': 'Christian Studer',
              'description': '',
              'module-type': ['export']}
moduleconfig = []
mispattributes = {}

objects_to_parse = ['bank-account', 'person']

class GoAmlGeneration():
    def __init__(self):
        self.document = {}

    def from_event(self, event):
        self.misp_event = pymisp.MISPEvent()
        self.misp_event.load(event)

    def parse_objects(self):
        for obj in self.misp_event.objects:
            if obj.name in objects_to_parse:
                obj_dict = {}
                for attribute in obj.attributes:
                    obj_dict[attribute.object_relation] = attribute.value
                self.document[obj.name] = obj_dict

def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if 'data' not in request:
        return False
    exp_doc = GoAmlGeneration()
    exp_doc.from_event(request['data'][0])
    exp_doc.parse_objects()
    return {'response': {}, 'data': exp_doc.document}
    #return {'response': [], 'data': str(base64.b64encode(bytes(exp_doc.document, 'utf-8')), 'utf-8')}

def introspection():
    return

def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
