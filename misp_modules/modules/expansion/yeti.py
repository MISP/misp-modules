import json

import json
try:
    import pyeti
except ImportError:
    print("pyeti module not installed.")

misperrors = {'error': 'Error'}

mispattributes = {'input': ['ip-src', 'ip-dst', 'hostname', 'domain'],
                  'output': ['hostname', 'domain', 'ip-src', 'ip-dst', 'url']}
# possible module-types: 'expansion', 'hover' or both
moduleinfo = {'version': '1', 'author': 'Sebastien Larinier @sebdraven',
              'description': 'Query on yeti',
              'module-type': ['expansion', 'hover']}

