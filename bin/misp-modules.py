#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Core MISP expansion modules loader and web service
#
# Copyright (C) 2016 Alexandre Dulaunoy
# Copyright (C) 2016 CIRCL - Computer Incident Response Center Luxembourg
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import sys
import tornado.web
import importlib
import json
import logging
import re

runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, '..'))
port = 6666

log = logging.getLogger('misp-modules')
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler = logging.StreamHandler(stream=sys.stdout)
handler.setFormatter(formatter)
handler.setLevel(logging.INFO)

log.addHandler(handler)
log.setLevel(logging.INFO)

modulesdir = '../modules/expansion'

mhandlers = {}
modules = []
for module in os.listdir(modulesdir):
    if ".py" not in module or ".pyc" in module or ".py~" in module:
        continue
    if re.match("^\.", module):
        continue
    modulename = module.split(".")[0]
    moduletype = os.path.split(modulesdir)[1]
    modules.append(modulename)
    log.info('MISP modules {0} imported'.format(modulename))
    mhandlers[modulename] = importlib.import_module('modules.expansion.' + modulename)
    mhandlers['type:' + modulename] = moduletype


class ListModules(tornado.web.RequestHandler):
    def get(self):
        ret = []
        for module in modules:
            x = {}
            x['name'] = module
            x['type'] = mhandlers['type:' + module]
            x['mispattributes'] = mhandlers[module].introspection()
            x['meta'] = mhandlers[module].version()
            ret.append(x)
        log.debug('MISP ListModules request')
        self.write(json.dumps(ret))


class QueryModule(tornado.web.RequestHandler):
    def post(self):
        jsonpayload = self.request.body.decode('utf-8')
        x = json.loads(jsonpayload)
        log.debug('MISP QueryModule request {0}'.format(jsonpayload))
        ret = mhandlers[x['module']].handler(q=jsonpayload)
        self.write(json.dumps(ret))


service = [(r'/modules', ListModules), (r'/query', QueryModule)]

application = tornado.web.Application(service)
log.info('MISP modules server started on TCP port {0}'.format(port))
application.listen(port)
tornado.ioloop.IOLoop.instance().start()
