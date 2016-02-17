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

runPath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(runPath, '..'))

modulesdir = '../modules/expansion'

mhandlers = {}
modules = []
for module in os.listdir(modulesdir):
    if ".py" not in module or ".pyc" in module:
        continue
    modulename = module.split(".")[0]
    modules.append(modulename)
    mhandlers[modulename] = importlib.import_module('modules.expansion.'+modulename)
    print (module)

class ListModules(tornado.web.RequestHandler):
    def get(self):
        ret = []
        for module in modules:
            x = {}
            x['name'] = module
            x['mispattributes'] = mhandlers[module].introspection()
            print (x['mispattributes'])
            ret.append(x)
        self.write(json.dumps(ret))
class QueryModule(tornado.web.RequestHandler):
    def post(self):
        jsonpayload = self.request.body.decode('utf-8')
        x=json.loads(jsonpayload)
        ret = mhandlers[x['module']].handler(q=jsonpayload)
        self.write(json.dumps(ret))


service = [(r'/modules',ListModules), (r'/query',QueryModule)]

application = tornado.web.Application(service)
application.listen(6666)
tornado.ioloop.IOLoop.instance().start()
