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
import signal
import sys
from tornado.ioloop import IOLoop
import tornado.web
import importlib
import json
import logging
import fnmatch
import argparse
import re

try:
    from . import modules
    HAS_PACKAGE_MODULES = True
except Exception as e:
    print(e)
    HAS_PACKAGE_MODULES = False

try:
    from .helpers import *
    HAS_PACKAGE_HELPERS = True
except Exception as e:
    print(e)
    HAS_PACKAGE_HELPERS = False

log = logging.getLogger('misp-modules')

def handle_signal(sig, frame):
    IOLoop.instance().add_callback(IOLoop.instance().stop)


def init_logger():
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(formatter)
    handler.setLevel(logging.INFO)

    log.addHandler(handler)
    log.setLevel(logging.INFO)
    return log


def load_helpers(helpersdir):
    sys.path.append(helpersdir)
    hhandlers = {}
    helpers = []
    for root, dirnames, filenames in os.walk(helpersdir):
        if os.path.basename(root) == '__pycache__':
            continue
        if re.match(r'^\.', os.path.basename(root)):
            continue
        for filename in fnmatch.filter(filenames, '*.py'):
            if filename == '__init__.py':
                continue
            helpername = filename.split(".")[0]
            hhandlers[helpername] = importlib.import_module(helpername)
            selftest = hhandlers[helpername].selftest()
            if selftest is None:
                helpers.append(helpername)
                log.info('Helpers loaded {} '.format(filename))
            else:
                log.info('Helpers failed {} due to {}'.format(filename, selftest))


def load_package_helpers():
    if not HAS_PACKAGE_HELPERS:
        log.info('Unable to load MISP helpers from package.')
        sys.exit()
    mhandlers = {}
    helpers = []
    for path, helper in sys.modules.items():
        if not path.startswith('misp_modules.helpers.'):
            continue
        helpername = path.replace('misp_modules.helpers.', '')
        mhandlers[helpername] = helper
        helpers.append(helpername)
        log.info('Helper loaded {}'.format(helpername))
    return mhandlers, helpers


def load_modules(mod_dir):
    sys.path.append(mod_dir)
    mhandlers = {}
    modules = []
    for root, dirnames, filenames in os.walk(mod_dir):
        if os.path.basename(root) == '__pycache__':
            continue
        if os.path.basename(root).startswith("."):
            continue
        for filename in fnmatch.filter(filenames, '*.py'):
            if filename == '__init__.py':
                continue
            modulename = filename.split(".")[0]
            moduletype = os.path.split(modulesdir)[1]
            try:
                mhandlers[modulename] = importlib.import_module(os.path.basename(root) + '.' + modulename)
            except Exception as e:
                log.warning('MISP modules {0} failed due to {1}'.format(modulename, e))
                continue
            modules.append(modulename)
            log.info('MISP modules {0} imported'.format(modulename))
            mhandlers['type:' + modulename] = moduletype
    return mhandlers, modules


def load_package_modules():
    if not HAS_PACKAGE_MODULES:
        log.info('Unable to load MISP modules from package.')
        sys.exit()
    mhandlers = {}
    modules = []
    for path, module in sys.modules.items():
        r = re.findall("misp_modules[.]modules[.](\w+)[.](\w+)", path)
        if r and len(r[0]) == 2:
            moduletype, modulename = r[0]
            mhandlers[modulename] = module
            modules.append(modulename)
            log.info('MISP modules {0} imported'.format(modulename))
            mhandlers['type:' + modulename] = moduletype
    return mhandlers, modules


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

def main():
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    if os.path.dirname(__file__) in ['.', '']:
        os.chdir('../')
    argParser = argparse.ArgumentParser(description='misp-modules server')
    argParser.add_argument('-t', default=False, action='store_true', help='Test mode')
    argParser.add_argument('-s', default=False, action='store_true', help='Run a system install (package installed via pip)')
    argParser.add_argument('-p', default=6666, help='misp-modules TCP port (default 6666)')
    argParser.add_argument('-l', default='localhost', help='misp-modules listen address (default localhost)')
    args = argParser.parse_args()
    port = args.p
    listen = args.l
    log = init_logger()
    if args.s:
        load_package_helpers()
        mhandlers, modules = load_package_modules()
    else:
        modulesdir = 'misp_modules/modules'
        helpersdir = 'misp_modules/helpers'
        load_helpers(helpersdir=helpersdir)
        mhandlers, modules = load_modules(modulesdir)
    service = [(r'/modules', ListModules), (r'/query', QueryModule)]

    application = tornado.web.Application(service)
    application.listen(port, address=listen)
    log.info('MISP modules server started on {0} port {1}'.format(listen, port))
    if args.t:
        log.info('MISP modules started in test-mode, quitting immediately.')
        sys.exit()
    IOLoop.instance().start()
    IOLoop.instance().stop()
    return 0


if __name__ == '__main__':
    sys.exit(main())
