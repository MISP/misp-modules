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
import importlib
import json
import logging
import fnmatch
import argparse
import re
import datetime
import psutil

import tornado.web
import tornado.process
from tornado.ioloop import IOLoop
from tornado.concurrent import run_on_executor
from concurrent.futures import ThreadPoolExecutor

try:
    from .modules import *  # noqa
    HAS_PACKAGE_MODULES = True
except Exception as e:
    print(e)
    HAS_PACKAGE_MODULES = False

try:
    from .helpers import *  # noqa
    HAS_PACKAGE_HELPERS = True
except Exception as e:
    print(e)
    HAS_PACKAGE_HELPERS = False

log = logging.getLogger('misp-modules')


def handle_signal(sig, frame):
    IOLoop.instance().add_callback_from_signal(IOLoop.instance().stop)


def init_logger(level=False):
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(formatter)
    handler.setLevel(logging.INFO)
    if level:
        handler.setLevel(logging.DEBUG)
    log.addHandler(handler)
    log.setLevel(logging.INFO)
    if level:
        log.setLevel(logging.DEBUG)
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
        selftest = mhandlers[helpername].selftest()
        if selftest is None:
            helpers.append(helpername)
            log.info('Helper loaded {}'.format(helpername))
        else:
            log.info('Helpers failed {} due to {}'.format(helpername, selftest))
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
            if root.split('/')[-1].startswith('_'):
                continue
            if filename == '__init__.py':
                continue
            modulename = filename.split(".")[0]
            moduletype = os.path.split(mod_dir)[1]
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
        r = re.findall(r"misp_modules[.]modules[.](\w+)[.]([^_]\w+)", path)
        if r and len(r[0]) == 2:
            moduletype, modulename = r[0]
            mhandlers[modulename] = module
            modules.append(modulename)
            log.info('MISP modules {0} imported'.format(modulename))
            mhandlers['type:' + modulename] = moduletype
    return mhandlers, modules


class ListModules(tornado.web.RequestHandler):
    global loaded_modules
    global mhandlers

    def get(self):
        ret = []
        for module in loaded_modules:
            x = {}
            x['name'] = module
            x['type'] = mhandlers['type:' + module]
            x['mispattributes'] = mhandlers[module].introspection()
            x['meta'] = mhandlers[module].version()
            ret.append(x)
        log.debug('MISP ListModules request')
        self.write(json.dumps(ret))


class QueryModule(tornado.web.RequestHandler):

    # Default value in Python 3.5
    # https://docs.python.org/3/library/concurrent.futures.html#concurrent.futures.ThreadPoolExecutor
    nb_threads = tornado.process.cpu_count() * 5
    executor = ThreadPoolExecutor(nb_threads)

    @run_on_executor
    def run_request(self, jsonpayload):
        x = json.loads(jsonpayload)
        log.debug('MISP QueryModule request {0}'.format(jsonpayload))
        response = mhandlers[x['module']].handler(q=jsonpayload)
        return json.dumps(response)

    @tornado.gen.coroutine
    def post(self):
        try:
            jsonpayload = self.request.body.decode('utf-8')
            dict_payload = json.loads(jsonpayload)
            if dict_payload.get('timeout'):
                timeout = datetime.timedelta(seconds=int(dict_payload.get('timeout')))
            else:
                timeout = datetime.timedelta(seconds=300)
            response = yield tornado.gen.with_timeout(timeout, self.run_request(jsonpayload))
            self.write(response)
        except tornado.gen.TimeoutError:
            log.warning('Timeout on {} '.format(dict_payload['module']))
            self.write(json.dumps({'error': 'Timeout.'}))
        except Exception:
            self.write(json.dumps({'error': 'Something went wrong, look in the server logs for details'}))
            log.exception('Something went wrong:')
        finally:
            self.finish()


def main():
    global mhandlers
    global loaded_modules
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    argParser = argparse.ArgumentParser(description='misp-modules server')
    argParser.add_argument('-t', default=False, action='store_true', help='Test mode')
    argParser.add_argument('-s', default=False, action='store_true', help='Run a system install (package installed via pip)')
    argParser.add_argument('-d', default=False, action='store_true', help='Enable debugging')
    argParser.add_argument('-p', default=6666, help='misp-modules TCP port (default 6666)')
    argParser.add_argument('-l', default='localhost', help='misp-modules listen address (default localhost)')
    argParser.add_argument('-m', default=[], action='append', help='Register a custom module')
    args = argParser.parse_args()
    port = args.p
    listen = args.l
    log = init_logger(level=args.d)
    if args.s:
        log.info('Launch MISP modules server from package.')
        load_package_helpers()
        mhandlers, loaded_modules = load_package_modules()
    else:
        log.info('Launch MISP modules server from current directory.')
        os.chdir(os.path.dirname(__file__))
        modulesdir = 'modules'
        helpersdir = 'helpers'
        load_helpers(helpersdir=helpersdir)
        mhandlers, loaded_modules = load_modules(modulesdir)

    for module in args.m:
        mispmod = importlib.import_module(module)
        mispmod.register(mhandlers, loaded_modules)

    service = [(r'/modules', ListModules), (r'/query', QueryModule)]

    application = tornado.web.Application(service)
    try:
        application.listen(port, address=listen)
    except Exception as e:
        if e.errno == 98:
            pids = psutil.pids()
            for pid in pids:
                p = psutil.Process(pid)
                if p.name() == "misp-modules":
                    print("\n\n\n")
                    print(e)
                    print("\nmisp-modules is still running as PID: {}\n".format(pid))
                    print("Please kill accordingly:")
                    print("sudo kill {}".format(pid))
                    sys.exit(-1)
            print(e)
            print("misp-modules might still be running.")

    log.info('MISP modules server started on {0} port {1}'.format(listen, port))
    if args.t:
        log.info('MISP modules started in test-mode, quitting immediately.')
        sys.exit()
    try:
        IOLoop.instance().start()
    finally:
        IOLoop.instance().stop()

    return 0


if __name__ == '__main__':
    sys.exit(main())
