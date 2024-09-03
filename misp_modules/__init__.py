#!/usr/bin/env python3
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
import logging
import fnmatch
import argparse
import re
import datetime
import psutil
import pkgutil
import platform
import typing

try:
    import orjson as json
except ImportError:
    import json

import tornado.web
import tornado.process
from tornado.ioloop import IOLoop
from tornado.concurrent import run_on_executor
from concurrent.futures import ThreadPoolExecutor
from pymisp import pymisp_json_default


import warnings
warnings.filterwarnings("ignore", category=SyntaxWarning)


LIBFAUP_PATHS = [
    "/usr/local/lib/",
    "/usr/lib/",
    "/opt/local/lib/",
]

ARCH_TO_EXTENSION = {
    "linux": "so",
    "darwin": "dylib",
}


def _get_libfaup_path(lib_path: str) -> str:
    extension = ARCH_TO_EXTENSION.get(platform.system().lower(), "lib")
    return f"{lib_path.rstrip('/')}/libfaupl.{extension}"
    

def _replace_libfaup_path(module_path: str, libfaup_path: str) -> None:
    with open(module_path, "r") as f:
        file_data = f.read()
    file_data = re.sub(r"cdll.LoadLibrary\(.*\)", f"cdll.LoadLibrary(\"{libfaup_path}\")", file_data)
    with open(module_path, "w") as f:
        f.write(file_data)


def _try_pyfaup_import(lib_path: typing.Optional[str]) -> None:
    package = pkgutil.get_loader("pyfaup")
    if not package:
        return
    if lib_path:
        _replace_libfaup_path(package.path, _get_libfaup_path(lib_path))
    importlib.import_module("pyfaup")

        
for lib_path in [None, *LIBFAUP_PATHS]:
    try:
        _try_pyfaup_import(lib_path)
        break
    except OSError:
        continue

try:
    from .modules import *  # noqa
    HAS_PACKAGE_MODULES = True
except Exception as e:
    logging.exception(e)
    HAS_PACKAGE_MODULES = False

try:
    from .helpers import *  # noqa
    HAS_PACKAGE_HELPERS = True
except Exception as e:
    logging.exception(e)
    HAS_PACKAGE_HELPERS = False

log = logging.getLogger('misp-modules')


def handle_signal(sig, frame):
    IOLoop.instance().add_callback_from_signal(IOLoop.instance().stop)


def init_logger(debug=False):
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    # Enable access logs
    access_log = logging.getLogger('tornado.access')
    access_log.propagate = False
    access_log.setLevel(logging.INFO)
    access_log.addHandler(handler)

    # Set application log
    log.addHandler(handler)
    log.propagate = False
    log.setLevel(logging.DEBUG if debug else logging.INFO)


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
                log.info(f'Helpers loaded {filename}')
            else:
                log.warning(f'Helpers failed {filename} due to {selftest}')


def load_package_helpers():
    if not HAS_PACKAGE_HELPERS:
        log.error('Unable to load MISP helpers from package.')
        sys.exit(1)
    mhandlers = {}
    helpers = []
    for path, helper in sys.modules.items():
        if not path.startswith('misp_modules.helpers.'):
            continue
        helper_name = path.replace('misp_modules.helpers.', '')
        mhandlers[helper_name] = helper
        selftest = mhandlers[helper_name].selftest()
        if selftest is None:
            helpers.append(helper_name)
            log.info(f'Helper loaded {helper_name}')
        else:
            log.warning(f'Helpers failed {helper_name} due to {selftest}')
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
            module_name = filename.split(".")[0]
            module_type = os.path.split(mod_dir)[1]
            try:
                mhandlers[module_name] = importlib.import_module(os.path.basename(root) + '.' + module_name)
            except Exception as e:
                log.warning(f'MISP modules {module_name} failed due to {e}')
                continue
            modules.append(module_name)
            log.info(f'MISP modules {module_name} imported')
            mhandlers['type:' + module_name] = module_type
    return mhandlers, modules


def load_package_modules():
    if not HAS_PACKAGE_MODULES:
        log.error('Unable to load MISP modules from package.')
        sys.exit(1)
    mhandlers = {}
    modules = []
    for path, module in sys.modules.items():
        r = re.findall(r"misp_modules[.]modules[.](\w+)[.]([^_]\w+)", path)
        if r and len(r[0]) == 2:
            module_type, module_name = r[0]
            mhandlers[module_name] = module
            modules.append(module_name)
            log.info(f'MISP modules {module_name} imported')
            mhandlers['type:' + module_name] = module_type
    return mhandlers, modules


class Healthcheck(tornado.web.RequestHandler):
    def get(self):
        self.write(b'{"status": true}')


class ListModules(tornado.web.RequestHandler):
    global loaded_modules
    global mhandlers

    _cached_json = None

    def get(self):
        if not self._cached_json:
            ret = []
            for module_name in loaded_modules:
                ret.append({
                    'name': module_name,
                    'type': mhandlers['type:' + module_name],
                    'mispattributes': mhandlers[module_name].introspection(),
                    'meta': mhandlers[module_name].version()
                })
            self._cached_json = json.dumps(ret)

        log.debug('MISP ListModules request')
        self.write(self._cached_json)


class QueryModule(tornado.web.RequestHandler):

    # Default value in Python 3.5
    # https://docs.python.org/3/library/concurrent.futures.html#concurrent.futures.ThreadPoolExecutor
    nb_threads = tornado.process.cpu_count() * 5
    executor = ThreadPoolExecutor(nb_threads)

    @run_on_executor
    def run_request(self, module_name, json_payload, dict_payload):
        log.debug('MISP QueryModule %s request %s', module_name, json_payload)
        module = mhandlers[module_name]
        if getattr(module, "dict_handler", None):
            # New method that avoids double JSON decoding, new modules should define dict_handler
            response = module.dict_handler(request=dict_payload)
        else:
            response = module.handler(q=json_payload)
        return json.dumps(response, default=pymisp_json_default)

    @tornado.gen.coroutine
    def post(self):
        try:
            json_payload = self.request.body
            dict_payload = json.loads(json_payload)
            if dict_payload.get('timeout'):
                timeout = datetime.timedelta(seconds=int(dict_payload.get('timeout')))
            else:
                timeout = datetime.timedelta(seconds=300)
            future = self.run_request(dict_payload['module'], json_payload, dict_payload)
            response = yield tornado.gen.with_timeout(timeout, future)
            self.write(response)
        except tornado.gen.TimeoutError:
            log.warning('Timeout on {}'.format(dict_payload['module']))
            self.write(json.dumps({'error': 'Timeout.'}))
        except Exception:
            self.write(json.dumps({'error': 'Something went wrong, look in the server logs for details'}))
            log.exception('Something went wrong when processing query request')
        finally:
            self.finish()


def _launch_from_current_dir():
    log.info('Launch MISP modules server from current directory.')
    os.chdir(os.path.dirname(__file__))
    modulesdir = 'modules'
    helpersdir = 'helpers'
    load_helpers(helpersdir=helpersdir)
    return load_modules(modulesdir)


def main():
    global mhandlers
    global loaded_modules
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    arg_parser = argparse.ArgumentParser(description='misp-modules server', formatter_class=argparse.RawTextHelpFormatter)
    arg_parser.add_argument('-t', '--test', default=False, action='store_true', help='Test mode')
    arg_parser.add_argument('-s', '--system', default=False, action='store_true', help='Run a system install (package installed via pip)')
    arg_parser.add_argument('-d', '--debug', default=False, action='store_true', help='Enable debugging')
    arg_parser.add_argument('-p', '--port', default=6666, help='misp-modules TCP port (default 6666)')
    arg_parser.add_argument('-l', '--listen', default='localhost', help='misp-modules listen address (default localhost)')
    arg_parser.add_argument('-m', default=[], action='append', help='Register a custom module')
    arg_parser.add_argument('--devel', default=False, action='store_true', help='''Start in development mode, enable debug, start only the module(s) listed in -m.\nExample: -m misp_modules.modules.expansion.bgpranking''')
    args = arg_parser.parse_args()

    if args.devel:
        init_logger(debug=True)
        log.info('Launch MISP modules server in development mode. Enable debug, load a list of modules is -m is used.')
        if args.m:
            mhandlers = {}
            modules = []
            for module in args.m:
                splitted = module.split(".")
                modulename = splitted[-1]
                moduletype = splitted[2]
                mhandlers[modulename] = importlib.import_module(module)
                mhandlers['type:' + modulename] = moduletype
                modules.append(modulename)
                log.info(f'MISP modules {modulename} imported')
        else:
            mhandlers, loaded_modules = _launch_from_current_dir()
    else:
        init_logger(debug=args.debug)
        if args.system:
            log.info('Launch MISP modules server from package.')
            load_package_helpers()
            mhandlers, loaded_modules = load_package_modules()
        else:
            mhandlers, loaded_modules = _launch_from_current_dir()

        for module in args.m:
            mispmod = importlib.import_module(module)
            mispmod.register(mhandlers, loaded_modules)

    service = [
        (r'/modules', ListModules),
        (r'/query', QueryModule),
        (r'/healthcheck', Healthcheck),
    ]

    application = tornado.web.Application(service)
    try:
        server = tornado.httpserver.HTTPServer(application, max_buffer_size=1073741824)  # buffer size increase when large MISP event are submitted - GH issue 662
        server.listen(args.port, args.listen)
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
                    return 1
            print(e)
            print("misp-modules might still be running.")
        else:
            log.exception(f"Could not listen on {args.listen}:{args.port}")
            return 1

    log.info(f'MISP modules server started on {args.listen} port {args.port}')
    if args.test:
        log.info('MISP modules started in test-mode, quitting immediately.')
        return 0
    try:
        IOLoop.instance().start()
    finally:
        IOLoop.instance().stop()

    return 0


if __name__ == '__main__':
    sys.exit(main())
