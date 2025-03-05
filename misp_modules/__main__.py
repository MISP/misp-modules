#!/usr/bin/env python
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
import importlib
import logging
import os.path
import pathlib
import signal
import sys

logging.captureWarnings(True)

import argparse
import datetime
import importlib.resources
import importlib.util
import types
from concurrent.futures import ThreadPoolExecutor

import orjson
import pymisp
import tornado.process
import tornado.web
from tornado import concurrent as tornado_concurrent
from tornado import ioloop

import misp_modules

# See https://github.com/MISP/misp-modules/issues/662
MAX_BUFFER_SIZE = 1073741824

# Global variables
MODULES_HANDLERS = {}
HELPERS_HANDLERS = {}
LOGGER = logging.getLogger("misp-modules")

# Module that, if present, guarantees that the extra 'all' has been installed
DEGRADED_SENTINEL_MODULE = "yara"
DEGRADED_MESSAGE = [
    r"",
    r"__        ___    ____  _   _ ___ _   _  ____ _ _ _ ",
    r"\ \      / / \  |  _ \| \ | |_ _| \ | |/ ___| | | |",
    r" \ \ /\ / / _ \ | |_) |  \| || ||  \| | |  _| | | |",
    r"  \ V  V / ___ \|  _ <| |\  || || |\  | |_| |_|_|_|",
    r"   \_/\_/_/   \_\_| \_\_| \_|___|_| \_|\____(_|_|_)",
    r"",
    r"Since 'misp-modules' version 3, many dependencies are not installed by default. ",
    r"If you want to re-enable the old behavior, install the 'all' extra.",
    r"Use the command 'pip install misp-modules[all]'",
    r"",
]


def is_degraded_install() -> bool:
    """Whether the extra 'all' has been installed."""
    try:
        importlib.import_module(DEGRADED_SENTINEL_MODULE)
    except ImportError:
        return True
    else:
        return False


def warn_if_degraded() -> None:
    """Alert if the system is running in degraded mode."""
    if is_degraded_install():
        for line in DEGRADED_MESSAGE:
            LOGGER.warning(line)


def handle_signal(sig: int, frame: types.FrameType) -> None:
    """Handle the signal."""
    _ = sig, frame
    ioloop.IOLoop.instance().add_callback_from_signal(ioloop.IOLoop.instance().stop)


def init_logger(debug: bool = False) -> None:
    """Initialize the logger."""
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    # Enable access logs
    access_log = logging.getLogger("tornado.access")
    access_log.propagate = False
    access_log.setLevel(logging.INFO)
    access_log.addHandler(handler)

    # Configure warning logs
    warning_log = logging.getLogger("py.warnings")
    warning_log.propagate = False
    warning_log.setLevel(logging.ERROR)
    warning_log.addHandler(handler)

    # Set application log
    LOGGER.propagate = False
    LOGGER.setLevel(logging.DEBUG if debug else logging.INFO)
    LOGGER.addHandler(handler)


class VersionCheck(tornado.web.RequestHandler):
    """VersionCheck handler."""

    def get(self):
        LOGGER.debug("VersionCheck request")
        try:
            self.write(orjson.dumps({"version": misp_modules.get_version()}))
        except ValueError:
            self.send_error(500)


class HealthCheck(tornado.web.RequestHandler):
    """HealthCheck handler."""

    def get(self):
        LOGGER.debug("Healthcheck request")
        self.write(b'{"status": true}')


class ListModules(tornado.web.RequestHandler):
    """ListModules handler."""

    CACHE = None

    @classmethod
    def _build_handlers_data(cls) -> bytes:
        return orjson.dumps(
            [
                {
                    "name": module_name,
                    "type": MODULES_HANDLERS["type:" + module_name],
                    "mispattributes": MODULES_HANDLERS[module_name].introspection(),
                    "meta": MODULES_HANDLERS[module_name].version(),
                }
                for module_name in MODULES_HANDLERS
                if not module_name.startswith("type:")
            ]
        )

    def get(self):
        LOGGER.debug("ListModules request")
        if not self.CACHE:
            self.CACHE = self._build_handlers_data()
        self.write(self.CACHE)


class QueryModule(tornado.web.RequestHandler):
    """QueryModule handler."""

    DEFAULT_TIMEOUT = 300

    # Never go above 32
    executor = ThreadPoolExecutor(max_workers=min(32, tornado.process.cpu_count() * 5))

    @tornado_concurrent.run_on_executor
    def run_request(self, module_name, json_payload, dict_payload):
        LOGGER.debug("QueryModule %s request %s", module_name, json_payload)
        try:
            response = MODULES_HANDLERS[module_name].dict_handler(request=dict_payload)
        except AttributeError:
            response = MODULES_HANDLERS[module_name].handler(q=json_payload)
        return orjson.dumps(response, default=pymisp.pymisp_json_default)

    @tornado.gen.coroutine
    def post(self):
        json_payload = self.request.body
        dict_payload = orjson.loads(json_payload)
        timeout = datetime.timedelta(seconds=int(dict_payload.get("timeout", self.DEFAULT_TIMEOUT)))
        try:
            future = self.run_request(dict_payload["module"], json_payload, dict_payload)
            response = yield tornado.gen.with_timeout(timeout, future)
            self.write(response)
        except tornado.gen.TimeoutError:
            LOGGER.warning("Timeout on {}".format(dict_payload["module"]))
            self.write(orjson.dumps({"error": "Timeout."}))
        except Exception:
            self.write(orjson.dumps({"error": "Something went wrong, look in the server logs for details"}))
            LOGGER.exception("Something went wrong when processing query request")
        finally:
            self.finish()


def main():
    """Init function."""
    global HELPERS_HANDLERS
    global MODULES_HANDLERS

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    arg_parser = argparse.ArgumentParser(description="misp-modules", formatter_class=argparse.RawTextHelpFormatter)
    arg_parser.add_argument("-t", "--test", default=False, action="store_true", help="test mode")
    arg_parser.add_argument("-d", "--debug", default=False, action="store_true", help="enable debugging")
    arg_parser.add_argument("-p", "--port", type=int, default=6666, help="port (default 6666)")
    arg_parser.add_argument("-l", "--listen", default="localhost", help="address (default localhost)")
    arg_parser.add_argument("-c", "--custom", default=None, help="custom modules root")
    arg_parser.add_argument("-s", "--system", default=None, help="legacy option that now has no effect")
    args = arg_parser.parse_args()

    # Initialize
    init_logger(debug=args.debug)

    # Alert if needed
    warn_if_degraded()

    # Load libraries as root modules
    misp_modules.promote_lib_to_root()

    # Load modules
    for module_type, module in misp_modules.iterate_modules(
        importlib.resources.files(__package__).joinpath(misp_modules.MODULES_DIR)
    ):
        module_name = os.path.splitext(module.name)[0]
        absolute_module_name = ".".join([__package__, misp_modules.MODULES_DIR, module_type.name, module_name])
        try:
            imported_module = importlib.import_module(absolute_module_name)
        except ImportError as e:
            LOGGER.warning("MISP module %s (type=%s) failed: %s", module_name, module_type.name, e)
            continue
        MODULES_HANDLERS[module_name] = imported_module
        MODULES_HANDLERS[f"type:{module_name}"] = module_type.name
        LOGGER.info("MISP module %s (type=%s) imported", module_name, module_type.name)

    # Load custom modules
    if args.custom:
        LOGGER.info("Parsing custom modules from root directory: %s", args.custom)
        for module_type, module in misp_modules.iterate_modules(pathlib.Path(args.custom)):
            module_name = os.path.splitext(module.name)[0]
            try:
                imported_module = misp_modules.import_from_path(module_name, str(module_type.joinpath(module.name)))
            except ImportError as e:
                LOGGER.warning("CUSTOM MISP module %s (type=%s) failed: %s", module_name, module_type.name, e)
                continue
            MODULES_HANDLERS[module_name] = imported_module
            MODULES_HANDLERS[f"type:{module_name}"] = module_type.name
            LOGGER.info("CUSTOM MISP module %s (type=%s) imported", module_name, module_type.name)

    try:
        server = tornado.httpserver.HTTPServer(
            tornado.web.Application(
                [
                    (r"/modules", ListModules),
                    (r"/query", QueryModule),
                    (r"/healthcheck", HealthCheck),
                    (r"/version", VersionCheck),
                ]
            ),
            max_buffer_size=MAX_BUFFER_SIZE,
        )
        server.listen(args.port, args.listen)
    except OSError as e:
        if e.errno == 48 or e.errno == 98:
            LOGGER.exception("Could not listen on %s:%d", args.listen, args.port)
            if pid := misp_modules.get_misp_modules_pid():
                LOGGER.exception("Dangling 'misp-modules' with pid %d found", pid)
        else:
            LOGGER.exception("Unspecified OSError")
        raise
    except Exception:
        LOGGER.exception("Unspecified Exception")
        raise

    # Alert if needed again
    warn_if_degraded()

    LOGGER.info("MISP modules server started on %s:%d", args.listen, args.port)
    if args.test:
        LOGGER.info("MISP modules started in test-mode, quitting immediately.")
        return 0

    try:
        ioloop.IOLoop.instance().start()
    finally:
        ioloop.IOLoop.instance().stop()
        return 0


if __name__ == "__main__":
    sys.exit(main())
