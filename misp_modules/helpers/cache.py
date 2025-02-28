#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# MISP modules helper - cache
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

import hashlib
import os
import typing

import redis

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 6379
DEFAULT_DATABASE = 0
DEFAULT_TIMEOUT = 5


def create_connection(timeout: int = DEFAULT_TIMEOUT, **kwargs) -> redis.Redis:
    return redis.Redis(
        host=os.getenv("REDIS_BACKEND", DEFAULT_HOST),
        password=os.getenv("REDIS_PW"),
        port=int(os.getenv("REDIS_PORT", DEFAULT_PORT)),
        db=int(os.getenv("REDIS_DATABASE", DEFAULT_DATABASE)),
        socket_timeout=timeout,
        socket_connect_timeout=timeout,
        **kwargs,
    )


def selftest(enable: bool = True) -> typing.Union[str, None]:
    if not enable:
        return None
    try:
        r = create_connection(timeout=3)
        r.ping()
    except Exception:
        return "Redis not running or not installed. Helper will be disabled."
    else:
        return None


def get(modulename=None, query=None, value=None, debug=False):
    if modulename is None or query is None:
        return False
    r = create_connection(decode_responses=True)
    h = hashlib.sha1()
    h.update(query.encode("UTF-8"))
    hv = h.hexdigest()
    key = "m:{}:{}".format(modulename, hv)

    if not r.exists(key):
        if debug:
            print("Key {} added in cache".format(key))
        r.setex(key, 86400, value)
    else:
        if debug:
            print("Cache hit with Key {}".format(key))

    return r.get(key)


def flush():
    r = create_connection(decode_responses=True)
    return r.flushdb()


if __name__ == "__main__":
    import sys

    if selftest() is not None:
        sys.exit()
    else:
        print("Selftest ok")
    v = get(modulename="testmodule", query="abcdef", value="barfoo", debug=True)
    if v == "barfoo":
        print("Cache ok")
    v = get(modulename="testmodule", query="abcdef")
    print(v)
    v = get(modulename="testmodule")
    if not v:
        print("Failed ok")
    if flush():
        print("Cache flushed ok")
