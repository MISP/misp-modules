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

import redis
import hashlib

port = 6379
hostname = '127.0.0.1'
db = 5


def selftest(enable=True):
    if not enable:
        return False
    r = redis.StrictRedis(host=hostname, port=port, db=db)
    try:
        r.set('test', 'selftest')
    except:
        return 'Redis not running or not installed. Helper will be disabled.'


def get(modulename=None, query=None, value=None, debug=False):
    if (modulename is None or query is None or value is None):
        return False
    r = redis.StrictRedis(host=hostname, port=port, db=db)
    h = hashlib.sha1()
    h.update(query.encode('UTF-8'))
    hv = h.hexdigest()
    key = "m:"+modulename+":"+hv

    if not r.exists(key):
        if debug:
            print ("Key {} added in cache".format(key))
        r.set(key, value)
        r.expire(key, 86400)
    else:
        if debug:
            print ("Cache hit with Key {}".format(key))

    return r.get(key)


def flush():
    r = redis.StrictRedis(host=hostname, port=port, db=db)
    returncode = r.flushdb()
    return returncode

if __name__ == "__main__":
    import sys
    if selftest() is not None:
        sys.exit()
    else:
        print ("Selftest ok")
    v = get(modulename="testmodule", query="abcdef", value="barfoo", debug=True)
    if v == b'barfoo':
        print ("Cache ok")
    v = get(modulename="testmodule")
    if (not v):
        print ("Failed ok")
    if flush():
        print ("Cache flushed ok")
