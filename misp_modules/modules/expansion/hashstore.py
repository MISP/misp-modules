#!/usr/bin/env python3
# -*- coding: utf-8 -*
import json, redis, hashlib
# TODO : test sha256 len

misperrors = {'error': 'Error'}
mispattributes = {'input': ['hashs', 'values'], 'output': ['bool', 'uuid']}
moduleinfo = {'version': '0.1', 'author': 'Tristan Métayer',
              'description': 'Is this hashs (sha256) or stric values in misp database ?',
              'module-type': ['expansion', 'hover']}

moduleconfig = ['hashstore_host', 'hashstore_port', 'hashstore_db']

def exists(store, keys, return_uuid=False, quick_search=False):
    if quick_search is False:
        if return_uuid is False:
            if isinstance(keys, str):
                return {keys: store.exists(keys)}
            return [{key: store.exists(key)} for key in keys]
        else:
            if isinstance(keys, str):
                return {keys: list(store.smembers(keys))}
            return [{key: list(store.smembers(key))} for key in keys]
    else:
        with store.pipeline() as pipe:
            if isinstance(keys, str):
                pipe.exists(keys)
            else :
                for key in keys:
                    pipe.exists(key)
            return pipe.execute()


def handler(q=False):
    if q is False:
        return False
    q = json.loads(q)

    quick_search = False
    return_uuid = False
    results = {}

    # Test if there are some hashs or values in payload
    if q.get('hashs') is False and q.get('values') is False:
        misperrors['error'] = "No hashs of values in post data"
        return misperrors

    if q.get('quick_search'):
        quick_search = q['quick_search']

    if q.get('return_uuid'):
        return_uuid = q['return_uuid']

    # default redis value
    paramRedis = {
        'host': '127.0.0.1',
        'port': 6379,
        'db': 7,
        'decode_responses': True,
        'encoding' : 'utf-8'
    }
    if q.get('config'):
        if q['config'].get('hashstore_host'):
            paramRedis['host'] = q['config'].get('hashstore_host')
        if q['config'].get('hashstore_port'):
            paramRedis['port'] = q['config'].get('hashstore_port')
        if q['config'].get('hashstore_db'):
            paramRedis['db'] = q['config'].get('hashstore_db')

    # Connect to redis
    store = redis.Redis(**paramRedis)
    

    if q.get('hashs'):
        results['hashs'] = exists(store, q['hashs'], return_uuid, quick_search)

    if q.get('values'):
        hashFromValue = None
        if isinstance(q['values'], str):
            hashFromValue = hashlib.sha256(q['values'].encode('utf-8')).hexdigest()
        else:
            hashFromValue = [hashlib.sha256(x.encode('utf-8')).hexdigest() for x in q['values']]
        results['hash_values'] = exists(store, hashFromValue, return_uuid, quick_search)

    return {'results':results}



def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
