# -*- coding: utf-8 -*-
import json

from assemblyline_client import Client, ClientError
from urllib.parse import urljoin


moduleinfo = {"version": 1, "author": "Christian Studer", "module-type": ["expansion"],
              "description": "Submit files or URLs to AssemblyLine"}
moduleconfig = ["apiurl", "user_id", "apikey", "password"]
mispattributes = {"input": ["attachment", "malware-sample", "url"],
                  "output": ["link"]}


def parse_config(apiurl, user_id, config):
    error = {"error": "Please provide your AssemblyLine API key or Password."}
    if config.get('apikey'):
        try:
            return Client(apiurl, apikey=(user_id, config['apikey']))
        except ClientError as e:
            error['error'] = f'Error while initiating a connection with AssemblyLine: {e.__str__()}'
    if config.get('password'):
        try:
            return Client(apiurl, auth=(user_id, config['password']))
        except ClientError as e:
            error['error'] = f'Error while initiating a connection with AssemblyLine: {e.__str__()}'
    return error


def submit_content(client, filename, data):
    try:
        return client.submit(fname=filename, contents=data.encode())
    except Exception as e:
        return {'error': f'Error while submitting content to AssemblyLine: {e.__str__()}'}


def submit_request(client, request):
    if 'attachment' in request:
        return submit_content(client, request['attachment'], request['data'])
    if 'malware-sample' in request:
        return submit_content(client, request['malware-sample'].split('|')[0], request['data'])
    for feature in ('url', 'domain'):
        if feature in request:
            return submit_url(client, request[feature])
    return {"error": "No valid attribute type for this module has been provided."}


def submit_url(client, url):
    try:
        return client.submit(url=url)
    except Exception as e:
        return {'error': f'Error while submitting url to AssemblyLine: {e.__str__()}'}


def handler(q=False):
    if q is False:
        return q
    request = json.loads(q)
    if not request.get('config'):
        return {"error": "Missing configuration."}
    if not request['config'].get('apiurl'):
        return {"error": "No AssemblyLine server address provided."}
    apiurl = request['config']['apiurl']
    if not request['config'].get('user_id'):
        return {"error": "Please provide your AssemblyLine User ID."}
    user_id = request['config']['user_id']
    client = parse_config(apiurl, user_id, request['config'])
    if isinstance(client, dict):
        return client
    submission = submit_request(client, request)
    if 'error' in submission:
        return submission
    sid = submission['submission']['sid']
    return {
        "results": [{
            "types": "link",
            "categories": "External analysis",
            "values": urljoin(apiurl, f'submission_detail.html?sid={sid}')
        }]
    }


def introspection():
    return mispattributes


def version():
    moduleinfo["config"] = moduleconfig
    return moduleinfo
