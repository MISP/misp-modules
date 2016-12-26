#!/usr/bin/env python3

'''
Submit sample to  VMRay.

Submit a sample to VMRay

TODO:
 # Deal with archive submissions

'''

import json
import base64

import io
import zipfile

from ._vmray.vmray_rest_api import VMRayRESTAPI

misperrors = {'error': 'Error'}
mispattributes = {'input': ['attachment', 'malware-sample'], 'output': ['text', 'sha1', 'sha256', 'md5', 'link']}
moduleinfo = {'version': '0.2', 'author': 'Koen Van Impe',
              'description': 'Submit a sample to VMRay',
              'module-type': ['expansion']}
moduleconfig = ['apikey', 'url', 'shareable', 'do_not_reanalyze', 'do_not_include_vmrayjobids']


include_vmrayjobids = False


def handler(q=False):
    global include_vmrayjobids

    if q is False:
        return False
    request = json.loads(q)

    try:
        data = request.get("data")
        if 'malware-sample' in request:
            # malicious samples are encrypted with zip (password infected) and then base64 encoded
            sample_filename = request.get("malware-sample").split("|",1)[0]
            data = base64.b64decode(data)
            fl = io.BytesIO(data)
            zf = zipfile.ZipFile(fl)
            sample_hashname = zf.namelist()[0]
            data = zf.read(sample_hashname,b"infected")
            zf.close()
        elif 'attachment' in request:
            # All attachments get base64 encoded
            sample_filename = request.get("attachment")
            data = base64.b64decode(data)

        else:
            misperrors['error'] = "No malware sample or attachment supplied"
            return misperrors
    except:
        misperrors['error'] = "Unable to process submited sample data"
        return misperrors

    if (request["config"].get("apikey") is None) or (request["config"].get("url") is None):
        misperrors["error"] = "Missing API key or server URL (hint: try cloud.vmray.com)"
        return misperrors

    api = VMRayRESTAPI(request["config"].get("url"), request["config"].get("apikey"), False)

    shareable = request["config"].get("shareable")
    do_not_reanalyze = request["config"].get("do_not_reanalyze")
    do_not_include_vmrayjobids = request["config"].get("do_not_include_vmrayjobids")

    # Do we want the sample to be shared?
    if shareable == "True":
        shareable = True
    else:
        shareable = False

    # Always reanalyze the sample?
    if do_not_reanalyze == "True":
        do_not_reanalyze = True
    else:
        do_not_reanalyze = False
    reanalyze = not do_not_reanalyze

    # Include the references to VMRay job IDs
    if do_not_include_vmrayjobids == "True":
        do_not_include_vmrayjobids = True
    else:
        do_not_include_vmrayjobids = False
    include_vmrayjobids = not do_not_include_vmrayjobids

    if data and sample_filename:
        args = {}
        args["shareable"] = shareable
        args["sample_file"] = {'data': io.BytesIO(data), 'filename': sample_filename}
        args["reanalyze"] = reanalyze

        try:
            vmraydata = vmraySubmit(api, args)
            if vmraydata["errors"]:
                misperrors['error'] = "VMRay: %s" % vmraydata["errors"][0]["error_msg"]
                return misperrors
            else:
                return vmrayProcess(vmraydata)
        except:
            misperrors['error'] = "Problem when calling API."
            return misperrors
    else:
        misperrors['error'] = "No sample data or filename."
        return misperrors


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo


def vmrayProcess(vmraydata):
    ''' Process the JSON file returned by vmray'''
    if vmraydata:
        try:
            submissions = vmraydata["submissions"][0]
            jobs = vmraydata["jobs"]

            # Result received?
            if submissions and jobs:
                r = {'results': []}
                r["results"].append({"types": "md5", "values": submissions["submission_sample_md5"]})
                r["results"].append({"types": "sha1", "values": submissions["submission_sample_sha1"]})
                r["results"].append({"types": "sha256", "values": submissions["submission_sample_sha256"]})
                r["results"].append({"types": "text", "values": "VMRay Sample ID: %s" % submissions["submission_sample_id"]})
                r["results"].append({"types": "text", "values": "VMRay Submission ID: %s" % submissions["submission_id"]})
                r["results"].append({"types": "text", "values": "VMRay Submission Sample IP: %s" % submissions["submission_ip_ip"]})
                r["results"].append({"types": "link", "values": submissions["submission_webif_url"]})

                # Include data from different jobs
                if include_vmrayjobids:
                    for job in jobs:
                        job_id = job["job_id"]
                        job_vm_name = job["job_vm_name"]
                        job_configuration_name = job["job_configuration_name"]
                        r["results"].append({"types": "text", "values": "VMRay Job ID %s (%s - %s)" % (job_id, job_vm_name, job_configuration_name)})
                return r
            else:
                misperrors['error'] = "No valid results returned."
                return misperrors
        except:
            misperrors['error'] = "No valid submission data returned."
            return misperrors
    else:
        misperrors['error'] = "Unable to parse results."
        return misperrors


def vmraySubmit(api, args):
    ''' Submit the sample to VMRay'''
    vmraydata = api.call("POST", "/rest/sample/submit", args)
    return vmraydata
