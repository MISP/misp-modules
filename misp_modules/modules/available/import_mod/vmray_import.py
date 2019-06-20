#!/usr/bin/env python3

'''
Import VMRay results.

This version supports import from different analyze jobs, starting from one sample
(the supplied sample_id).

Requires "vmray_rest_api"

The expansion module vmray_submit and import module vmray_import are a two step
process to import data from VMRay.
You can automate this by setting the PyMISP example script 'vmray_automation'
as a cron job

'''

import json

from ._vmray.vmray_rest_api import VMRayRESTAPI

misperrors = {'error': 'Error'}
inputSource = []
moduleinfo = {'version': '0.2', 'author': 'Koen Van Impe',
              'description': 'Import VMRay results',
              'module-type': ['import']}
userConfig = {'include_analysisid': {'type': 'Boolean',
                                     'message': 'Include link to VMRay analysis'
                                     },
              'include_analysisdetails': {'type': 'Boolean',
                                          'message': 'Include (textual) analysis details'
                                          },
              'include_vtidetails': {'type': 'Boolean',
                                     'message': 'Include VMRay Threat Identifier (VTI) rules'
                                     },
              'include_imphash_ssdeep': {'type': 'Boolean',
                                         'message': 'Include imphash and ssdeep'
                                         },
              'include_extracted_files': {'type': 'Boolean',
                                          'message': 'Include extracted files section'
                                          },

              'sample_id': {'type': 'Integer',
                            'errorMessage': 'Expected a sample ID',
                            'message': 'The VMRay sample_id'
                            }
              }

moduleconfig = ['apikey', 'url', 'wait_period']


def handler(q=False):
    global include_analysisid, include_imphash_ssdeep, include_extracted_files, include_analysisdetails, include_vtidetails, include_static_to_ids

    if q is False:
        return False
    request = json.loads(q)

    include_analysisid = bool(int(request["config"].get("include_analysisid")))
    include_imphash_ssdeep = bool(int(request["config"].get("include_imphash_ssdeep")))
    include_extracted_files = bool(int(request["config"].get("include_extracted_files")))
    include_analysisdetails = bool(int(request["config"].get("include_extracted_files")))
    include_vtidetails = bool(int(request["config"].get("include_vtidetails")))
    include_static_to_ids = True

    # print("include_analysisid: %s  include_imphash_ssdeep: %s  include_extracted_files: %s  include_analysisdetails: %s  include_vtidetails: %s" % ( include_analysisid, include_imphash_ssdeep, include_extracted_files, include_analysisdetails, include_vtidetails))

    sample_id = int(request["config"].get("sample_id"))

    if (request["config"].get("apikey") is None) or (request["config"].get("url") is None):
        misperrors["error"] = "Missing API key or server URL (hint: try cloud.vmray.com)"
        return misperrors

    if sample_id > 0:
        try:
            api = VMRayRESTAPI(request["config"].get("url"), request["config"].get("apikey"), False)
            vmray_results = {'results': []}

            # Get all information on the sample, returns a set of finished analyze jobs
            data = vmrayGetInfoAnalysis(api, sample_id)
            if data["data"]:
                for analysis in data["data"]:
                    analysis_id = int(analysis["analysis_id"])
                    if analysis_id > 0:
                        # Get the details for an analyze job
                        analysis_data = vmrayDownloadAnalysis(api, analysis_id)

                        if analysis_data:
                            if include_analysisdetails and "analysis_details" in analysis_data:
                                analysis_details = vmrayAnalysisDetails(analysis_data["analysis_details"], analysis_id)
                                if analysis_details and len(analysis_details["results"]) > 0:
                                    vmray_results = {'results': vmray_results["results"] + analysis_details["results"]}

                            if "classifications" in analysis_data:
                                classifications = vmrayClassifications(analysis_data["classifications"], analysis_id)
                                if classifications and len(classifications["results"]) > 0:
                                    vmray_results = {'results': vmray_results["results"] + classifications["results"]}

                            if include_extracted_files and "extracted_files" in analysis_data:
                                extracted_files = vmrayExtractedfiles(analysis_data["extracted_files"])
                                if extracted_files and len(extracted_files["results"]) > 0:
                                    vmray_results = {'results': vmray_results["results"] + extracted_files["results"]}

                            if include_vtidetails and "vti" in analysis_data:
                                vti = vmrayVti(analysis_data["vti"])
                                if vti and len(vti["results"]) > 0:
                                    vmray_results = {'results': vmray_results["results"] + vti["results"]}

                            if "artifacts" in analysis_data:
                                artifacts = vmrayArtifacts(analysis_data["artifacts"])
                                if artifacts and len(artifacts["results"]) > 0:
                                    vmray_results = {'results': vmray_results["results"] + artifacts["results"]}

                            if include_analysisid:
                                a_id = {'results': []}
                                url1 = request["config"].get("url") + "/user/analysis/view?from_sample_id=%u" % sample_id
                                url2 = "&id=%u" % analysis_id
                                url3 = "&sub=%2Freport%2Foverview.html"
                                a_id["results"].append({"values": url1 + url2 + url3, "types": "link"})
                                vmray_results = {'results': vmray_results["results"] + a_id["results"]}

                # Clean up (remove doubles)
                if len(vmray_results["results"]) > 0:
                    vmray_results = vmrayCleanup(vmray_results)
                    return vmray_results
                else:
                    misperrors['error'] = "No vti_results returned or jobs not finished"
                    return misperrors
            else:
                if "result" in data:
                    if data["result"] == "ok":
                        return vmray_results

                # Fallback
                misperrors['error'] = "Unable to fetch sample id %u" % (sample_id)
                return misperrors
        except Exception as e:  # noqa
            misperrors['error'] = "Unable to access VMRay API : %s" % (e)
            return misperrors
    else:
        misperrors['error'] = "Not a valid sample id"
        return misperrors


def introspection():
    modulesetup = {}
    try:
        userConfig
        modulesetup['userConfig'] = userConfig
    except NameError:
        pass
    try:
        inputSource
        modulesetup['inputSource'] = inputSource
    except NameError:
        pass
    return modulesetup


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo


def vmrayGetInfoAnalysis(api, sample_id):
    ''' Get information from a sample, returns a set of analyzed reports'''

    if sample_id:
        data = api.call("GET", "/rest/analysis/sample/%u" % (sample_id), raw_data=True)
        return json.loads(data.read().decode())
    else:
        return False


def vmrayDownloadAnalysis(api, analysis_id):
    ''' Get the details from an analysis'''
    if analysis_id:
        try:
            data = api.call("GET", "/rest/analysis/%u/archive/logs/summary.json" % (analysis_id), raw_data=True)
            return json.loads(data.read().decode())
        except Exception as e:  # noqa
            misperrors['error'] = "Unable to download summary.json for analysis %s" % (analysis_id)
            return misperrors
    else:
        return False


def vmrayVti(vti):
    '''VMRay Threat Identifier (VTI) rules that matched for this analysis'''

    if vti:
        r = {'results': []}
        for rule in vti:
            if rule == "vti_rule_matches":
                vti_rule = vti["vti_rule_matches"]
                for el in vti_rule:
                    if "operation_desc" in el:
                        comment = ""
                        types = ["text"]
                        values = el["operation_desc"]
                        r['results'].append({'types': types, 'values': values, 'comment': comment})

        return r

    else:
        return False


def vmrayExtractedfiles(extracted_files):
    ''' Information about files which were extracted during the analysis, such as files that were created, modified, or embedded by the malware'''

    if extracted_files:
        r = {'results': []}

        for file in extracted_files:
            if "file_type" and "norm_filename" in file:
                comment = "%s - %s" % (file["file_type"], file["norm_filename"])
            else:
                comment = ""

            if "norm_filename" in file:
                attr_filename_c = file["norm_filename"].rsplit("\\", 1)
                if len(attr_filename_c) > 1:
                    attr_filename = attr_filename_c[len(attr_filename_c) - 1]
                else:
                    attr_filename = "vmray_sample"
            else:
                attr_filename = "vmray_sample"

            if "md5_hash" in file and file["md5_hash"] is not None:
                r['results'].append({'types': ["filename|md5"], 'values': '{}|{}'.format(attr_filename, file["md5_hash"]), 'comment': comment, 'categories': ['Payload delivery', 'Artifacts dropped'], 'to_ids': include_static_to_ids})
            if include_imphash_ssdeep and "imp_hash" in file and file["imp_hash"] is not None:
                r['results'].append({'types': ["filename|imphash"], 'values': '{}|{}'.format(attr_filename, file["imp_hash"]), 'comment': comment, 'categories': ['Payload delivery', 'Artifacts dropped'], 'to_ids': include_static_to_ids})
            if "sha1_hash" in file and file["sha1_hash"] is not None:
                r['results'].append({'types': ["filename|sha1"], 'values': '{}|{}'.format(attr_filename, file["sha1_hash"]), 'comment': comment, 'categories': ['Payload delivery', 'Artifacts dropped'], 'to_ids': include_static_to_ids})
            if "sha256_hash" in file and file["sha256_hash"] is not None:
                r['results'].append({'types': ["filename|sha256"], 'values': '{}|{}'.format(attr_filename, file["sha256_hash"]), 'comment': comment, 'categories': ['Payload delivery', 'Artifacts dropped'], 'to_ids': include_static_to_ids})
            if include_imphash_ssdeep and "ssdeep_hash" in file and file["ssdeep_hash"] is not None:
                r['results'].append({'types': ["filename|ssdeep"], 'values': '{}|{}'.format(attr_filename, file["ssdeep_hash"]), 'comment': comment, 'categories': ['Payload delivery', 'Artifacts dropped'], 'to_ids': include_static_to_ids})

        return r

    else:
        return False


def vmrayClassifications(classification, analysis_id):
    ''' List the classifications, tag them on a "text" attribute '''

    if classification:
        r = {'results': []}
        types = ["text"]
        comment = ""
        values = "Classification : %s " % (", ".join(str(x) for x in classification))
        r['results'].append({'types': types, 'values': values, 'comment': comment})

        return r

    else:
        return False


def vmrayAnalysisDetails(details, analysis_id):
    ''' General information about the analysis information '''

    if details:
        r = {'results': []}
        types = ["text"]
        comment = ""
        if "execution_successful" in details:
            values = "Analysis %s : execution_successful : %s " % (analysis_id, str(details["execution_successful"]))
            r['results'].append({'types': types, 'values': values, 'comment': comment})
        if "termination_reason" in details:
            values = "Analysis %s : termination_reason : %s " % (analysis_id, str(details["termination_reason"]))
            r['results'].append({'types': types, 'values': values, 'comment': comment})
        if "result_str" in details:
            values = "Analysis %s : result : %s " % (analysis_id, details["result_str"])
            r['results'].append({'types': types, 'values': values, 'comment': comment})

        return r

    else:
        return False


def vmrayArtifacts(patterns):
    ''' IOCs that were seen during the analysis '''

    if patterns:
        r = {'results': []}
        y = {'results': []}

        for pattern in patterns:
            if pattern == "domains":
                for el in patterns[pattern]:
                    values = el["domain"]
                    types = ["domain", "hostname"]
                    if "sources" in el:
                        sources = el["sources"]
                        comment = "Found in: " + ", ".join(str(x) for x in sources)
                    else:
                        comment = ""
                    r['results'].append({'types': types, 'values': values, 'comment': comment, 'to_ids': include_static_to_ids})
            if pattern == "files":
                for el in patterns[pattern]:
                    filename_values = el["filename"]
                    attr_filename_c = filename_values.rsplit("\\", 1)
                    if len(attr_filename_c) > 1:
                        attr_filename = attr_filename_c[len(attr_filename_c) - 1]
                    else:
                        attr_filename = ""
                    filename_types = ["filename"]
                    filename_operations = el["operations"]
                    comment = "File operations: " + ", ".join(str(x) for x in filename_operations)
                    r['results'].append({'types': filename_types, 'values': filename_values, 'comment': comment})

                    # Run through all hashes
                    if "hashes" in el:
                        for hash in el["hashes"]:
                            if "md5_hash" in hash and hash["md5_hash"] is not None:
                                r['results'].append({'types': ["filename|md5"], 'values': '{}|{}'.format(attr_filename, hash["md5_hash"]), 'comment': comment, 'categories': ['Payload delivery', 'Artifacts dropped'], 'to_ids': include_static_to_ids})
                            if include_imphash_ssdeep and "imp_hash" in hash and hash["imp_hash"] is not None:
                                r['results'].append({'types': ["filename|imphash"], 'values': '{}|{}'.format(attr_filename, hash["imp_hash"]), 'comment': comment, 'categories': ['Payload delivery', 'Artifacts dropped'], 'to_ids': include_static_to_ids})
                            if "sha1_hash" in hash and hash["sha1_hash"] is not None:
                                r['results'].append({'types': ["filename|sha1"], 'values': '{}|{}'.format(attr_filename, hash["sha1_hash"]), 'comment': comment, 'categories': ['Payload delivery', 'Artifacts dropped'], 'to_ids': include_static_to_ids})
                            if "sha256_hash" in hash and hash["sha256_hash"] is not None:
                                r['results'].append({'types': ["filename|sha256"], 'values': '{}|{}'.format(attr_filename, hash["sha256_hash"]), 'comment': comment, 'categories': ['Payload delivery', 'Artifacts dropped'], 'to_ids': include_static_to_ids})
                            if include_imphash_ssdeep and "ssdeep_hash" in hash and hash["ssdeep_hash"] is not None:
                                r['results'].append({'types': ["filename|ssdeep"], 'values': '{}|{}'.format(attr_filename, hash["ssdeep_hash"]), 'comment': comment, 'categories': ['Payload delivery', 'Artifacts dropped'], 'to_ids': include_static_to_ids})
            if pattern == "ips":
                for el in patterns[pattern]:
                    values = el["ip_address"]
                    types = ["ip-dst"]
                    if "sources" in el:
                        sources = el["sources"]
                        comment = "Found in: " + ", ".join(str(x) for x in sources)
                    else:
                        comment = ""

                    r['results'].append({'types': types, 'values': values, 'comment': comment, 'to_ids': include_static_to_ids})
            if pattern == "mutexes":
                for el in patterns[pattern]:
                    values = el["mutex_name"]
                    types = ["mutex"]
                    if "operations" in el:
                        sources = el["operations"]
                        comment = "Operations: " + ", ".join(str(x) for x in sources)
                    else:
                        comment = ""

                    r['results'].append({'types': types, 'values': values, 'comment': comment, 'to_ids': include_static_to_ids})
            if pattern == "registry":
                for el in patterns[pattern]:
                    values = el["reg_key_name"]
                    types = ["regkey"]
                    include_static_to_ids_tmp = include_static_to_ids
                    if "operations" in el:
                        sources = el["operations"]
                        if sources == ["access"]:
                            include_static_to_ids_tmp = False
                        comment = "Operations: " + ", ".join(str(x) for x in sources)
                    else:
                        comment = ""

                    r['results'].append({'types': types, 'values': values, 'comment': comment, 'to_ids': include_static_to_ids_tmp})
            if pattern == "urls":
                for el in patterns[pattern]:
                    values = el["url"]
                    types = ["url"]
                    if "operations" in el:
                        sources = el["operations"]
                        comment = "Operations: " + ", ".join(str(x) for x in sources)
                    else:
                        comment = ""

                    r['results'].append({'types': types, 'values': values, 'comment': comment, 'to_ids': include_static_to_ids})

        # Remove doubles
        for el in r["results"]:
            if el not in y["results"]:
                y["results"].append(el)
        return y

    else:
        return False


def vmrayCleanup(x):
    ''' Remove doubles'''
    y = {'results': []}
    for el in x["results"]:
        if el not in y["results"]:
            y["results"].append(el)
    return y
