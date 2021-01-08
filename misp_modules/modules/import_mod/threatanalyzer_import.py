'''
import
define mandatory

'''
import json
import base64
import re
import zipfile
import ipaddress
import io
import logging

misperrors = {'error': 'Error'}
userConfig = {}
inputSource = ['file']

moduleinfo = {'version': '0.10', 'author': 'Christophe Vandeplas',
              'description': 'Import for ThreatAnalyzer archive.zip/analysis.json files',
              'module-type': ['import']}

moduleconfig = []
log = logging.getLogger('misp-modules')

# FIXME - many hardcoded filters should be migrated to import regexes. See also https://github.com/MISP/MISP/issues/2712
# DISCLAIMER - This module is to be considered as experimental and needs much fine-tuning.
# more can be done with what's in the ThreatAnalyzer archive.zip


def handler(q=False):
    if q is False:
        return False
    results = []
    zip_starts = 'PK'
    request = json.loads(q)
    data = base64.b64decode(request['data'])

    if data[:len(zip_starts)].decode() == zip_starts:
        with zipfile.ZipFile(io.BytesIO(data), 'r') as zf:
            # unzipped_files = []
            modified_files_mapping = {}
            # pre-process some of the files in the zip
            for zip_file_name in zf.namelist():  # Get all files in the zip file
                # find the filenames of the modified_files
                if re.match(r"Analysis/proc_\d+/modified_files/mapping\.log", zip_file_name):
                    with zf.open(zip_file_name, mode='r', pwd=None) as fp:
                        file_data = fp.read()
                        for line in file_data.decode("utf-8", 'ignore').split('\n'):
                            if not line:
                                continue
                            if line.count('|') == 3:
                                l_fname, l_size, l_md5, l_created = line.split('|')
                            if line.count('|') == 4:
                                l_fname, l_size, l_md5, l_sha256, l_created = line.split('|')
                            l_fname = cleanup_filepath(l_fname)
                            if l_fname:
                                if l_size == 0:
                                    results.append({'values': l_fname, 'type': 'filename', 'to_ids': True,
                                                    'categories': ['Artifacts dropped', 'Payload delivery'], 'comment': ''})
                                else:
                                    # file is a non empty sample, upload the sample later
                                    modified_files_mapping[l_md5] = l_fname

            # now really process the data
            for zip_file_name in zf.namelist():  # Get all files in the zip file
                # print('Processing file: {}'.format(zip_file_name))
                if re.match(r"Analysis/proc_\d+/modified_files/.+\.", zip_file_name) and "mapping.log" not in zip_file_name:
                    sample_md5 = zip_file_name.split('/')[-1].split('.')[0]
                    if sample_md5 in modified_files_mapping:
                        current_sample_filename = modified_files_mapping[sample_md5]
                        # print("{} maps to {}".format(sample_md5, current_sample_filename))
                        with zf.open(zip_file_name, mode='r', pwd=None) as fp:
                            file_data = fp.read()
                            results.append({
                                'values': current_sample_filename,
                                'data': base64.b64encode(file_data).decode(),
                                'type': 'malware-sample', 'categories': ['Artifacts dropped', 'Payload delivery'], 'to_ids': True, 'comment': ''})

                if 'Analysis/analysis.json' in zip_file_name:
                    with zf.open(zip_file_name, mode='r', pwd=None) as fp:
                        file_data = fp.read()
                        analysis_json = json.loads(file_data.decode('utf-8'))
                    results += process_analysis_json(analysis_json)
            try:
                sample_filename = analysis_json.get('analysis').get('@filename')
                if sample_filename:
                    with zf.open('sample', mode='r', pwd=None) as fp:
                        file_data = fp.read()
                        results.append({
                            'values': sample_filename,
                            'data': base64.b64encode(file_data).decode(),
                            'type': 'malware-sample', 'categories': ['Payload delivery', 'Artifacts dropped'], 'to_ids': True, 'comment': ''})
            except Exception:
                # no 'sample' in archive, might be an url analysis, just ignore
                pass

    else:
        try:
            results = process_analysis_json(json.loads(data.decode('utf-8')))
        except ValueError:
            log.warning('MISP modules {0} failed: uploaded file is not a zip or json file.'.format(request['module']))
            return {'error': 'Uploaded file is not a zip or json file.'}
            pass
    # keep only unique entries based on the value field
    results = list({v['values']: v for v in results}.values())
    r = {'results': results}
    return r


def process_analysis_json(analysis_json):
    if 'analysis' in analysis_json and 'processes' in analysis_json['analysis'] and 'process' in analysis_json['analysis']['processes']:
        # if 'analysis' in analysis_json and '@filename' in analysis_json['analysis']:
        #     sample['values'] = analysis_json['analysis']['@filename']
        for process in analysis_json['analysis']['processes']['process']:
            # print_json(process)
            if 'connection_section' in process and 'connection' in process['connection_section']:
                # compensate for absurd behavior of the data format: if one entry = immediately the dict, if multiple entries = list containing dicts
                # this will always create a list, even with only one item
                if isinstance(process['connection_section']['connection'], dict):
                    process['connection_section']['connection'] = [process['connection_section']['connection']]

                # iterate over each entry
                for connection_section_connection in process['connection_section']['connection']:
                    # compensate for absurd behavior of the data format: if one entry = immediately the dict, if multiple entries = list containing dicts
                    # this will always create a list, even with only one item
                    for subsection in ['http_command', 'http_header']:
                        if isinstance(connection_section_connection[subsection], dict):
                            connection_section_connection[subsection] = [connection_section_connection[subsection]]

                    if 'name_to_ip' in connection_section_connection:  # TA 6.1 data format
                        connection_section_connection['@remote_ip'] = connection_section_connection['name_to_ip']['@result_addresses']
                        connection_section_connection['@remote_hostname'] = connection_section_connection['name_to_ip']['@request_name']

                    connection_section_connection['@remote_ip'] = cleanup_ip(connection_section_connection['@remote_ip'])
                    connection_section_connection['@remote_hostname'] = cleanup_hostname(connection_section_connection['@remote_hostname'])
                    if connection_section_connection['@remote_ip'] and connection_section_connection['@remote_hostname']:
                        val = '{}|{}'.format(connection_section_connection['@remote_hostname'],
                                             connection_section_connection['@remote_ip'])
                        # print("connection_section_connection hostname|ip: {}|{}  IDS:yes".format(
                        #     connection_section_connection['@remote_hostname'],
                        #     connection_section_connection['@remote_ip'])
                        # )
                        yield({'values': val, 'type': 'domain|ip', 'categories': ['Network activity'], 'to_ids': True, 'comment': ''})
                    elif connection_section_connection['@remote_ip']:
                        # print("connection_section_connection ip-dst: {}  IDS:yes".format(
                        #     connection_section_connection['@remote_ip'])
                        # )
                        yield({'values': connection_section_connection['@remote_ip'], 'type': 'ip-dst', 'to_ids': True, 'comment': ''})
                    elif connection_section_connection['@remote_hostname']:
                        # print("connection_section_connection hostname: {}  IDS:yes".format(
                        #     connection_section_connection['@remote_hostname'])
                        # )
                        yield({'values': connection_section_connection['@remote_hostname'], 'type': 'hostname', 'to_ids': True, 'comment': ''})
                    if 'http_command' in connection_section_connection:
                        for http_command in connection_section_connection['http_command']:
                            # print('connection_section_connection HTTP COMMAND: {}\t{}'.format(
                            #     connection_section_connection['http_command']['@method'],                    # comment
                            #     connection_section_connection['http_command']['@url'])                       # url
                            # )
                            val = cleanup_url(http_command['@url'])
                            if val:
                                yield({'values': val, 'type': 'url', 'categories': ['Network activity'], 'to_ids': True, 'comment': http_command['@method']})

                    if 'http_header' in connection_section_connection:
                        for http_header in connection_section_connection['http_header']:
                            if 'User-Agent:' in http_header['@header']:
                                val = http_header['@header'][len('User-Agent: '):]
                                yield({'values': val, 'type': 'user-agent', 'categories': ['Network activity'], 'to_ids': False, 'comment': ''})
                            elif 'Host:' in http_header['@header']:
                                val = http_header['@header'][len('Host: '):]
                                if ':' in val:
                                    try:
                                        val_port = int(val.split(':')[1])
                                    except ValueError:
                                        val_port = False
                                    val_hostname = cleanup_hostname(val.split(':')[0])
                                    val_ip = cleanup_ip(val.split(':')[0])
                                    if val_hostname and val_port:
                                        val_combined = '{}|{}'.format(val_hostname, val_port)
                                        # print({'values': val_combined, 'type': 'hostname|port', 'to_ids': True, 'comment': ''})
                                        yield({'values': val_combined, 'type': 'hostname|port', 'categories': ['Network activity'], 'to_ids': True, 'comment': ''})
                                    elif val_ip and val_port:
                                        val_combined = '{}|{}'.format(val_ip, val_port)
                                        # print({'values': val_combined, 'type': 'ip-dst|port', 'to_ids': True, 'comment': ''})
                                        yield({'values': val_combined, 'type': 'ip-dst|port', 'to_ids': True, 'comment': ''})
                                    else:
                                        continue
                                val_hostname = cleanup_hostname(val)
                                if val_hostname:
                                    # print({'values': val_hostname, 'type': 'hostname', 'to_ids': True, 'comment': ''})
                                    yield({'values': val_hostname, 'type': 'hostname', 'to_ids': True, 'comment': ''})
                            else:
                                # LATER header not processed
                                pass
            if 'filesystem_section' in process and 'create_file' in process['filesystem_section']:
                for filesystem_section_create_file in process['filesystem_section']['create_file']:
                    # first skip some items
                    if filesystem_section_create_file['@create_disposition'] in {'FILE_OPEN_IF'}:
                        continue
                        # FIXME - this section is probably not needed considering the 'stored_files stored_created_file' section we process later.
                        # print('CREATE FILE: {}\t{}'.format(
                        #     filesystem_section_create_file['@srcfile'],             # filename
                        #     filesystem_section_create_file['@create_disposition'])  # comment - use this to filter out cases
                        # )

            if 'networkoperation_section' in process and 'dns_request_by_addr' in process['networkoperation_section']:
                for networkoperation_section_dns_request_by_addr in process['networkoperation_section']['dns_request_by_addr']:
                    # FIXME - it's unclear what this section is for.
                    # TODO filter this
                    # print('DNS REQUEST: {}\t{}'.format(
                    #     networkoperation_section_dns_request_by_addr['@request_address'],       # ip-dst
                    #     networkoperation_section_dns_request_by_addr['@result_name'])           # hostname
                    # )                                                                           # => NOT hostname|ip
                    pass
            if 'networkoperation_section' in process and 'dns_request_by_name' in process['networkoperation_section']:
                for networkoperation_section_dns_request_by_name in process['networkoperation_section']['dns_request_by_name']:
                    networkoperation_section_dns_request_by_name['@request_name'] = cleanup_hostname(networkoperation_section_dns_request_by_name['@request_name'].rstrip('.'))
                    networkoperation_section_dns_request_by_name['@result_addresses'] = cleanup_ip(networkoperation_section_dns_request_by_name['@result_addresses'])
                    if networkoperation_section_dns_request_by_name['@request_name'] and networkoperation_section_dns_request_by_name['@result_addresses']:
                        val = '{}|{}'.format(networkoperation_section_dns_request_by_name['@request_name'],
                                             networkoperation_section_dns_request_by_name['@result_addresses'])
                        # print("networkoperation_section_dns_request_by_name hostname|ip: {}|{}  IDS:yes".format(
                        #     networkoperation_section_dns_request_by_name['@request_name'],
                        #     networkoperation_section_dns_request_by_name['@result_addresses'])
                        # )
                        yield({'values': val, 'type': 'domain|ip', 'categories': ['Network activity'], 'to_ids': True, 'comment': ''})
                    elif networkoperation_section_dns_request_by_name['@request_name']:
                        # print("networkoperation_section_dns_request_by_name hostname: {}  IDS:yes".format(
                        #     networkoperation_section_dns_request_by_name['@request_name'])
                        # )
                        yield({'values': networkoperation_section_dns_request_by_name['@request_name'], 'type': 'hostname', 'to_ids': True, 'comment': ''})
                    elif networkoperation_section_dns_request_by_name['@result_addresses']:
                        # this happens when the IP is both in the request_name and result_address.
                        # print("networkoperation_section_dns_request_by_name hostname: {}  IDS:yes".format(
                        #     networkoperation_section_dns_request_by_name['@result_addresses'])
                        # )
                        yield({'values': networkoperation_section_dns_request_by_name['@result_addresses'], 'type': 'ip-dst', 'to_ids': True, 'comment': ''})

            if 'networkpacket_section' in process and 'connect_to_computer' in process['networkpacket_section']:
                for networkpacket_section_connect_to_computer in process['networkpacket_section']['connect_to_computer']:
                    networkpacket_section_connect_to_computer['@remote_hostname'] = cleanup_hostname(networkpacket_section_connect_to_computer['@remote_hostname'])
                    networkpacket_section_connect_to_computer['@remote_ip'] = cleanup_ip(networkpacket_section_connect_to_computer['@remote_ip'])
                    if networkpacket_section_connect_to_computer['@remote_hostname'] and networkpacket_section_connect_to_computer['@remote_ip']:
                        # print("networkpacket_section_connect_to_computer hostname|ip: {}|{}  IDS:yes COMMENT:port {}".format(
                        #     networkpacket_section_connect_to_computer['@remote_hostname'],
                        #     networkpacket_section_connect_to_computer['@remote_ip'],
                        #     networkpacket_section_connect_to_computer['@remote_port'])
                        # )
                        val_combined = "{}|{}".format(networkpacket_section_connect_to_computer['@remote_hostname'], networkpacket_section_connect_to_computer['@remote_ip'])
                        yield({'values': val_combined, 'type': 'domain|ip', 'to_ids': True, 'comment': ''})
                    elif networkpacket_section_connect_to_computer['@remote_hostname']:
                        # print("networkpacket_section_connect_to_computer hostname: {}  IDS:yes COMMENT:port {}".format(
                        #     networkpacket_section_connect_to_computer['@remote_hostname'],
                        #     networkpacket_section_connect_to_computer['@remote_port'])
                        # )
                        val_combined = "{}|{}".format(networkpacket_section_connect_to_computer['@remote_hostname'], networkpacket_section_connect_to_computer['@remote_port'])
                        yield({'values': val_combined, 'type': 'hostname|port', 'categories': ['Network activity'], 'to_ids': True, 'comment': ''})
                    elif networkpacket_section_connect_to_computer['@remote_ip']:
                        # print("networkpacket_section_connect_to_computer ip-dst: {}  IDS:yes COMMENT:port {}".format(
                        #     networkpacket_section_connect_to_computer['@remote_ip'],
                        #     networkpacket_section_connect_to_computer['@remote_port'])
                        # )
                        val_combined = "{}|{}".format(networkpacket_section_connect_to_computer['@remote_ip'], networkpacket_section_connect_to_computer['@remote_port'])
                        yield({'values': val_combined, 'type': 'ip-dst|port', 'to_ids': True, 'comment': ''})

            if 'registry_section' in process and 'create_key' in process['registry_section']:
                # FIXME this is a complicated section, together with the 'set_value'.
                # it looks like this section is not ONLY about creating registry keys,
                # more about accessing a handle to keys (with specific permissions)
                # maybe we don't want to keep this, in favor of 'set_value'
                for create_key in process['registry_section']['create_key']:
                    # print('REG CREATE: {}\t{}'.format(
                    #     create_key['@desired_access'],
                    #     create_key['@key_name']))
                    pass
            if 'registry_section' in process and 'delete_key' in process['registry_section']:
                # LATER we probably don't want to keep this. Much pollution.
                # Maybe for later once we have filtered out this.
                for delete_key in process['registry_section']['delete_key']:
                    # print('REG DELETE: {}'.format(
                    #     delete_key['@key_name'])
                    # )
                    pass
            if 'registry_section' in process and 'set_value' in process['registry_section']:
                # FIXME this is a complicated section, together with the 'create_key'.
                for set_value in process['registry_section']['set_value']:
                    # '@data_type' == 'REG_BINARY',
                    # '@data_type' == 'REG_DWORD',
                    # '@data_type' == 'REG_EXPAND_SZ',
                    # '@data_type' == 'REG_MULTI_SZ',
                    # '@data_type' == 'REG_NONE',
                    # '@data_type' == 'REG_QWORD',
                    # '@data_type' == 'REG_SZ',
                    regkey = cleanup_regkey("{}\\{}".format(set_value['@key_name'], set_value['@value_name']))
                    regdata = cleanup_regdata(set_value.get('@data'))
                    if not regkey:
                        continue
                    if set_value['@data_size'] == '0' or not regdata:
                        # print('registry_section set_value REG SET: {}\t{}\t{}'.format(
                        #     set_value['@data_type'],
                        #     set_value['@key_name'],
                        #     set_value['@value_name'])
                        # )
                        yield({'values': regkey, 'type': 'regkey', 'to_ids': True,
                               'categories': ['External analysis', 'Persistence mechanism', 'Artifacts dropped'], 'comment': set_value['@data_type']})
                    else:
                        try:
                            # unicode fun...
                            # print('registry_section set_value REG SET: {}\t{}\t{}\t{}'.format(
                            #     set_value['@data_type'],
                            #     set_value['@key_name'],
                            #     set_value['@value_name'],
                            #     set_value['@data'])
                            # )
                            val = "{}|{}".format(regkey, regdata)
                            yield({'values': val, 'type': 'regkey|value', 'to_ids': True,
                                   'categories': ['External analysis', 'Persistence mechanism', 'Artifacts dropped'], 'comment': set_value['@data_type']})
                        except Exception as e:
                            print("EXCEPTION registry_section {}".format(e))
                            # TODO - maybe we want to handle these later, or not...
                        pass
                    pass

            if 'stored_files' in process and 'stored_created_file' in process['stored_files']:
                for stored_created_file in process['stored_files']['stored_created_file']:
                    stored_created_file['@filename'] = cleanup_filepath(stored_created_file['@filename'])
                    if stored_created_file['@filename']:
                        if stored_created_file['@filesize'] != '0':
                            val = '{}|{}'.format(stored_created_file['@filename'], stored_created_file['@md5'])
                            # print("stored_created_file filename|md5: {}|{}  IDS:yes".format(
                            #     stored_created_file['@filename'],                       # filename
                            #     stored_created_file['@md5'])                            # md5
                            # )                                                           # => filename|md5
                            yield({'values': val, 'type': 'filename|md5', 'to_ids': True,
                                   'categories': ['Artifacts dropped', 'Payload delivery'], 'comment': ''})

                        else:
                            # print("stored_created_file filename: {}  IDS:yes".format(
                            #     stored_created_file['@filename'])                        # filename
                            # )                                                           # => filename
                            yield({'values': stored_created_file['@filename'],
                                   'type': 'filename', 'to_ids': True,
                                   'categories': ['Artifacts dropped', 'Payload delivery'], 'comment': ''})

            if 'stored_files' in process and 'stored_modified_file' in process['stored_files']:
                for stored_modified_file in process['stored_files']['stored_modified_file']:
                    stored_modified_file['@filename'] = cleanup_filepath(stored_modified_file['@filename'])
                    if stored_modified_file['@filename']:
                        if stored_modified_file['@filesize'] != '0':
                            val = '{}|{}'.format(stored_modified_file['@filename'], stored_modified_file['@md5'])
                            # print("stored_modified_file MODIFY FILE: {}\t{}".format(
                            #     stored_modified_file['@filename'],                       # filename
                            #     stored_modified_file['@md5'])                            # md5
                            # )                                                            # => filename|md5
                            yield({'values': val, 'type': 'filename|md5', 'to_ids': True,
                                   'categories': ['Artifacts dropped', 'Payload delivery'],
                                   'comment': 'modified'})
                        else:
                            # print("stored_modified_file MODIFY FILE: {}\t{}".format(
                            #     stored_modified_file['@filename'])                       # filename
                            # )                                                            # => filename
                            yield({'values': stored_modified_file['@filename'], 'type': 'filename', 'to_ids': True,
                                   'categories': ['Artifacts dropped', 'Payload delivery'],
                                   'comment': 'modified'})


def add_file(filename, results, hash, index, filedata=None):
    pass
    # results.append({'values': filename, 'data': "{}|{}".format(filename, filedata.decode()), 'type': 'malware-sample',
    #                 'categories': ['Artifacts dropped', 'Payload delivery']})


def add_file_zip():
    # if 'malware-sample' in request:
    # sample_filename = request.get("malware-sample").split("|", 1)[0]
    #            data = base64.b64decode(data)
    #            fl = io.BytesIO(data)
    #            zf = zipfile.ZipFile(fl)
    #            sample_hashname = zf.namelist()[0]
    #            data = zf.read(sample_hashname, b"infected")
    #            zf.close()
    pass


def print_json(data):
    print(json.dumps(data, sort_keys=True, indent=4, separators=(',', ': ')))


def list_in_string(lst, data, regex=False):
    for item in lst:
        if regex:
            if re.search(item, data, flags=re.IGNORECASE):
                return True
        else:
            if item in data:
                return True


def cleanup_ip(item):
    # you should exclude private IP ranges via import regexes
    noise_substrings = {
        '224.0.0.',
        '127.0.0.',
        '8.8.8.8',
        '8.8.4.4',
        '0.0.0.0',
        'NONE'
    }
    if list_in_string(noise_substrings, item):
        return None
    try:
        ipaddress.ip_address(item)
        return item
    except ValueError:
        return None


def cleanup_hostname(item):
    noise_substrings = {
        'wpad',
        'teredo.ipv6.microsoft.com',
        'WIN7SP1-x64-UNP'
    }
    # take away common known bad
    if list_in_string(noise_substrings, item):
        return None
    # eliminate IP addresses
    try:
        ipaddress.ip_address(item)
    except ValueError:
        # this is not an IP, so continue
        return item
    return None


def cleanup_url(item):
    if item in ['/']:
        return None
    return item


def cleanup_filepath(item):
    noise_substrings = {
        '\\AppData\\Local\\GDIPFONTCACHEV1.DAT',
        '\\AppData\\Local\\Microsoft\\Internet Explorer\\DOMStore\\',
        '\\AppData\\Local\\Microsoft\\Internet Explorer\\Recovery\\High\\',
        '\\AppData\\Local\\Microsoft\\Windows\\Caches\\',
        '\\AppData\\Local\\Microsoft\\Windows\\Explorer\\thumbcache',
        '\\AppData\\Local\\Microsoft\\Windows\\History\\History.',
        '\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files\\Content.',
        '\\AppData\\Local\\Microsoft\\Windows\\WebCache\\',
        '\\AppData\\Local\\Temp\\.*tmp$',
        '\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache\\',
        '\\AppData\\LocalLow\\Microsoft\\Internet Explorer\\Services\\search_',
        '\\AppData\\Roaming\\Microsoft\\Office\\Recent\\',
        '\\AppData\\Roaming\\Microsoft\\Windows\\Cookies\\',
        '\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\',
        'C:\\ProgramData\\Microsoft\\OfficeSoftwareProtectionPlatform\\Cache\\cache.dat',
        'C:\\Windows\\Prefetch\\',

        '\\AppData\\Roaming\\Adobe\\Acrobat\\9.0\\SharedDataEvents-journal',
        '\\AppData\\Roaming\\Adobe\\Acrobat\\9.0\\UserCache.bin',

        '\\AppData\\Roaming\\Macromedia\\Flash Player\\macromedia.com\\support\\flashplayer\\sys\\settings.sol',
        '\\AppData\\Roaming\\Adobe\\Flash Player\\NativeCache\\',
        'C:\\Windows\\AppCompat\\Programs\\',
        'C:\\~'  # caused by temp file created by MS Office when opening malicious doc/xls/...
    }
    if list_in_string(noise_substrings, item):
        return None
    return item


def cleanup_regkey(item):
    noise_substrings = {
        r'\\CurrentVersion\\Explorer\\FileExts\\[a-z\.]+\\OpenWith',
        r'\\CurrentVersion\\Explorer\\RecentDocs\\',
        r'\\CurrentVersion\\Explorer\\UserAssist\\',
        r'\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bag',
        r'\\Software\\Classes\\CLSID\\',
        r'\\Software\\Classes\\Local Settings\\MuiCache\\',
        r'\\Software\\Microsoft\\Internet Explorer\\Main\\WindowsSearch',
        r'\\Software\\Microsoft\\Office\\[0-9\.]+\\',
        r'\\Software\\Microsoft\\Office\\Common\\Smart Tag\\',
        r'\\Software\\Microsoft\\OfficeSoftwareProtectionPlatform\\',
        r'\\Software\\Microsoft\\Shared Tools\\Panose\\',
        r'\\Software\\Microsoft\\Tracing\\',
        r'\\Software\\Microsoft\\Tracing\\powershell_RASAPI32\\',
        r'\\Software\\Microsoft\\Tracing\\powershell_RASMANCS\\',
        r'\\Software\\Microsoft\\Windows\\CurrentVersion\\Action Center\\',
        r'\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU\\',
        r'\\Software\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\',
        r'\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\',
        r'\\System\\CurrentControlSet\\Services\\RdyBoost\\',
        r'\\Usage\\SpellingAndGrammarFiles'
    }
    if list_in_string(noise_substrings, item, regex=True):
        return None
    return item


def cleanup_regdata(item):
    if not item:
        return None
    item = item.replace('(UNICODE_0x00000000)', '')
    return item


def get_zipped_contents(filename, data, password=None):
    with zipfile.ZipFile(io.BytesIO(data), 'r') as zf:
        unzipped_files = []
        if password is not None:
            password = str.encode(password)  # Byte encoded password required
        for zip_file_name in zf.namelist():  # Get all files in the zip file
            # print(zip_file_name)
            with zf.open(zip_file_name, mode='r', pwd=password) as fp:
                file_data = fp.read()
            unzipped_files.append({'values': zip_file_name,
                                   'data': file_data,
                                   'comment': 'Extracted from {0}'.format(filename)})
            # print("{} : {}".format(zip_file_name, len(file_data)))
    return unzipped_files


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
