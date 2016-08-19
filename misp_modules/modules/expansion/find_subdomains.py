import json
import os
import subprocess
import requests
import tempfile

misperrors = {'error': 'Error'}
mispattributes = {'input': ['domain'], 'output': ['domain']}

# possible module-types: 'expansion', 'hover' or both
moduleinfo = {'version': '1', 'author': 'Hannah Ward',
              'description': 'Attempt to brute force subdomains',
              'module-type': ['expansion']}

# config fields that your code expects from the site admin
moduleconfig = ["use_top_n_subdomains"]

domains = requests.get("http://hannah-ward.uk/Subdomain_List.txt").text.split("\n")[:-1]

def handler(q=False):
    global domains

    if q is False:
        return False
    request = json.loads(q)

    r = {"results": []}
    
    f = tempfile.NamedTemporaryFile(delete=False, prefix="domains", mode="w")
    print("Saving domains to {}".format(f.name))
    f.write("\n".join(domains[:int(request["config"]["use_top_n_subdomains"])]))

    f.close()
  
    print("Searching for subdomains of {}".format(request["domain"]))
    print("Using {} domains".format(request["config"]["use_top_n_subdomains"]))

    print("Turning on tor...")
    #subprocess.call([".","torsocks","on"])
    proc = subprocess.Popen(["knockpy", "-w", f.name, request["domain"]], 
                            stdout=subprocess.PIPE
                           )

    os.remove(f.name)

    print("Turning off tor...")
    #subprocess.call([".","torsocks","off"])
    out,err = proc.communicate()

    r["results"] = {'values':out.split("\n"), "types":'domain'}

    return r


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo

