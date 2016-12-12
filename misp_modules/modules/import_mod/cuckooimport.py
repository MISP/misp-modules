import json
import logging 
import sys 
import base64 

misperrors = {'error': 'Error'}
userConfig = {}
inputSource = ['file']

moduleinfo = {'version': '0.1', 'author': 'Victor van der Stoep',
              'description': 'Cuckoo JSON import',
              'module-type': ['import']}

moduleconfig = []

def handler(q=False):
    # Just in case we have no data
    if q is False:
        return False
    
    # The return value
    r = {'results': []}

    # Load up that JSON
    q = json.loads(q) 
    data = base64.b64decode(q.get("data")).decode('utf-8')
    
    # If something really weird happened
    if not data:
        return json.dumps({"success": 0})
   
    data = json.loads(data)
    
    # Get characteristics of file  
    targetFile = data['target']['file']
    
    # Process the inital binary
    processBinary(r, targetFile, initial = True)
    
    # Get binary information for dropped files
    if(data.get('dropped')):
        for droppedFile in data['dropped']:
            processBinary(r, droppedFile, dropped = True)
    
    # Add malscore to results
    r["results"].append({ 
        "values": "Malscore: {} ".format(data['malscore']), 
        "types": "comment",
        "categories": "Payload delivery", 
        "comment": "Cuckoo analysis: MalScore"
    })
    
    # Add virustotal data, if exists
    if(data.get('virustotal')):
        processVT(r, data['virustotal'])
    
    # Add network information, should be improved
    processNetwork(r, data['network'])
    
    # Add behavioral information
    processSummary(r, data['behavior']['summary'])
    
    # Return 
    return r

def processSummary(r, summary):
    r["results"].append({ 
        "values": summary['mutexes'], 
        "types": "mutex",
        "categories": "Artifacts dropped", 
        "comment": "Cuckoo analysis: Observed mutexes"
    })
    
def processVT(r, virustotal):
    category = "Antivirus detection"
    comment = "VirusTotal analysis" 
    
    if(virustotal.get('permalink')):
        r["results"].append({ 
            "values": virustotal['permalink'], 
            "types": "link",
            "categories": category, 
            "comments": comment + " - Permalink"
        })
    
    if(virustotal.get('total')):
        r["results"].append({ 
            "values": "VirusTotal detection rate {}/{}".format(
                virustotal['positives'],
                virustotal['total']
            ), 
            "types": "comment",
            "categories": category, 
            "comment": comment
        }) 
    else: 
        r["results"].append({ 
            "values": "Sample not detected on VirusTotal", 
            "types": "comment",
            "categories": category, 
            "comment": comment
        })
    

def processNetwork(r, network):
    category = "Network activity"
    
    for host in network['hosts']:
        r["results"].append({ 
            "values": host['ip'], 
            "types": "ip-dst",
            "categories": category,  
            "comment": "Cuckoo analysis: Observed network traffic"
        })
    

def processBinary(r, target, initial = False, dropped = False):
    if(initial): 
        comment = "Cuckoo analysis: Initial file"
        category = "Payload delivery"
    elif(dropped):
        category = "Artifacts dropped"
        comment = "Cuckoo analysis: Dropped file"
    
    r["results"].append({ 
        "values": target['name'], 
        "types": "filename",
        "categories": category, 
        "comment": comment
    })
    
    r["results"].append({ 
        "values": target['md5'], 
        "types": "md5",
        "categories": category, 
        "comment": comment
    })
    
    r["results"].append({ 
        "values": target['sha1'], 
        "types": "sha1",
        "categories": category, 
        "comment": comment
    })
    
    r["results"].append({ 
        "values": target['sha256'], 
        "types": "sha256",
        "categories": category, 
        "comment": comment
    })
    
    r["results"].append({ 
        "values": target['sha512'], 
        "types": "sha512",
        "categories": category, 
        "comment": comment
    })
    
    # todo : add file size?
    
    if(target.get('guest_paths')):
        r["results"].append({ 
            "values": target['guest_paths'],
            "types": "filename",
            "categories": "Payload installation", 
            "comment": comment + " - Path"
        })
    

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

if __name__ == '__main__':
    x = open('test.json', 'r')
    q = []
    q['data'] = x.read()
    q = base64.base64encode(q)
    
    handler(q)
