import json
from stix.core import STIXPackage
import re
import base64
import hashlib
import tempfile

misperrors = {'error': 'Error'}
userConfig = {}
inputSource = ['file']

moduleinfo = {'version': '0.1', 'author': 'Hannah Ward',
              'description': 'Import some stix stuff',
              'module-type': ['import']}

moduleconfig = ["max_size"]


def handler(q=False):
    # Just in case we have no data
    if q is False:
        return False

    # The return value
    r = {'results': []}

    # Load up that JSON
    q = json.loads(q)

    # It's b64 encoded, so decode that stuff
    package = str(base64.b64decode(q.get("data", None)), 'utf-8')

    # If something really weird happened
    if not package:
        return json.dumps({"success": 0})

    # Get the maxsize from the config
    # Default to 10MB
    # (I believe the max_size arg is given  in bytes)
    # Check if we were given a configuration
    memsize = q.get("config", None)

    # If we were, find out if there's a memsize field
    if memsize:
        memsize = memsize.get("max_size", 10 * 1024)
    else:
        memsize = 10 * 1024

    # Load up the package into STIX
    package = loadPackage(package, memsize)

    # Build all the observables
    if package.observables:
        for obs in package.observables:
            r["results"].append(buildObservable(obs))

    # And now the threat actors
    if package.threat_actors:
        for ta in package.threat_actors:
            r["results"].append(buildActor(ta))

    # Aaaand the indicators
    if package.indicators:
        for ind in package.indicators:
            r["results"].append(buildIndicator(ind))

    # Are you seeing a pattern?
    if package.exploit_targets:
        for et in package.exploit_targets:
            r["results"].append(buildExploitTarget(et))

    # LOADING STUFF
    if package.campaigns:
        for cpn in package.campaigns:
            r["results"].append(buildCampaign(cpn))

    # Clean up results
    # Don't send on anything that didn't have a value
    r["results"] = [x for x in r["results"] if len(x["values"]) != 0]
    return r

# Quick and dirty regex for IP addresses
ipre = re.compile("([0-9]{1,3}.){3}[0-9]{1,3}")


def buildCampaign(cpn):
    """
        Extract a campaign name
    """
    return {"values": [cpn.title], "types": ["campaign-name"]}


def buildExploitTarget(et):
    """
        Extract CVEs from exploit targets
    """

    r = {"values": [], "types": ["vulnerability"]}

    if et.vulnerabilities:
        for v in et.vulnerabilities:
            if v.cve_id:
                r["values"].append(v.cve_id)
    return r


def identifyHash(hsh):
    """
        What's that hash!?
    """

    possible_hashes = []

    hashes = [x for x in hashlib.algorithms_guaranteed]

    for h in hashes:
        if len(str(hsh)) == len(hashlib.new(h).hexdigest()):
            possible_hashes.append(h)
            possible_hashes.append("filename|{}".format(h))
    return possible_hashes


def buildIndicator(ind):
    """
        Extract hashes
        and other fun things
        like that
    """
    r = {"values": [], "types": []}

    # Try to get hashes. I hate stix
    if ind.observable:
        return buildObservable(ind.observable)
    return r


def buildActor(ta):
    """
        Extract the name
        and comment of a
        threat actor
    """

    r = {"values": [ta.title], "types": ["threat-actor"]}

    return r


def buildObservable(o):
    """
        Take a STIX observable
        and extract the value
        and category
    """

    # Life is easier with json
    if not isinstance(o, dict):
        o = json.loads(o.to_json())
    # Make a new record to store values in
    r = {"values": []}

    # Get the object properties. This contains all the
    # fun stuff like values
    if "observable_composition" in o:
        # May as well be useless
        return r

    props = o["object"]["properties"]

    # If it has an address_value field, it's gonna be an address
    # print(props)
    # Kinda obvious really
    if "address_value" in props:

        # We've got ourselves a nice little address
        value = props["address_value"]

        if isinstance(value, dict):
            # Sometimes it's embedded in a dictionary
            value = value["value"]

        # Is it an IP?
        if ipre.match(str(value)):
            # Yes!
            r["values"].append(value)
            r["types"] = ["ip-src", "ip-dst"]
        else:
            # Probably a domain yo
            r["values"].append(value)
            r["types"] = ["domain", "hostname"]

        if "hashes" in props:
            for hsh in props["hashes"]:
                r["values"].append(hsh["simple_hash_value"]["value"])
                r["types"] = identifyHash(hsh["simple_hash_value"]["value"])
        return r


def loadPackage(data, memsize=1024):
    # Write the stix package to a tmp file

    temp = tempfile.SpooledTemporaryFile(max_size=int(memsize), mode="w+")

    temp.write(data)

    # Back to the beginning so we can read it again
    temp.seek(0)
    try:
        # Try loading it into every format we know of
        try:
            package = STIXPackage().from_xml(temp)
        except:
            # We have to seek back again
            temp.seek(0)
            package = STIXPackage().from_json(temp)
    except Exception:
        print("Failed to load package")
        raise ValueError("COULD NOT LOAD STIX PACKAGE!")
    temp.close()
    return package


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
