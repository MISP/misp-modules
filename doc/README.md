# MISP modules documentation

## Expansion Modules

#### [apiosintds](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/apiosintds.py)

On demand query API for OSINT.digitalside.it project.
- **features**:
>The module simply queries the API of OSINT.digitalside.it with a domain, ip, url or hash attribute.
>
>The result of the query is then parsed to extract additional hashes or urls. A module parameters also allows to parse the hashes related to the urls.
>
>Furthermore, it is possible to cache the urls and hashes collected over the last 7 days by OSINT.digitalside.it
- **input**:
>A domain, ip, url or hash attribute.
- **output**:
>Hashes and urls resulting from the query to OSINT.digitalside.it
- **references**:
>https://osint.digitalside.it/#About
- **requirements**:
>The apiosintDS python library to query the OSINT.digitalside.it API.

-----

#### [apivoid](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/apivoid.py)

<img src=logos/apivoid.png height=60>

Module to query APIVoid with some domain attributes.
- **features**:
>This module takes a domain name and queries API Void to get the related DNS records and the SSL certificates. It returns then those pieces of data as MISP objects that can be added to the event.
>
>To make it work, a valid API key and enough credits to proceed 2 queries (0.06 + 0.07 credits) are required.
- **input**:
>A domain attribute.
- **output**:
>DNS records and SSL certificates related to the domain.
- **references**:
>https://www.apivoid.com/
- **requirements**:
>A valid APIVoid API key with enough credits to proceed 2 queries

-----

#### [assemblyline_query](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/assemblyline_query.py)

<img src=logos/assemblyline.png height=60>

A module tu query the AssemblyLine API with a submission ID to get the submission report and parse it.
- **features**:
>The module requires the address of the AssemblyLine server you want to query as well as your credentials used for this instance. Credentials include the used-ID and an API key or the password associated to the user-ID.
>
>The submission ID extracted from the submission link is then used to query AssemblyLine and get the full submission report. This report is parsed to extract file objects and the associated IPs, domains or URLs the files are connecting to.
>
>Some more data may be parsed in the future.
- **input**:
>Link of an AssemblyLine submission report.
- **output**:
>MISP attributes & objects parsed from the AssemblyLine submission.
- **references**:
>https://www.cyber.cg.ca/en/assemblyline
- **requirements**:
>assemblyline_client: Python library to query the AssemblyLine rest API.

-----

#### [assemblyline_submit](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/assemblyline_submit.py)

<img src=logos/assemblyline.png height=60>

A module to submit samples and URLs to AssemblyLine for advanced analysis, and return the link of the submission.
- **features**:
>The module requires the address of the AssemblyLine server you want to query as well as your credentials used for this instance. Credentials include the user-ID and an API key or the password associated to the user-ID.
>
>If the sample or url is correctly submitted, you get then the link of the submission.
- **input**:
>Sample, or url to submit to AssemblyLine.
- **output**:
>Link of the report generated in AssemblyLine.
- **references**:
>https://www.cyber.gc.ca/en/assemblyline
- **requirements**:
>assemblyline_client: Python library to query the AssemblyLine rest API.

-----

#### [backscatter_io](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/backscatter_io.py)

<img src=logos/backscatter_io.png height=60>

Query backscatter.io (https://backscatter.io/).
- **features**:
>The module takes a source or destination IP address as input and displays the information known by backscatter.io.
>
>
- **input**:
>IP addresses.
- **output**:
>Text containing a history of the IP addresses especially on scanning based on backscatter.io information .
- **references**:
>https://pypi.org/project/backscatter/
- **requirements**:
>backscatter python library

-----

#### [bgpranking](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/bgpranking.py)

Query BGP Ranking (https://bgpranking-ng.circl.lu/).
- **features**:
>The module takes an AS number attribute as input and displays its description and history, and position in BGP Ranking.
>
>
- **input**:
>Autonomous system number.
- **output**:
>Text containing a description of the ASN, its history, and the position in BGP Ranking.
- **references**:
>https://github.com/D4-project/BGP-Ranking/
- **requirements**:
>pybgpranking python library

-----

#### [btc_scam_check](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/btc_scam_check.py)

<img src=logos/bitcoin.png height=60>

An expansion hover module to query a special dns blacklist to check if a bitcoin address has been abused.
- **features**:
>The module queries a dns blacklist directly with the bitcoin address and get a response if the address has been abused.
- **input**:
>btc address attribute.
- **output**:
>Text to indicate if the BTC address has been abused.
- **references**:
>https://btcblack.it/
- **requirements**:
>dnspython3: dns python library

-----

#### [btc_steroids](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/btc_steroids.py)

<img src=logos/bitcoin.png height=60>

An expansion hover module to get a blockchain balance from a BTC address in MISP.
- **input**:
>btc address attribute.
- **output**:
>Text to describe the blockchain balance and the transactions related to the btc address in input.

-----

#### [censys_enrich](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/censys_enrich.py)

An expansion module to enrich attributes in MISP by quering the censys.io API
- **features**:
>This module takes an IP, hostname or a certificate fingerprint and attempts to enrich it by querying the Censys API.
- **input**:
>IP, domain or certificate fingerprint (md5, sha1 or sha256)
- **output**:
>MISP objects retrieved from censys, including open ports, ASN, Location of the IP, x509 details
- **references**:
>https://www.censys.io
- **requirements**:
>API credentials to censys.io

-----

#### [circl_passivedns](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/circl_passivedns.py)

<img src=logos/passivedns.png height=60>

Module to access CIRCL Passive DNS.
- **features**:
>This module takes a hostname, domain or ip-address (ip-src or ip-dst) attribute as input, and queries the CIRCL Passive DNS REST API to get the asssociated passive dns entries and return them as MISP objects.
>
>To make it work a username and a password are thus required to authenticate to the CIRCL Passive DNS API.
- **input**:
>Hostname, domain, or ip-address attribute.
- **ouput**:
>Passive DNS objects related to the input attribute.
- **references**:
>https://www.circl.lu/services/passive-dns/, https://datatracker.ietf.org/doc/draft-dulaunoy-dnsop-passive-dns-cof/
- **requirements**:
>pypdns: Passive DNS python library, A CIRCL passive DNS account with username & password

-----

#### [circl_passivessl](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/circl_passivessl.py)

<img src=logos/passivessl.png height=60>

Modules to access CIRCL Passive SSL.
- **features**:
>This module takes an ip-address (ip-src or ip-dst) attribute as input, and queries the CIRCL Passive SSL REST API to gather the related certificates and return the corresponding MISP objects.
>
>To make it work a username and a password are required to authenticate to the CIRCL Passive SSL API.
- **input**:
>IP address attribute.
- **output**:
>x509 certificate objects seen by the IP address(es).
- **references**:
>https://www.circl.lu/services/passive-ssl/
- **requirements**:
>pypssl: Passive SSL python library, A CIRCL passive SSL account with username & password

-----

#### [countrycode](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/countrycode.py)

Module to expand country codes.
- **features**:
>The module takes a domain or a hostname as input, and returns the country it belongs to.
>
>For non country domains, a list of the most common possible extensions is used.
- **input**:
>Hostname or domain attribute.
- **output**:
>Text with the country code the input belongs to.

-----

#### [crowdstrike_falcon](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/crowdstrike_falcon.py)

<img src=logos/crowdstrike.png height=60>

Module to query Crowdstrike Falcon.
- **features**:
>This module takes a MISP attribute as input to query a CrowdStrike Falcon API. The API returns then the result of the query with some types we map into compatible types we add as MISP attributes.
>
>Please note that composite attributes composed by at least one of the input types mentionned below (domains, IPs, hostnames) are also supported.
- **input**:
>A MISP attribute included in the following list:
>- domain
>- email-attachment
>- email-dst
>- email-reply-to
>- email-src
>- email-subject
>- filename
>- hostname
>- ip-src
>- ip-dst
>- md5
>- mutex
>- regkey
>- sha1
>- sha256
>- uri
>- url
>- user-agent
>- whois-registrant-email
>- x509-fingerprint-md5
- **output**:
>MISP attributes mapped after the CrowdStrike API has been queried, included in the following list:
>- hostname
>- email-src
>- email-subject
>- filename
>- md5
>- sha1
>- sha256
>- ip-dst
>- ip-dst
>- mutex
>- regkey
>- url
>- user-agent
>- x509-fingerprint-md5
- **references**:
>https://www.crowdstrike.com/products/crowdstrike-falcon-faq/
- **requirements**:
>A CrowdStrike API access (API id & key)

-----

#### [cuckoo_submit](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/cuckoo_submit.py)

<img src=logos/cuckoo.png height=60>

An expansion module to submit files and URLs to Cuckoo Sandbox.
- **features**:
>The module takes a malware-sample, attachment, url or domain and submits it to Cuckoo Sandbox.
> The returned task id can be used to retrieve results when the analysis completed.
- **input**:
>A malware-sample or attachment for files. A url or domain for URLs.
- **output**:
>A text field containing 'Cuckoo task id: <id>'
- **references**:
>https://cuckoosandbox.org/, https://cuckoo.sh/docs/
- **requirements**:
>Access to a Cuckoo Sandbox API and an API key if the API requires it. (api_url and api_key)

-----

#### [cve](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/cve.py)

<img src=logos/cve.png height=60>

An expansion hover module to expand information about CVE id.
- **features**:
>The module takes a vulnerability attribute as input and queries the CIRCL CVE search API to get information about the vulnerability as it is described in the list of CVEs.
- **input**:
>Vulnerability attribute.
- **output**:
>Text giving information about the CVE related to the Vulnerability.
- **references**:
>https://cve.circl.lu/, https://cve.mitre.org/

-----

#### [cytomic_orion](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/cytomic_orion.py)

<img src=logos/cytomic_orion.png height=60>

An expansion module to enrich attributes in MISP by quering the Cytomic Orion API
- **features**:
>This module takes an MD5 hash and searches for occurrences of this hash in the Cytomic Orion database. Returns observed files and machines.
- **input**:
>MD5, hash of the sample / malware to search for.
- **output**:
>MISP objects with sightings of the hash in Cytomic Orion. Includes files and machines.
- **references**:
>https://www.vanimpe.eu/2020/03/10/integrating-misp-and-cytomic-orion/, https://www.cytomicmodel.com/solutions/
- **requirements**:
>Access (license) to Cytomic Orion

-----

#### [dbl_spamhaus](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/dbl_spamhaus.py)

<img src=logos/spamhaus.jpg height=60>

Module to check Spamhaus DBL for a domain name.
- **features**:
>This modules takes a domain or a hostname in input and queries the Domain Block List provided by Spamhaus to determine what kind of domain it is.
>
>DBL then returns a response code corresponding to a certain classification of the domain we display. If the queried domain is not in the list, it is also mentionned.
>
>Please note that composite MISP attributes containing domain or hostname are supported as well.
- **input**:
>Domain or hostname attribute.
- **output**:
>Information about the nature of the input.
- **references**:
>https://www.spamhaus.org/faq/section/Spamhaus%20DBL
- **requirements**:
>dnspython3: DNS python3 library

-----

#### [dns](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/dns.py)

A simple DNS expansion service to resolve IP address from domain MISP attributes.
- **features**:
>The module takes a domain of hostname attribute as input, and tries to resolve it. If no error is encountered, the IP address that resolves the domain is returned, otherwise the origin of the error is displayed.
>
>The address of the DNS resolver to use is also configurable, but if no configuration is set, we use the Google public DNS address (8.8.8.8).
>
>Please note that composite MISP attributes containing domain or hostname are supported as well.
- **input**:
>Domain or hostname attribute.
- **output**:
>IP address resolving the input.
- **requirements**:
>dnspython3: DNS python3 library

-----

#### [docx-enrich](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/docx-enrich.py)

<img src=logos/docx.png height=60>

Module to extract freetext from a .docx document.
- **features**:
>The module reads the text contained in a .docx document. The result is passed to the freetext import parser so IoCs can be extracted out of it.
- **input**:
>Attachment attribute containing a .docx document.
- **output**:
>Text and freetext parsed from the document.
- **requirements**:
>docx python library

-----

#### [domaintools](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/domaintools.py)

<img src=logos/domaintools.png height=60>

DomainTools MISP expansion module.
- **features**:
>This module takes a MISP attribute as input to query the Domaintools API. The API returns then the result of the query with some types we map into compatible types we add as MISP attributes.
>
>Please note that composite attributes composed by at least one of the input types mentionned below (domains, IPs, hostnames) are also supported.
- **input**:
>A MISP attribute included in the following list:
>- domain
>- hostname
>- email-src
>- email-dst
>- target-email
>- whois-registrant-email
>- whois-registrant-name
>- whois-registrant-phone
>- ip-src
>- ip-dst
- **output**:
>MISP attributes mapped after the Domaintools API has been queried, included in the following list:
>- whois-registrant-email
>- whois-registrant-phone
>- whois-registrant-name
>- whois-registrar
>- whois-creation-date
>- text
>- domain
- **references**:
>https://www.domaintools.com/
- **requirements**:
>Domaintools python library, A Domaintools API access (username & apikey)

-----

#### [eql](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/eql.py)

<img src=logos/eql.png height=60>

EQL query generation for a MISP attribute.
- **features**:
>This module adds a new attribute to a MISP event containing an EQL query for a network or file attribute.
- **input**:
>A filename or ip attribute.
- **output**:
>Attribute containing EQL for a network or file attribute.
- **references**:
>https://eql.readthedocs.io/en/latest/

-----

#### [eupi](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/eupi.py)

<img src=logos/eupi.png height=60>

A module to query the Phishing Initiative service (https://phishing-initiative.lu).
- **features**:
>This module takes a domain, hostname or url MISP attribute as input to query the Phishing Initiative API. The API returns then the result of the query with some information about the value queried.
>
>Please note that composite attributes containing domain or hostname are also supported.
- **input**:
>A domain, hostname or url MISP attribute.
- **output**:
>Text containing information about the input, resulting from the query on Phishing Initiative.
- **references**:
>https://phishing-initiative.eu/?lang=en
- **requirements**:
>pyeupi: eupi python library, An access to the Phishing Initiative API (apikey & url)

-----

#### [farsight_passivedns](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/farsight_passivedns.py)

<img src=logos/farsight.png height=60>

Module to access Farsight DNSDB Passive DNS.
- **features**:
>This module takes a domain, hostname or IP address MISP attribute as input to query the Farsight Passive DNS API. The API returns then the result of the query with some information about the value queried.
- **input**:
>A domain, hostname or IP address MISP attribute.
- **output**:
>Text containing information about the input, resulting from the query on the Farsight Passive DNS API.
- **references**:
>https://www.farsightsecurity.com/
- **requirements**:
>An access to the Farsight Passive DNS API (apikey)

-----

#### [geoip_country](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/geoip_country.py)

<img src=logos/maxmind.png height=60>

Module to query a local copy of Maxmind's Geolite database.
- **features**:
>This module takes an IP address MISP attribute as input and queries a local copy of the Maxmind's Geolite database to get information about the location of this IP address.
>
>Please note that composite attributes domain|ip are also supported.
- **input**:
>An IP address MISP Attribute.
- **output**:
>Text containing information about the location of the IP address.
- **references**:
>https://www.maxmind.com/en/home
- **requirements**:
>A local copy of Maxmind's Geolite database

-----

#### [greynoise](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/greynoise.py)

<img src=logos/greynoise.png height=60>

Module to access GreyNoise.io API
- **features**:
>The module takes an IP address as input and queries Greynoise for some additional information about it. The result is returned as text.
- **input**:
>An IP address.
- **output**:
>Additional information about the IP fetched from Greynoise API.
- **references**:
>https://greynoise.io/, https://github.com/GreyNoise-Intelligence/api.greynoise.io

-----

#### [hashdd](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/hashdd.py)

A hover module to check hashes against hashdd.com including NSLR dataset.
- **features**:
>This module takes a hash attribute as input to check its known level, using the hashdd API. This information is then displayed.
- **input**:
>A hash MISP attribute (md5).
- **output**:
>Text describing the known level of the hash in the hashdd databases.
- **references**:
>https://hashdd.com/

-----

#### [hibp](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/hibp.py)

<img src=logos/hibp.png height=60>

Module to access haveibeenpwned.com API.
- **features**:
>The module takes an email address as input and queries haveibeenpwned.com API to find additional information about it. This additional information actually tells if any account using the email address has already been compromised in a data breach.
- **input**:
>An email address
- **output**:
>Additional information about the email address.
- **references**:
>https://haveibeenpwned.com/

-----

#### [intelmq_eventdb](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/intelmq_eventdb.py)

<img src=logos/intelmq.png height=60>

Module to access intelmqs eventdb.
- **features**:
>/!\ EXPERIMENTAL MODULE, some features may not work /!\
>
>This module takes a domain, hostname, IP address or Autonomous system MISP attribute as input to query the IntelMQ database. The result of the query gives then additional information about the input.
- **input**:
>A hostname, domain, IP address or AS attribute.
- **output**:
>Text giving information about the input using IntelMQ database.
- **references**:
>https://github.com/certtools/intelmq, https://intelmq.readthedocs.io/en/latest/Developers-Guide/
- **requirements**:
>psycopg2: Python library to support PostgreSQL, An access to the IntelMQ database (username, password, hostname and database reference)

-----

#### [ipasn](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/ipasn.py)

Module to query an IP ASN history service (https://github.com/D4-project/IPASN-History).
- **features**:
>This module takes an IP address attribute as input and queries the CIRCL IPASN service. The result of the query is the latest asn related to the IP address, that is returned as a MISP object.
- **input**:
>An IP address MISP attribute.
- **output**:
>Asn object(s) objects related to the IP address used as input.
- **references**:
>https://github.com/D4-project/IPASN-History
- **requirements**:
>pyipasnhistory: Python library to access IPASN-history instance

-----

#### [iprep](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/iprep.py)

Module to query IPRep data for IP addresses.
- **features**:
>This module takes an IP address attribute as input and queries the database from packetmail.net to get some information about the reputation of the IP.
- **input**:
>An IP address MISP attribute.
- **output**:
>Text describing additional information about the input after a query on the IPRep API.
- **references**:
>https://github.com/mahesh557/packetmail
- **requirements**:
>An access to the packetmail API (apikey)

-----

#### [joesandbox_query](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/joesandbox_query.py)

<img src=logos/joesandbox.png height=60>

Query Joe Sandbox API with a submission url to get the json report and extract its data that is parsed and converted into MISP attributes and objects.

This url can by the way come from the result of the [joesandbox_submit expansion module](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/joesandbox_submit.py).
- **features**:
>Module using the new format of modules able to return attributes and objects.
>
>The module returns the same results as the import module [joe_import](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/import_mod/joe_import.py) taking directly the json report as input.
>
>Even if the introspection will allow all kinds of links to call this module, obviously only the ones presenting a sample or url submission in the Joe Sandbox API will return results.
>
>To make it work you will need to fill the 'apikey' configuration with your Joe Sandbox API key and provide a valid link as input.
- **input**:
>Link of a Joe Sandbox sample or url submission.
- **output**:
>MISP attributes & objects parsed from the analysis report.
- **references**:
>https://www.joesecurity.org, https://www.joesandbox.com/
- **requirements**:
>jbxapi: Joe Sandbox API python3 library

-----

#### [joesandbox_submit](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/joesandbox_submit.py)

<img src=logos/joesandbox.png height=60>

A module to submit files or URLs to Joe Sandbox for an advanced analysis, and return the link of the submission.
- **features**:
>The module requires a Joe Sandbox API key to submit files or URL, and returns the link of the submitted analysis.
>
>It is then possible, when the analysis is completed, to query the Joe Sandbox API to get the data related to the analysis, using the [joesandbox_query module](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/joesandbox_query.py) directly on this submission link.
- **input**:
>Sample, url (or domain) to submit to Joe Sandbox for an advanced analysis.
- **output**:
>Link of the report generated in Joe Sandbox.
- **references**:
>https://www.joesecurity.org, https://www.joesandbox.com/
- **requirements**:
>jbxapi: Joe Sandbox API python3 library

-----

#### [lastline_query](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/lastline_query.py)

<img src=logos/lastline.png height=60>

Query Lastline with an analysis link and parse the report into MISP attributes and objects.
The analysis link can also be retrieved from the output of the [lastline_submit](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/lastline_submit.py) expansion module.
- **features**:
>The module requires a Lastline Portal `username` and `password`.
>The module uses the new format and it is able to return MISP attributes and objects.
>The module returns the same results as the [lastline_import](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/import_mod/lastline_import.py) import module.
- **input**:
>Link to a Lastline analysis.
- **output**:
>MISP attributes and objects parsed from the analysis report.
- **references**:
>https://www.lastline.com

-----

#### [lastline_submit](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/lastline_submit.py)

<img src=logos/lastline.png height=60>

Module to submit a file or URL to Lastline.
- **features**:
>The module requires a Lastline Analysis `api_token` and `key`.
>When the analysis is completed, it is possible to import the generated report by feeding the analysis link to the [lastline_query](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/lastline_query.py) module.
- **input**:
>File or URL to submit to Lastline.
- **output**:
>Link to the report generated by Lastline.
- **references**:
>https://www.lastline.com

-----

#### [macaddress_io](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/macaddress_io.py)

<img src=logos/macaddress_io.png height=60>

MISP hover module for macaddress.io
- **features**:
>This module takes a MAC address attribute as input and queries macaddress.io for additional information.
>
>This information contains data about:
>- MAC address details
>- Vendor details
>- Block details
- **input**:
>MAC address MISP attribute.
- **output**:
>Text containing information on the MAC address fetched from a query on macaddress.io.
- **references**:
>https://macaddress.io/, https://github.com/CodeLineFi/maclookup-python
- **requirements**:
>maclookup: macaddress.io python library, An access to the macaddress.io API (apikey)

-----

#### [macvendors](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/macvendors.py)

<img src=logos/macvendors.png height=60>

Module to access Macvendors API.
- **features**:
>The module takes a MAC address as input and queries macvendors.com for some information about it. The API returns the name of the vendor related to the address.
- **input**:
>A MAC address.
- **output**:
>Additional information about the MAC address.
- **references**:
>https://macvendors.com/, https://macvendors.com/api

-----

#### [malwarebazaar](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/malwarebazaar.py)

Query the MALWAREbazaar API to get additional information about the input hash attribute.
- **features**:
>The module takes a hash attribute as input and queries MALWAREbazaar's API to fetch additional data about it. The result, if the payload is known on the databases, is at least one file object describing the file the input hash is related to.
>
>The module is using the new format of modules able to return object since the result is one or multiple MISP object(s).
- **input**:
>A hash attribute (md5, sha1 or sha256).
- **output**:
>File object(s) related to the input attribute found on MALWAREbazaar databases.
- **references**:
>https://bazaar.abuse.ch/

-----

#### [ocr-enrich](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/ocr-enrich.py)

Module to process some optical character recognition on pictures.
- **features**:
>The module takes an attachment attributes as input and process some optical character recognition on it. The text found is then passed to the Freetext importer to extract potential IoCs.
- **input**:
>A picture attachment.
- **output**:
>Text and freetext fetched from the input picture.
- **requirements**:
>cv2: The OpenCV python library.

-----

#### [ods-enrich](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/ods-enrich.py)

<img src=logos/ods.png height=60>

Module to extract freetext from a .ods document.
- **features**:
>The module reads the text contained in a .ods document. The result is passed to the freetext import parser so IoCs can be extracted out of it.
- **input**:
>Attachment attribute containing a .ods document.
- **output**:
>Text and freetext parsed from the document.
- **requirements**:
>ezodf: Python package to create/manipulate OpenDocumentFormat files., pandas_ods_reader: Python library to read in ODS files.

-----

#### [odt-enrich](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/odt-enrich.py)

<img src=logos/odt.png height=60>

Module to extract freetext from a .odt document.
- **features**:
>The module reads the text contained in a .odt document. The result is passed to the freetext import parser so IoCs can be extracted out of it.
- **input**:
>Attachment attribute containing a .odt document.
- **output**:
>Text and freetext parsed from the document.
- **requirements**:
>ODT reader python library.

-----

#### [onyphe](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/onyphe.py)

<img src=logos/onyphe.jpg height=60>

Module to process a query on Onyphe.
- **features**:
>This module takes a domain, hostname, or IP address attribute as input in order to query the Onyphe API. Data fetched from the query is then parsed and MISP attributes are extracted.
- **input**:
>A domain, hostname or IP address MISP attribute.
- **output**:
>MISP attributes fetched from the Onyphe query.
- **references**:
>https://www.onyphe.io/, https://github.com/sebdraven/pyonyphe
- **requirements**:
>onyphe python library, An access to the Onyphe API (apikey)

-----

#### [onyphe_full](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/onyphe_full.py)

<img src=logos/onyphe.jpg height=60>

Module to process a full query on Onyphe.
- **features**:
>This module takes a domain, hostname, or IP address attribute as input in order to query the Onyphe API. Data fetched from the query is then parsed and MISP attributes are extracted.
>
>The parsing is here more advanced than the one on onyphe module, and is returning more attributes, since more fields of the query result are watched and parsed.
- **input**:
>A domain, hostname or IP address MISP attribute.
- **output**:
>MISP attributes fetched from the Onyphe query.
- **references**:
>https://www.onyphe.io/, https://github.com/sebdraven/pyonyphe
- **requirements**:
>onyphe python library, An access to the Onyphe API (apikey)

-----

#### [otx](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/otx.py)

<img src=logos/otx.png height=60>

Module to get information from AlienVault OTX.
- **features**:
>This module takes a MISP attribute as input to query the OTX Alienvault API. The API returns then the result of the query with some types we map into compatible types we add as MISP attributes.
- **input**:
>A MISP attribute included in the following list:
>- hostname
>- domain
>- ip-src
>- ip-dst
>- md5
>- sha1
>- sha256
>- sha512
- **output**:
>MISP attributes mapped from the result of the query on OTX, included in the following list:
>- domain
>- ip-src
>- ip-dst
>- text
>- md5
>- sha1
>- sha256
>- sha512
>- email
- **references**:
>https://www.alienvault.com/open-threat-exchange
- **requirements**:
>An access to the OTX API (apikey)

-----

#### [passivetotal](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/passivetotal.py)

<img src=logos/passivetotal.png height=60>


- **features**:
>The PassiveTotal MISP expansion module brings the datasets derived from Internet scanning directly into your MISP instance. This module supports passive DNS, historic SSL, WHOIS, and host attributes. In order to use the module, you must have a valid PassiveTotal account username and API key. Registration is free and can be done by visiting https://www.passivetotal.org/register
- **input**:
>A MISP attribute included in the following list:
>- hostname
>- domain
>- ip-src
>- ip-dst
>- x509-fingerprint-sha1
>- email-src
>- email-dst
>- target-email
>- whois-registrant-email
>- whois-registrant-phone
>- text
>- whois-registrant-name
>- whois-registrar
>- whois-creation-date
- **output**:
>MISP attributes mapped from the result of the query on PassiveTotal, included in the following list:
>- hostname
>- domain
>- ip-src
>- ip-dst
>- x509-fingerprint-sha1
>- email-src
>- email-dst
>- target-email
>- whois-registrant-email
>- whois-registrant-phone
>- text
>- whois-registrant-name
>- whois-registrar
>- whois-creation-date
>- md5
>- sha1
>- sha256
>- link
- **references**:
>https://www.passivetotal.org/register
- **requirements**:
>Passivetotal python library, An access to the PassiveTotal API (apikey)

-----

#### [pdf-enrich](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/pdf-enrich.py)

<img src=logos/pdf.jpg height=60>

Module to extract freetext from a PDF document.
- **features**:
>The module reads the text contained in a PDF document. The result is passed to the freetext import parser so IoCs can be extracted out of it.
- **input**:
>Attachment attribute containing a PDF document.
- **output**:
>Text and freetext parsed from the document.
- **requirements**:
>pdftotext: Python library to extract text from PDF.

-----

#### [pptx-enrich](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/pptx-enrich.py)

<img src=logos/pptx.png height=60>

Module to extract freetext from a .pptx document.
- **features**:
>The module reads the text contained in a .pptx document. The result is passed to the freetext import parser so IoCs can be extracted out of it.
- **input**:
>Attachment attribute containing a .pptx document.
- **output**:
>Text and freetext parsed from the document.
- **requirements**:
>pptx: Python library to read PowerPoint files.

-----

#### [qrcode](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/qrcode.py)

Module to decode QR codes.
- **features**:
>The module reads the QR code and returns the related address, which can be an URL or a bitcoin address.
- **input**:
>A QR code stored as attachment attribute.
- **output**:
>The URL or bitcoin address the QR code is pointing to.
- **requirements**:
>cv2: The OpenCV python library., pyzbar: Python library to read QR codes.

-----

#### [rbl](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/rbl.py)

Module to check an IPv4 address against known RBLs.
- **features**:
>This module takes an IP address attribute as input and queries multiple know Real-time Blackhost Lists to check if they have already seen this IP address.
>
>We display then all the information we get from those different sources.
- **input**:
>IP address attribute.
- **output**:
>Text with additional data from Real-time Blackhost Lists about the IP address.
- **references**:
>[RBLs list](https://github.com/MISP/misp-modules/blob/8817de476572a10a9c9d03258ec81ca70f3d926d/misp_modules/modules/expansion/rbl.py#L20)
- **requirements**:
>dnspython3: DNS python3 library

-----

#### [reversedns](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/reversedns.py)

Simple Reverse DNS expansion service to resolve reverse DNS from MISP attributes.
- **features**:
>The module takes an IP address as input and tries to find the hostname this IP address is resolved into.
>
>The address of the DNS resolver to use is also configurable, but if no configuration is set, we use the Google public DNS address (8.8.8.8).
>
>Please note that composite MISP attributes containing IP addresses are supported as well.
- **input**:
>An IP address attribute.
- **output**:
>Hostname attribute the input is resolved into.
- **requirements**:
>DNS python library

-----

#### [securitytrails](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/securitytrails.py)

<img src=logos/securitytrails.png height=60>

An expansion modules for SecurityTrails.
- **features**:
>The module takes a domain, hostname or IP address attribute as input and queries the SecurityTrails API with it.
>
>Multiple parsing operations are then processed on the result of the query to extract a much information as possible.
>
>From this data extracted are then mapped MISP attributes.
- **input**:
>A domain, hostname or IP address attribute.
- **output**:
>MISP attributes resulting from the query on SecurityTrails API, included in the following list:
>- hostname
>- domain
>- ip-src
>- ip-dst
>- dns-soa-email
>- whois-registrant-email
>- whois-registrant-phone
>- whois-registrant-name
>- whois-registrar
>- whois-creation-date
>- domain
- **references**:
>https://securitytrails.com/
- **requirements**:
>dnstrails python library, An access to the SecurityTrails API (apikey)

-----

#### [shodan](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/shodan.py)

<img src=logos/shodan.png height=60>

Module to query on Shodan.
- **features**:
>The module takes an IP address as input and queries the Shodan API to get some additional data about it.
- **input**:
>An IP address MISP attribute.
- **output**:
>Text with additional data about the input, resulting from the query on Shodan.
- **references**:
>https://www.shodan.io/
- **requirements**:
>shodan python library, An access to the Shodan API (apikey)

-----

#### [sigma_queries](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/sigma_queries.py)

<img src=logos/sigma.png height=60>

An expansion hover module to display the result of sigma queries.
- **features**:
>This module takes a Sigma rule attribute as input and tries all the different queries available to convert it into different formats recognized by SIEMs.
- **input**:
>A Sigma attribute.
- **output**:
>Text displaying results of queries on the Sigma attribute.
- **references**:
>https://github.com/Neo23x0/sigma/wiki
- **requirements**:
>Sigma python library

-----

#### [sigma_syntax_validator](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/sigma_syntax_validator.py)

<img src=logos/sigma.png height=60>

An expansion hover module to perform a syntax check on sigma rules.
- **features**:
>This module takes a Sigma rule attribute as input and performs a syntax check on it.
>
>It displays then that the rule is valid if it is the case, and the error related to the rule otherwise.
- **input**:
>A Sigma attribute.
- **output**:
>Text describing the validity of the Sigma rule.
- **references**:
>https://github.com/Neo23x0/sigma/wiki
- **requirements**:
>Sigma python library, Yaml python library

-----

#### [sourcecache](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/sourcecache.py)

Module to cache web pages of analysis reports, OSINT sources. The module returns a link of the cached page.
- **features**:
>This module takes a link or url attribute as input and caches the related web page. It returns then a link of the cached page.
- **input**:
>A link or url attribute.
- **output**:
>A malware-sample attribute describing the cached page.
- **references**:
>https://github.com/adulau/url_archiver
- **requirements**:
>urlarchiver: python library to fetch and archive URL on the file-system

-----

#### [stix2_pattern_syntax_validator](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/stix2_pattern_syntax_validator.py)

<img src=logos/stix.png height=60>

An expansion hover module to perform a syntax check on stix2 patterns.
- **features**:
>This module takes a STIX2 pattern attribute as input and performs a syntax check on it.
>
>It displays then that the rule is valid if it is the case, and the error related to the rule otherwise.
- **input**:
>A STIX2 pattern attribute.
- **output**:
>Text describing the validity of the STIX2 pattern.
- **references**:
>[STIX2.0 patterning specifications](http://docs.oasis-open.org/cti/stix/v2.0/cs01/part5-stix-patterning/stix-v2.0-cs01-part5-stix-patterning.html)
- **requirements**:
>stix2patterns python library

-----

#### [threatcrowd](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/threatcrowd.py)

<img src=logos/threatcrowd.png height=60>

Module to get information from ThreatCrowd.
- **features**:
>This module takes a MISP attribute as input and queries ThreatCrowd with it.
>
>The result of this query is then parsed and some data is mapped into MISP attributes in order to enrich the input attribute.
- **input**:
>A MISP attribute included in the following list:
>- hostname
>- domain
>- ip-src
>- ip-dst
>- md5
>- sha1
>- sha256
>- sha512
>- whois-registrant-email
- **output**:
>MISP attributes mapped from the result of the query on ThreatCrowd, included in the following list:
>- domain
>- ip-src
>- ip-dst
>- text
>- md5
>- sha1
>- sha256
>- sha512
>- hostname
>- whois-registrant-email
- **references**:
>https://www.threatcrowd.org/

-----

#### [threatminer](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/threatminer.py)

<img src=logos/threatminer.png height=60>

Module to get information from ThreatMiner.
- **features**:
>This module takes a MISP attribute as input and queries ThreatMiner with it.
>
>The result of this query is then parsed and some data is mapped into MISP attributes in order to enrich the input attribute.
- **input**:
>A MISP attribute included in the following list:
>- hostname
>- domain
>- ip-src
>- ip-dst
>- md5
>- sha1
>- sha256
>- sha512
- **output**:
>MISP attributes mapped from the result of the query on ThreatMiner, included in the following list:
>- domain
>- ip-src
>- ip-dst
>- text
>- md5
>- sha1
>- sha256
>- sha512
>- ssdeep
>- authentihash
>- filename
>- whois-registrant-email
>- url
>- link
- **references**:
>https://www.threatminer.org/

-----

#### [trustar_enrich](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/trustar_enrich.py)

<img src=logos/trustar.png height=60>

Module to get enrich indicators with TruSTAR.
- **features**:
>This module enriches MISP attributes with scoring and metadata from TruSTAR.
>
>The TruSTAR indicator summary is appended to the attributes along with links to any associated reports.
- **input**:
>Any of the following MISP attributes:
>- btc
>- domain
>- email-src
>- filename
>- hostname
>- ip-src
>- ip-dst
>- md5
>- sha1
>- sha256
>- url
- **output**:
>MISP attributes enriched with indicator summary data from the TruSTAR API. Data includes a severity level score and additional source and scoring info.
- **references**:
>https://docs.trustar.co/api/v13/indicators/get_indicator_summaries.html

-----

#### [urlhaus](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/urlhaus.py)

<img src=logos/urlhaus.png height=60>

Query of the URLhaus API to get additional information about the input attribute.
- **features**:
>Module using the new format of modules able to return attributes and objects.
>
>The module takes one of the attribute type specified as input, and query the URLhaus API with it. If any result is returned by the API, attributes and objects are created accordingly.
- **input**:
>A domain, hostname, url, ip, md5 or sha256 attribute.
- **output**:
>MISP attributes & objects fetched from the result of the URLhaus API query.
- **references**:
>https://urlhaus.abuse.ch/

-----

#### [urlscan](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/urlscan.py)

<img src=logos/urlscan.jpg height=60>

An expansion module to query urlscan.io.
- **features**:
>This module takes a MISP attribute as input and queries urlscan.io with it.
>
>The result of this query is then parsed and some data is mapped into MISP attributes in order to enrich the input attribute.
- **input**:
>A domain, hostname or url attribute.
- **output**:
>MISP attributes mapped from the result of the query on urlscan.io.
- **references**:
>https://urlscan.io/
- **requirements**:
>An access to the urlscan.io API

-----

#### [virustotal](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/virustotal.py)

<img src=logos/virustotal.png height=60>

Module to get advanced information from virustotal.
- **features**:
>New format of modules able to return attributes and objects.
>
>A module to take a MISP attribute as input and query the VirusTotal API to get additional data about it.
>
>Compared to the [standard VirusTotal expansion module](https://github.com/MISP/misp-modules/blob/master/misp_modules/modules/expansion/virustotal_public.py), this module is made for advanced parsing of VirusTotal report, with a recursive analysis of the elements found after the first request.
>
>Thus, it requires a higher request rate limit to avoid the API to return a 204 error (Request rate limit exceeded), and the data parsed from the different requests are returned as MISP attributes and objects, with the corresponding relations between each one of them.
- **input**:
>A domain, hash (md5, sha1, sha256 or sha512), hostname or IP address attribute.
- **output**:
>MISP attributes and objects resulting from the parsing of the VirusTotal report concerning the input attribute.
- **references**:
>https://www.virustotal.com/, https://developers.virustotal.com/reference
- **requirements**:
>An access to the VirusTotal API (apikey), with a high request rate limit.

-----

#### [virustotal_public](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/virustotal_public.py)

<img src=logos/virustotal.png height=60>

Module to get information from VirusTotal.
- **features**:
>New format of modules able to return attributes and objects.
>
>A module to take a MISP attribute as input and query the VirusTotal API to get additional data about it.
>
>Compared to the [more advanced VirusTotal expansion module](https://github.com/MISP/misp-modules/blob/master/misp_modules/modules/expansion/virustotal.py), this module is made for VirusTotal users who have a low request rate limit.
>
>Thus, it only queries the API once and returns the results that is parsed into MISP attributes and objects.
- **input**:
>A domain, hostname, ip, url or hash (md5, sha1, sha256 or sha512) attribute.
- **output**:
>MISP attributes and objects resulting from the parsing of the VirusTotal report concerning the input attribute.
- **references**:
>https://www.virustotal.com, https://developers.virustotal.com/reference
- **requirements**:
>An access to the VirusTotal API (apikey)

-----

#### [vmray_submit](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/vmray_submit.py)

<img src=logos/vmray.png height=60>

Module to submit a sample to VMRay.
- **features**:
>This module takes an attachment or malware-sample attribute as input to query the VMRay API.
>
>The sample contained within the attribute in then enriched with data from VMRay mapped into MISP attributes.
- **input**:
>An attachment or malware-sample attribute.
- **output**:
>MISP attributes mapped from the result of the query on VMRay API, included in the following list:
>- text
>- sha1
>- sha256
>- md5
>- link
- **references**:
>https://www.vmray.com/
- **requirements**:
>An access to the VMRay API (apikey & url)

-----

#### [vulndb](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/vulndb.py)

<img src=logos/vulndb.png height=60>

Module to query VulnDB (RiskBasedSecurity.com).
- **features**:
>This module takes a vulnerability attribute as input and queries VulnDB in order to get some additional data about it.
>
>The API gives the result of the query which can be displayed in the screen, and/or mapped into MISP attributes to add in the event.
- **input**:
>A vulnerability attribute.
- **output**:
>Additional data enriching the CVE input, fetched from VulnDB.
- **references**:
>https://vulndb.cyberriskanalytics.com/
- **requirements**:
>An access to the VulnDB API (apikey, apisecret)

-----

#### [vulners](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/vulners.py)

<img src=logos/vulners.png height=60>

An expansion hover module to expand information about CVE id using Vulners API.
- **features**:
>This module takes a vulnerability attribute as input and queries the Vulners API in order to get some additional data about it.
>
>The API then returns details about the vulnerability.
- **input**:
>A vulnerability attribute.
- **output**:
>Text giving additional information about the CVE in input.
- **references**:
>https://vulners.com/
- **requirements**:
>Vulners python library, An access to the Vulners API

-----

#### [whois](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/whois.py)

Module to query a local instance of uwhois (https://github.com/rafiot/uwhoisd).
- **features**:
>This module takes a domain or IP address attribute as input and queries a 'Univseral Whois proxy server' to get the correct details of the Whois query on the input value (check the references for more details about this whois server).
- **input**:
>A domain or IP address attribute.
- **output**:
>Text describing the result of a whois request for the input value.
- **references**:
>https://github.com/rafiot/uwhoisd
- **requirements**:
>uwhois: A whois python library

-----

#### [wiki](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/wiki.py)

<img src=logos/wikidata.png height=60>

An expansion hover module to extract information from Wikidata to have additional information about particular term for analysis.
- **features**:
>This module takes a text attribute as input and queries the Wikidata API. If the text attribute is clear enough to define a specific term, the API returns a wikidata link in response.
- **input**:
>Text attribute.
- **output**:
>Text attribute.
- **references**:
>https://www.wikidata.org
- **requirements**:
>SPARQLWrapper python library

-----

#### [xforceexchange](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/xforceexchange.py)

<img src=logos/xforce.png height=60>

An expansion module for IBM X-Force Exchange.
- **features**:
>This module takes a MISP attribute as input to query the X-Force API. The API returns then additional information known in their threats data, that is mapped into MISP attributes.
- **input**:
>A MISP attribute included in the following list:
>- ip-src
>- ip-dst
>- vulnerability
>- md5
>- sha1
>- sha256
- **output**:
>MISP attributes mapped from the result of the query on X-Force Exchange.
- **references**:
>https://exchange.xforce.ibmcloud.com/
- **requirements**:
>An access to the X-Force API (apikey)

-----

#### [xlsx-enrich](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/xlsx-enrich.py)

<img src=logos/xlsx.png height=60>

Module to extract freetext from a .xlsx document.
- **features**:
>The module reads the text contained in a .xlsx document. The result is passed to the freetext import parser so IoCs can be extracted out of it.
- **input**:
>Attachment attribute containing a .xlsx document.
- **output**:
>Text and freetext parsed from the document.
- **requirements**:
>pandas: Python library to perform data analysis, time series and statistics.

-----

#### [yara_query](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/yara_query.py)

<img src=logos/yara.png height=60>

An expansion & hover module to translate any hash attribute into a yara rule.
- **features**:
>The module takes a hash attribute (md5, sha1, sha256, imphash) as input, and is returning a YARA rule from it. This YARA rule is also validated using the same method as in 'yara_syntax_validator' module.
>Both hover and expansion functionalities are supported with this module, where the hover part is displaying the resulting YARA rule and the expansion part allows you to add the rule as a new attribute, as usual with expansion modules.
- **input**:
>MISP Hash attribute (md5, sha1, sha256, imphash, or any of the composite attribute with filename and one of the previous hash type).
- **output**:
>YARA rule.
- **references**:
>https://virustotal.github.io/yara/, https://github.com/virustotal/yara-python
- **requirements**:
>yara-python python library

-----

#### [yara_syntax_validator](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/yara_syntax_validator.py)

<img src=logos/yara.png height=60>

An expansion hover module to perform a syntax check on if yara rules are valid or not.
- **features**:
>This modules simply takes a YARA rule as input, and checks its syntax. It returns then a confirmation if the syntax is valid, otherwise the syntax error is displayed.
- **input**:
>YARA rule attribute.
- **output**:
>Text to inform users if their rule is valid.
- **references**:
>http://virustotal.github.io/yara/
- **requirements**:
>yara_python python library

-----

## Export Modules

#### [cef_export](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/export_mod/cef_export.py)

Module to export a MISP event in CEF format.
- **features**:
>The module takes a MISP event in input, to look every attribute. Each attribute matching with some predefined types is then exported in Common Event Format.
>Thus, there is no particular feature concerning MISP Events since any event can be exported. However, 4 configuration parameters recognized by CEF format are required and should be provided by users before exporting data: the device vendor, product and version, as well as the default severity of data.
- **input**:
>MISP Event attributes
- **output**:
>Common Event Format file
- **references**:
>https://community.softwaregrp.com/t5/ArcSight-Connectors/ArcSight-Common-Event-Format-CEF-Guide/ta-p/1589306?attachment-id=65537

-----

#### [cisco_firesight_manager_ACL_rule_export](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/export_mod/cisco_firesight_manager_ACL_rule_export.py)

<img src=logos/cisco.png height=60>

Module to export malicious network activity attributes to Cisco fireSIGHT manager block rules.
- **features**:
>The module goes through the attributes to find all the network activity ones in order to create block rules for the Cisco fireSIGHT manager.
- **input**:
>Network activity attributes (IPs, URLs).
- **output**:
>Cisco fireSIGHT manager block rules.
- **requirements**:
>Firesight manager console credentials

-----

#### [goamlexport](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/export_mod/goamlexport.py)

<img src=logos/goAML.jpg height=60>

This module is used to export MISP events containing transaction objects into GoAML format.
- **features**:
>The module works as long as there is at least one transaction object in the Event.
>
>Then in order to have a valid GoAML document, please follow these guidelines:
>- For each transaction object, use either a bank-account, person, or legal-entity object to describe the origin of the transaction, and again one of them to describe the target of the transaction.
>- Create an object reference for both origin and target objects of the transaction.
>- A bank-account object needs a signatory, which is a person object, put as object reference of the bank-account.
>- A person can have an address, which is a geolocation object, put as object reference of the person.
>
>Supported relation types for object references that are recommended for each object are the folowing:
>- transaction:
>	- 'from', 'from_my_client': Origin of the transaction - at least one of them is required.
>	- 'to', 'to_my_client': Target of the transaction - at least one of them is required.
>	- 'address': Location of the transaction - optional.
>- bank-account:
>	- 'signatory': Signatory of a bank-account - the reference from bank-account to a signatory is required, but the relation-type is optional at the moment since this reference will always describe a signatory.
>	- 'entity': Entity owning the bank account - optional.
>- person:
>	- 'address': Address of a person - optional.
- **input**:
>MISP objects (transaction, bank-account, person, legal-entity, geolocation), with references, describing financial transactions and their origin and target.
- **output**:
>GoAML format file, describing financial transactions, with their origin and target (bank accounts, persons or entities).
- **references**:
>http://goaml.unodc.org/
- **requirements**:
>PyMISP, MISP objects

-----

#### [liteexport](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/export_mod/liteexport.py)

Lite export of a MISP event.
- **features**:
>This module is simply producing a json MISP event format file, but exporting only Attributes from the Event. Thus, MISP Events exported with this module should have attributes that are not internal references, otherwise the resulting event would be empty.
- **input**:
>MISP Event attributes
- **output**:
>Lite MISP Event

-----

#### [mass_eql_export](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/export_mod/mass_eql_export.py)

<img src=logos/eql.png height=60>

Mass EQL query export for a MISP event.
- **features**:
>This module produces EQL queries for all relevant attributes in a MISP event.
- **input**:
>MISP Event attributes
- **output**:
>Text file containing one or more EQL queries
- **references**:
>https://eql.readthedocs.io/en/latest/

-----

#### [nexthinkexport](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/export_mod/nexthinkexport.py)

<img src=logos/nexthink.svg height=60>

Nexthink NXQL query export module
- **features**:
>This module export an event as Nexthink NXQL queries that can then be used in your own python3 tool or from wget/powershell
- **input**:
>MISP Event attributes
- **output**:
>Nexthink NXQL queries
- **references**:
>https://doc.nexthink.com/Documentation/Nexthink/latest/APIAndIntegrations/IntroducingtheWebAPIV2

-----

#### [osqueryexport](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/export_mod/osqueryexport.py)

<img src=logos/osquery.png height=60>

OSQuery export of a MISP event.
- **features**:
>This module export an event as osquery queries that can be used in packs or in fleet management solution like Kolide.
- **input**:
>MISP Event attributes
- **output**:
>osquery SQL queries

-----

#### [pdfexport](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/export_mod/pdfexport.py)

Simple export of a MISP event to PDF.
- **features**:
>The module takes care of the PDF file building, and work with any MISP Event. Except the requirement of reportlab, used to create the file, there is no special feature concerning the Event. Some parameters can be given through the config dict. 'MISP_base_url_for_dynamic_link' is your MISP URL, to attach an hyperlink to your event on your MISP instance from the PDF. Keep it clear to avoid hyperlinks in the generated pdf.
>  'MISP_name_for_metadata' is your CERT or MISP instance name. Used as text in the PDF' metadata
>  'Activate_textual_description' is a boolean (True or void) to activate the textual description/header abstract of an event
>  'Activate_galaxy_description' is a boolean (True or void) to activate the description of event related galaxies.
>  'Activate_related_events' is a boolean (True or void) to activate the description of related event. Be aware this might leak information on confidential events linked to the current event !
>  'Activate_internationalization_fonts' is a boolean (True or void) to activate Noto fonts instead of default fonts (Helvetica). This allows the support of CJK alphabet. Be sure to have followed the procedure to download Noto fonts (~70Mo) in the right place (/tools/pdf_fonts/Noto_TTF), to allow PyMisp to find and use them during PDF generation.
>  'Custom_fonts_path' is a text (path or void) to the TTF file of your choice, to create the PDF with it. Be aware the PDF won't support bold/italic/special style anymore with this option 
- **input**:
>MISP Event
- **output**:
>MISP Event in a PDF file.
- **references**:
>https://acrobat.adobe.com/us/en/acrobat/about-adobe-pdf.html
- **requirements**:
>PyMISP, reportlab

-----

#### [testexport](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/export_mod/testexport.py)

Skeleton export module.

-----

#### [threatStream_misp_export](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/export_mod/threatStream_misp_export.py)

<img src=logos/threatstream.png height=60>

Module to export a structured CSV file for uploading to threatStream.
- **features**:
>The module takes a MISP event in input, to look every attribute. Each attribute matching with some predefined types is then exported in a CSV format recognized by ThreatStream.
- **input**:
>MISP Event attributes
- **output**:
>ThreatStream CSV format file
- **references**:
>https://www.anomali.com/platform/threatstream, https://github.com/threatstream
- **requirements**:
>csv

-----

#### [threat_connect_export](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/export_mod/threat_connect_export.py)

<img src=logos/threatconnect.png height=60>

Module to export a structured CSV file for uploading to ThreatConnect.
- **features**:
>The module takes a MISP event in input, to look every attribute. Each attribute matching with some predefined types is then exported in a CSV format recognized by ThreatConnect.
>Users should then provide, as module configuration, the source of data they export, because it is required by the output format.
- **input**:
>MISP Event attributes
- **output**:
>ThreatConnect CSV format file
- **references**:
>https://www.threatconnect.com
- **requirements**:
>csv

-----

#### [vt_graph](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/export_mod/vt_graph.py)

<img src=logos/virustotal.png height=60>

This module is used to create a VirusTotal Graph from a MISP event.
- **features**:
>The module takes the MISP event as input and queries the VirusTotal Graph API to create a new graph out of the event.
>
>Once the graph is ready, we get the url of it, which is returned so we can view it on VirusTotal.
- **input**:
>A MISP event.
- **output**:
>Link of the VirusTotal Graph created for the event.
- **references**:
>https://www.virustotal.com/gui/graph-overview
- **requirements**:
>vt_graph_api, the python library to query the VirusTotal graph API

-----

## Import Modules

#### [csvimport](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/import_mod/csvimport.py)

Module to import MISP attributes from a csv file.
- **features**:
>In order to parse data from a csv file, a header is required to let the module know which column is matching with known attribute fields / MISP types.
>
>This header either comes from the csv file itself or is part of the configuration of the module and should be filled out in MISP plugin settings, each field separated by COMMAS. Fields that do not match with any type known in MISP or are not MISP attribute fields should be ignored in import, using a space or simply nothing between two separators (example: 'ip-src, , comment, ').
>
>If the csv file already contains a header that does not start by a '#', you should tick the checkbox 'has_header' to avoid importing it and have potential issues. You can also redefine the header even if it is already contained in the file, by following the rules for headers explained earlier. One reason why you would redefine a header is for instance when you want to skip some fields, or some fields are not valid types.
- **input**:
>CSV format file.
- **output**:
>MISP Event attributes
- **references**:
>https://tools.ietf.org/html/rfc4180, https://tools.ietf.org/html/rfc7111
- **requirements**:
>PyMISP

-----

#### [cuckooimport](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/import_mod/cuckooimport.py)

<img src=logos/cuckoo.png height=60>

Module to import Cuckoo JSON.
- **features**:
>The module simply imports MISP Attributes from a Cuckoo JSON format file. There is thus no special feature to make it work.
- **input**:
>Cuckoo JSON file
- **output**:
>MISP Event attributes
- **references**:
>https://cuckoosandbox.org/, https://github.com/cuckoosandbox/cuckoo

-----

#### [email_import](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/import_mod/email_import.py)

Module to import emails in MISP.
- **features**:
>This module can be used to import e-mail text as well as attachments and urls.
>3 configuration parameters are then used to unzip attachments, guess zip attachment passwords, and extract urls: set each one of them to True or False to process or not the respective corresponding actions.
- **input**:
>E-mail file
- **output**:
>MISP Event attributes

-----

#### [goamlimport](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/import_mod/goamlimport.py)

<img src=logos/goAML.jpg height=60>

Module to import MISP objects about financial transactions from GoAML files.
- **features**:
>Unlike the GoAML export module, there is here no special feature to import data from GoAML external files, since the module will import MISP Objects with their References on its own, as it is required for the export module to rebuild a valid GoAML document.
- **input**:
>GoAML format file, describing financial transactions, with their origin and target (bank accounts, persons or entities).
- **output**:
>MISP objects (transaction, bank-account, person, legal-entity, geolocation), with references, describing financial transactions and their origin and target.
- **references**:
>http://goaml.unodc.org/
- **requirements**:
>PyMISP

-----

#### [joe_import](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/import_mod/joe_import.py)

<img src=logos/joesandbox.png height=60>

A module to import data from a Joe Sandbox analysis json report.
- **features**:
>Module using the new format of modules able to return attributes and objects.
>
>The module returns the same results as the expansion module [joesandbox_query](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/joesandbox_query.py) using the submission link of the analysis to get the json report.
>
>
- **input**:
>Json report of a Joe Sandbox analysis.
- **output**:
>MISP attributes & objects parsed from the analysis report.
- **references**:
>https://www.joesecurity.org, https://www.joesandbox.com/

-----

#### [lastline_import](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/import_mod/lastline_import.py)

<img src=logos/lastline.png height=60>

Module to import and parse reports from Lastline analysis links.
- **features**:
>The module requires a Lastline Portal `username` and `password`.
>The module uses the new format and it is able to return MISP attributes and objects.
>The module returns the same results as the [lastline_query](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/lastline_query.py) expansion module.
- **input**:
>Link to a Lastline analysis.
- **output**:
>MISP attributes and objects parsed from the analysis report.
- **references**:
>https://www.lastline.com

-----

#### [mispjson](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/import_mod/mispjson.py)

Module to import MISP JSON format for merging MISP events.
- **features**:
>The module simply imports MISP Attributes from an other MISP Event in order to merge events together. There is thus no special feature to make it work.
- **input**:
>MISP Event
- **output**:
>MISP Event attributes

-----

#### [ocr](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/import_mod/ocr.py)

Optical Character Recognition (OCR) module for MISP.
- **features**:
>The module tries to recognize some text from an image and import the result as a freetext attribute, there is then no special feature asked to users to make it work.
- **input**:
>Image
- **output**:
>freetext MISP attribute

-----

#### [openiocimport](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/import_mod/openiocimport.py)

Module to import OpenIOC packages.
- **features**:
>The module imports MISP Attributes from OpenIOC packages, there is then no special feature for users to make it work.
- **input**:
>OpenIOC packages
- **output**:
>MISP Event attributes
- **references**:
>https://www.fireeye.com/blog/threat-research/2013/10/openioc-basics.html
- **requirements**:
>PyMISP

-----

#### [threatanalyzer_import](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/import_mod/threatanalyzer_import.py)

Module to import ThreatAnalyzer archive.zip / analysis.json files.
- **features**:
>The module imports MISP Attributes from a ThreatAnalyzer format file. This file can be either ZIP, or JSON format.
>There is by the way no special feature for users to make the module work.
- **input**:
>ThreatAnalyzer format file
- **output**:
>MISP Event attributes
- **references**:
>https://www.threattrack.com/malware-analysis.aspx

-----

#### [vmray_import](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/import_mod/vmray_import.py)

<img src=logos/vmray.png height=60>

Module to import VMRay (VTI) results.
- **features**:
>The module imports MISP Attributes from VMRay format, using the VMRay api.
>Users should then provide as the module configuration the API Key as well as the server url in order to fetch their data to import.
- **input**:
>VMRay format
- **output**:
>MISP Event attributes
- **references**:
>https://www.vmray.com/
- **requirements**:
>vmray_rest_api

-----
