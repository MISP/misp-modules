# MISP modules documentation

## Expansion Modules

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

#### [circl_passivedns](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/circl_passivedns.py)

<img src=logos/passivedns.png height=60>

Module to access CIRCL Passive DNS.
- **features**:
>This module takes a hostname, domain or ip-address (ip-src or ip-dst) attribute as input, and queries the CIRCL Passive DNS REST API to get and display information about this input.
>
>To make it work a username and a password are thus required to authenticate to the CIRCL Passive DNS API.
- **input**:
>Hostname, domain, or ip-address attribute.
- **ouput**:
>Text describing passive DNS information related to the input attribute.
- **references**:
>https://www.circl.lu/services/passive-dns/, https://datatracker.ietf.org/doc/draft-dulaunoy-dnsop-passive-dns-cof/
- **requirements**:
>pypdns: Passive DNS python library, A CIRCL passive DNS account with username & password

-----

#### [circl_passivessl](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/circl_passivessl.py)

<img src=logos/passivessl.png height=60>

Modules to access CIRCL Passive SSL.
- **features**:
>This module takes an ip-address (ip-src or ip-dst) attribute as input, and queries the CIRCL Passive SSL REST API to get and display information about this input.
>
>To make it work a username and a password are thus required to authenticate to the CIRCL Passive SSL API.
- **input**:
>Ip-address attribute.
- **output**:
>Text describing passive SSL information related to the input attribute.
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
>This module takes an IP address attribute as input and queries the CIRCL IPASN service to get additional information about the input.
- **input**:
>An IP address MISP attribute.
- **output**:
>Text describing additional information about the input after a query on the IPASN-history database.
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

Module to get information from virustotal.
- **features**:
>This module takes a MISP attribute as input and queries the VirusTotal API with it, in order to get additional data on the  input attribute.
>
>Multiple recursive requests on the API can then be processed on some attributes found in the first request. A limit can be set to restrict the number of values to query again, and at the same time the number of request submitted to the API.
>
>This limit is important because the default user VirusTotal apikey only allows to process a certain nunmber of queries per minute. As a consequence it is recommended to have a larger number of requests or a private apikey.
>
>Data is then mapped into MISP attributes.
- **input**:
>A domain, hash (md5, sha1, sha256 or sha512), hostname or IP address attribute.
- **output**:
>MISP attributes mapped from the rersult of the query on VirusTotal API.
- **references**:
>https://www.virustotal.com/
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
>The module takes care of the PDF file building, and work with any MISP Event. Except the requirement of asciidoctor, used to create the file, there is no special feature concerning the Event.
- **input**:
>MISP Event
- **output**:
>MISP Event in a PDF file.
- **references**:
>https://acrobat.adobe.com/us/en/acrobat/about-adobe-pdf.html
- **requirements**:
>PyMISP, asciidoctor

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

## Import Modules

#### [csvimport](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/import_mod/csvimport.py)

Module to import MISP attributes from a csv file.
- **features**:
>In order to parse data from a csv file, a header is required to let the module know which column is matching with known attribute fields / MISP types.
>This header is part of the configuration of the module and should be filled out in MISP plugin settings, each field separated by COMMAS. Fields that do not match with any type known in MISP can be ignored in import, using a space or simply nothing between two separators (example: 'ip-src, , comment, ').
>There is also one type that is confused and can be either a MISP attribute type or an attribute field: 'comment'. In this case, using 'attrComment' specifies that the attribute field 'comment' should be considered, otherwise it will be considered as the MISP attribute type.
>
>For each MISP attribute type, an attribute is created.
>Attribute fields that are imported are the following: value, type, category, to-ids, distribution, comment, tag.
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
