# MISP modules documentation

## Expansion Modules

#### [Abuse IPDB](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/abuseipdb.py)

AbuseIPDB MISP expansion module
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/abuseipdb.py)]

- **features**:
>

- **config**:
> - api_key
> - max_age_in_days
> - abuse_threshold

-----

#### [OSINT DigitalSide](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/apiosintds.py)

On demand query API for OSINT.digitalside.it project.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/apiosintds.py)]

- **features**:
>The module simply queries the API of OSINT.digitalside.it with a domain, ip, url or hash attribute.
>
>The result of the query is then parsed to extract additional hashes or urls. A module parameters also allows to parse the hashes related to the urls.
>
>Furthermore, it is possible to cache the urls and hashes collected over the last 7 days by OSINT.digitalside.it

- **config**:
> - STIX2_details
> - import_related
> - cache
> - cache_directory
> - cache_timeout_h
> - local_directory

- **input**:
>A domain, ip, url or hash attribute.

- **output**:
>Hashes and urls resulting from the query to OSINT.digitalside.it

- **references**:
>https://osint.digitalside.it/#About

- **requirements**:
>The apiosintDS python library to query the OSINT.digitalside.it API.

-----

#### [APIVoid](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/apivoid.py)

<img src=logos/apivoid.png height=60>

Module to query APIVoid with some domain attributes.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/apivoid.py)]

- **features**:
>This module takes a domain name and queries API Void to get the related DNS records and the SSL certificates. It returns then those pieces of data as MISP objects that can be added to the event.
>
>To make it work, a valid API key and enough credits to proceed 2 queries (0.06 + 0.07 credits) are required.

- **config**:
>apikey

- **input**:
>A domain attribute.

- **output**:
>DNS records and SSL certificates related to the domain.

- **references**:
>https://www.apivoid.com/

- **requirements**:
>A valid APIVoid API key with enough credits to proceed 2 queries

-----

#### [AssemblyLine Query](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/assemblyline_query.py)

<img src=logos/assemblyline.png height=60>

A module tu query the AssemblyLine API with a submission ID to get the submission report and parse it.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/assemblyline_query.py)]

- **features**:
>The module requires the address of the AssemblyLine server you want to query as well as your credentials used for this instance. Credentials include the used-ID and an API key or the password associated to the user-ID.
>
>The submission ID extracted from the submission link is then used to query AssemblyLine and get the full submission report. This report is parsed to extract file objects and the associated IPs, domains or URLs the files are connecting to.
>
>Some more data may be parsed in the future.

- **config**:
> - apiurl
> - user_id
> - apikey
> - password
> - verifyssl

- **input**:
>Link of an AssemblyLine submission report.

- **output**:
>MISP attributes & objects parsed from the AssemblyLine submission.

- **references**:
>https://www.cyber.gc.ca/en/assemblyline

- **requirements**:
>assemblyline_client: Python library to query the AssemblyLine rest API.

-----

#### [AssemblyLine Submit](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/assemblyline_submit.py)

<img src=logos/assemblyline.png height=60>

A module to submit samples and URLs to AssemblyLine for advanced analysis, and return the link of the submission.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/assemblyline_submit.py)]

- **features**:
>The module requires the address of the AssemblyLine server you want to query as well as your credentials used for this instance. Credentials include the user-ID and an API key or the password associated to the user-ID.
>
>If the sample or url is correctly submitted, you get then the link of the submission.

- **config**:
> - apiurl
> - user_id
> - apikey
> - password
> - verifyssl

- **input**:
>Sample, or url to submit to AssemblyLine.

- **output**:
>Link of the report generated in AssemblyLine.

- **references**:
>https://www.cyber.gc.ca/en/assemblyline

- **requirements**:
>assemblyline_client: Python library to query the AssemblyLine rest API.

-----

#### [Backscatter.io](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/backscatter_io.py)

<img src=logos/backscatter_io.png height=60>

Backscatter.io module to bring mass-scanning observations into MISP.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/backscatter_io.py)]

- **features**:
>The module takes a source or destination IP address as input and displays the information known by backscatter.io.

- **config**:
>api_key

- **input**:
>IP addresses.

- **output**:
>Text containing a history of the IP addresses especially on scanning based on backscatter.io information .

- **references**:
>https://pypi.org/project/backscatter/

- **requirements**:
>backscatter python library

-----

#### [BTC Scam Check](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/btc_scam_check.py)

<img src=logos/bitcoin.png height=60>

An expansion hover module to query a special dns blacklist to check if a bitcoin address has been abused.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/btc_scam_check.py)]

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

#### [BTC Steroids](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/btc_steroids.py)

<img src=logos/bitcoin.png height=60>

An expansion hover module to get a blockchain balance from a BTC address in MISP.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/btc_steroids.py)]

- **features**:
>

- **input**:
>btc address attribute.

- **output**:
>Text to describe the blockchain balance and the transactions related to the btc address in input.

-----

#### [Censys Enrich](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/censys_enrich.py)

An expansion module to enrich attributes in MISP by quering the censys.io API
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/censys_enrich.py)]

- **features**:
>This module takes an IP, hostname or a certificate fingerprint and attempts to enrich it by querying the Censys API.

- **config**:
> - api_id
> - api_secret

- **input**:
>IP, domain or certificate fingerprint (md5, sha1 or sha256)

- **output**:
>MISP objects retrieved from censys, including open ports, ASN, Location of the IP, x509 details

- **references**:
>https://www.censys.io

- **requirements**:
>API credentials to censys.io

-----

#### [CIRCL Passive DNS](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/circl_passivedns.py)

<img src=logos/passivedns.png height=60>

Module to access CIRCL Passive DNS.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/circl_passivedns.py)]

- **features**:
>This module takes a hostname, domain or ip-address (ip-src or ip-dst) attribute as input, and queries the CIRCL Passive DNS REST API to get the asssociated passive dns entries and return them as MISP objects.
>
>To make it work a username and a password are thus required to authenticate to the CIRCL Passive DNS API.

- **config**:
> - username
> - password

- **input**:
>Hostname, domain, or ip-address attribute.

- **ouput**:
>Passive DNS objects related to the input attribute.

- **references**:
> - https://www.circl.lu/services/passive-dns/
> - https://datatracker.ietf.org/doc/draft-dulaunoy-dnsop-passive-dns-cof/

- **requirements**:
> - pypdns: Passive DNS python library
> - A CIRCL passive DNS account with username & password

-----

#### [CIRCL Passive SSL](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/circl_passivessl.py)

<img src=logos/passivessl.png height=60>

Modules to access CIRCL Passive SSL.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/circl_passivessl.py)]

- **features**:
>This module takes an ip-address (ip-src or ip-dst) attribute as input, and queries the CIRCL Passive SSL REST API to gather the related certificates and return the corresponding MISP objects.
>
>To make it work a username and a password are required to authenticate to the CIRCL Passive SSL API.

- **config**:
> - username
> - password

- **input**:
>IP address attribute.

- **output**:
>x509 certificate objects seen by the IP address(es).

- **references**:
>https://www.circl.lu/services/passive-ssl/

- **requirements**:
> - pypssl: Passive SSL python library
> - A CIRCL passive SSL account with username & password

-----

#### [ClaamAV](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/clamav.py)

Submit file to ClamAV
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/clamav.py)]

- **features**:
>

- **config**:
>connection

-----

#### [Cluster25 Expand](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/cluster25_expand.py)

<img src=logos/cluster25.png height=60>

Module to query Cluster25 CTI.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/cluster25_expand.py)]

- **features**:
>This module takes a MISP attribute value as input to query the Cluster25CTI API. The result is then mapped into compatible MISP Objects and relative attributes.
>

- **config**:
> - api_id
> - apikey
> - base_url

- **input**:
>An Indicator value of type included in the following list:
>- domain
>- email-src
>- email-dst
>- filename
>- md5
>- sha1
>- sha256
>- ip-src
>- ip-dst
>- url
>- vulnerability
>- btc
>- xmr
> ja3-fingerprint-md5

- **output**:
>A series of c25 MISP Objects with colletion of attributes mapped from Cluster25 CTI query result.

- **references**:
>

- **requirements**:
>A Cluster25 API access (API id & key)

-----

#### [Markdown to PDF converter](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/convert_markdown_to_pdf.py)

Render the markdown (under GFM) into PDF. Requires pandoc (https://pandoc.org/), wkhtmltopdf (https://wkhtmltopdf.org/) and mermaid dependencies.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/convert_markdown_to_pdf.py)]

- **features**:
>

- **references**:
>
1. Install pandoc for your distribution
2. Install wkhtmltopdf
    - Ensure You have install the version with patched qt
    - Ensure it supports margin options
    - You can check the above by inspecting the extended help `wkhtmltopdf --extended-help`
3. Install mermaid
    - `npm install --global @mermaid-js/mermaid-cli`
4. Install the pandoc-mermaid-filter from https://github.com/DavidCruciani/pandoc-mermaid-filter
    - Easiest is to install the following:
    ```bash
        pip3 install git+https://github.com/DavidCruciani/pandoc-mermaid-filter
    ```


- **requirements**:
>pandoc

-----

#### [Country Code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/countrycode.py)

Module to expand country codes.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/countrycode.py)]

- **features**:
>The module takes a domain or a hostname as input, and returns the country it belongs to.
>
>For non country domains, a list of the most common possible extensions is used.

- **input**:
>Hostname or domain attribute.

- **output**:
>Text with the country code the input belongs to.

-----

#### [CPE Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/cpe.py)

<img src=logos/cve.png height=60>

An expansion module to query the CVE search API with a cpe code to get its related vulnerabilities.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/cpe.py)]

- **features**:
>The module takes a cpe attribute as input and queries the CVE search API to get its related vulnerabilities.  
>The list of vulnerabilities is then parsed and returned as vulnerability objects.
>
>Users can use their own CVE search API url by defining a value to the custom_API_URL parameter. If no custom API url is given, the default vulnerability.circl.lu api url is used.
>
>In order to limit the amount of data returned by CVE serach, users can also the limit parameter. With the limit set, the API returns only the requested number of vulnerabilities, sorted from the highest cvss score to the lowest one.

- **config**:
> - custom_API_URL
> - limit

- **input**:
>CPE attribute.

- **output**:
>The vulnerabilities related to the CPE.

- **references**:
>https://vulnerability.circl.lu/api/

-----

#### [CrowdSec CTI](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/crowdsec.py)

<img src=logos/crowdsec.png height=60>

Module to access CrowdSec CTI API.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/crowdsec.py)]

- **features**:
>This module enables IP lookup from CrowdSec CTI API. It provides information about the IP, such as what kind of attacks it has been participant of as seen by CrowdSec's network. It also includes enrichment by CrowdSec like background noise score, aggressivity over time etc.

- **config**:
> - api_key
> - add_reputation_tag
> - add_behavior_tag
> - add_classification_tag
> - add_mitre_technique_tag
> - add_cve_tag

- **input**:
>An IP address.

- **output**:
>IP Lookup information from CrowdSec CTI API

- **references**:
> - https://www.crowdsec.net/
> - https://docs.crowdsec.net/docs/cti_api/getting_started
> - https://app.crowdsec.net/

- **requirements**:
>A CrowdSec CTI API key. Get yours by following https://docs.crowdsec.net/docs/cti_api/getting_started/#getting-an-api-key

-----

#### [CrowdStrike Falcon](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/crowdstrike_falcon.py)

<img src=logos/crowdstrike.png height=60>

Module to query CrowdStrike Falcon.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/crowdstrike_falcon.py)]

- **features**:
>This module takes a MISP attribute as input to query a CrowdStrike Falcon API. The API returns then the result of the query with some types we map into compatible types we add as MISP attributes.
>
>Please note that composite attributes composed by at least one of the input types mentionned below (domains, IPs, hostnames) are also supported.

- **config**:
> - api_id
> - apikey

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

#### [Cuckoo Submit](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/cuckoo_submit.py)

<img src=logos/cuckoo.png height=60>

Submit files and URLs to Cuckoo Sandbox
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/cuckoo_submit.py)]

- **features**:
>The module takes a malware-sample, attachment, url or domain and submits it to Cuckoo Sandbox.
> The returned task id can be used to retrieve results when the analysis completed.

- **config**:
> - api_url
> - api_key

- **input**:
>A malware-sample or attachment for files. A url or domain for URLs.

- **output**:
>A text field containing 'Cuckoo task id: <id>'

- **references**:
> - https://cuckoosandbox.org/
> - https://cuckoo.sh/docs/

- **requirements**:
>Access to a Cuckoo Sandbox API and an API key if the API requires it. (api_url and api_key)

-----

#### [CVE Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/cve.py)

<img src=logos/vulnerability_lookyp.png height=60>

An expansion hover module to expand information about CVE id.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/cve.py)]

- **features**:
>The module takes a vulnerability attribute as input and queries Vulnerability Lookup to get additional information based on the Vulnerability ID.

- **input**:
>Vulnerability attribute.

- **output**:
>Additional information on the vulnerability, gathered from the Vulnerability Lookup API.

- **references**:
> - https://cve.circl.lu/
> - https://cve.mitre.org/

-----

#### [CVE Advanced Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/cve_advanced.py)

<img src=logos/cve.png height=60>

An expansion module to query the CIRCL CVE search API for more information about a vulnerability (CVE).
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/cve_advanced.py)]

- **features**:
>The module takes a vulnerability attribute as input and queries the CIRCL CVE search API to gather additional information.
>
>The result of the query is then parsed to return additional information about the vulnerability, like its cvss score or some references, as well as the potential related weaknesses and attack patterns.
>
>The vulnerability additional data is returned in a vulnerability MISP object, and the related additional information are put into weakness and attack-pattern MISP objects.

- **config**:
>custom_API

- **input**:
>Vulnerability attribute.

- **output**:
>Additional information about the vulnerability, such as its cvss score, some references, or the related weaknesses and attack patterns.

- **references**:
> - https://vulnerability.circl.lu
> - https://cve/mitre.org/

-----

#### [Cytomic Orion Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/cytomic_orion.py)

<img src=logos/cytomic_orion.png height=60>

An expansion module to enrich attributes in MISP by quering the Cytomic Orion API
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/cytomic_orion.py)]

- **features**:
>This module takes an MD5 hash and searches for occurrences of this hash in the Cytomic Orion database. Returns observed files and machines.

- **config**:
> - api_url
> - token_url
> - clientid
> - clientsecret
> - clientsecret
> - username
> - password
> - upload_timeframe
> - upload_tag
> - delete_tag
> - upload_ttlDays
> - upload_threat_level_id
> - limit_upload_events
> - limit_upload_attributes

- **input**:
>MD5, hash of the sample / malware to search for.

- **output**:
>MISP objects with sightings of the hash in Cytomic Orion. Includes files and machines.

- **references**:
> - https://www.vanimpe.eu/2020/03/10/integrating-misp-and-cytomic-orion/
> - https://www.cytomicmodel.com/solutions/

- **requirements**:
>Access (license) to Cytomic Orion

-----

#### [DBL Spamhaus Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/dbl_spamhaus.py)

<img src=logos/spamhaus.jpg height=60>

Checks Spamhaus DBL for a domain name.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/dbl_spamhaus.py)]

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

#### [DNS Resolver](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/dns.py)

Simple DNS expansion service to resolve IP address from MISP attributes
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/dns.py)]

- **features**:
>The module takes a domain of hostname attribute as input, and tries to resolve it. If no error is encountered, the IP address that resolves the domain is returned, otherwise the origin of the error is displayed.
>
>The address of the DNS resolver to use is also configurable, but if no configuration is set, we use the Google public DNS address (8.8.8.8).
>
>Please note that composite MISP attributes containing domain or hostname are supported as well.

- **config**:
>nameserver

- **input**:
>Domain or hostname attribute.

- **output**:
>IP address resolving the input.

- **requirements**:
>dnspython3: DNS python3 library

-----

#### [DOCX Enrich](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/docx_enrich.py)

<img src=logos/docx.png height=60>

Module to extract freetext from a .docx document.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/docx_enrich.py)]

- **features**:
>The module reads the text contained in a .docx document. The result is passed to the freetext import parser so IoCs can be extracted out of it.

- **input**:
>Attachment attribute containing a .docx document.

- **output**:
>Text and freetext parsed from the document.

- **requirements**:
>docx python library

-----

#### [DomainTools Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/domaintools.py)

<img src=logos/domaintools.png height=60>

DomainTools MISP expansion module.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/domaintools.py)]

- **features**:
>This module takes a MISP attribute as input to query the Domaintools API. The API returns then the result of the query with some types we map into compatible types we add as MISP attributes.
>
>Please note that composite attributes composed by at least one of the input types mentionned below (domains, IPs, hostnames) are also supported.

- **config**:
> - username
> - api_key

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
> - Domaintools python library
> - A Domaintools API access (username & apikey)

-----

#### [EQL Query Generator](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/eql.py)

<img src=logos/eql.png height=60>

EQL query generation for a MISP attribute.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/eql.py)]

- **features**:
>This module adds a new attribute to a MISP event containing an EQL query for a network or file attribute.

- **input**:
>A filename or ip attribute.

- **output**:
>Attribute containing EQL for a network or file attribute.

- **references**:
>https://eql.readthedocs.io/en/latest/

-----

#### [EUPI Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/eupi.py)

<img src=logos/eupi.png height=60>

A module to query the Phishing Initiative service (https://phishing-initiative.lu).
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/eupi.py)]

- **features**:
>This module takes a domain, hostname or url MISP attribute as input to query the Phishing Initiative API. The API returns then the result of the query with some information about the value queried.
>
>Please note that composite attributes containing domain or hostname are also supported.

- **config**:
> - apikey
> - url

- **input**:
>A domain, hostname or url MISP attribute.

- **output**:
>Text containing information about the input, resulting from the query on Phishing Initiative.

- **references**:
>https://phishing-initiative.eu/?lang=en

- **requirements**:
> - pyeupi: eupi python library
> - An access to the Phishing Initiative API (apikey & url)

-----

#### [URL Components Extractor](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/extract_url_components.py)

Extract URL components
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/extract_url_components.py)]

- **features**:
>

-----

#### [Farsight DNSDB Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/farsight_passivedns.py)

<img src=logos/farsight.png height=60>

Module to access Farsight DNSDB Passive DNS.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/farsight_passivedns.py)]

- **features**:
>This module takes a domain, hostname or IP address MISP attribute as input to query the Farsight Passive DNS API.
>  The results of rdata and rrset lookups are then returned and parsed into passive-dns objects.
>
>An API key is required to submit queries to the API.
>  It is also possible to define a custom server URL, and to set a limit of results to get.
>  This limit is set for each lookup, which means we can have an up to the limit number of passive-dns objects resulting from an rdata query about an IP address, but an up to the limit number of passive-dns objects for each lookup queries about a domain or a hostname (== twice the limit).

- **config**:
> - apikey
> - server
> - limit
> - flex_queries

- **input**:
>A domain, hostname or IP address MISP attribute.

- **output**:
>Passive-dns objects, resulting from the query on the Farsight Passive DNS API.

- **references**:
> - https://www.farsightsecurity.com/
> - https://docs.dnsdb.info/dnsdb-api/

- **requirements**:
>An access to the Farsight Passive DNS API (apikey)

-----

#### [GeoIP ASN Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/geoip_asn.py)

<img src=logos/maxmind.png height=60>

Query a local copy of the Maxmind Geolite ASN database (MMDB format)
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/geoip_asn.py)]

- **features**:
>The module takes an IP address attribute as input and queries a local copy of the Maxmind's Geolite database to get information about the related AS number.

- **config**:
>local_geolite_db

- **descrption**:
>An expansion module to query a local copy of Maxmind's Geolite database with an IP address, in order to get information about its related AS number.

- **input**:
>An IP address MISP attribute.

- **output**:
>Text containing information about the AS number of the IP address.

- **references**:
>https://www.maxmind.com/en/home

- **requirements**:
>A local copy of Maxmind's Geolite database

-----

#### [GeoIP City Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/geoip_city.py)

<img src=logos/maxmind.png height=60>

An expansion module to query a local copy of Maxmind's Geolite database with an IP address, in order to get information about the city where it is located.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/geoip_city.py)]

- **features**:
>The module takes an IP address attribute as input and queries a local copy of the Maxmind's Geolite database to get information about the city where this IP address is located.

- **config**:
>local_geolite_db

- **input**:
>An IP address MISP attribute.

- **output**:
>Text containing information about the city where the IP address is located.

- **references**:
>https://www.maxmind.com/en/home

- **requirements**:
>A local copy of Maxmind's Geolite database

-----

#### [GeoIP Country Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/geoip_country.py)

<img src=logos/maxmind.png height=60>

Query a local copy of Maxminds Geolite database, updated for MMDB format
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/geoip_country.py)]

- **features**:
>This module takes an IP address MISP attribute as input and queries a local copy of the Maxmind's Geolite database to get information about the location of this IP address.
>
>Please note that composite attributes domain|ip are also supported.

- **config**:
>local_geolite_db

- **input**:
>An IP address MISP Attribute.

- **output**:
>Text containing information about the location of the IP address.

- **references**:
>https://www.maxmind.com/en/home

- **requirements**:
>A local copy of Maxmind's Geolite database

-----

#### [Google Safe Browsing Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/google_safe_browsing.py)

Google safe browsing expansion module
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/google_safe_browsing.py)]

- **features**:
>

- **config**:
>api_key

-----

#### [Google Search](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/google_search.py)

<img src=logos/google.png height=60>

An expansion hover module to expand google search information about an URL
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/google_search.py)]

- **features**:
>The module takes an url as input to query the Google search API. The result of the query is then return as raw text.

- **input**:
>An url attribute.

- **output**:
>Text containing the result of a Google search on the input url.

- **references**:
>https://github.com/abenassi/Google-Search-API

- **requirements**:
>The python Google Search API library

-----

#### [Google Threat Intelligence Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/google_threat_intelligence.py)

<img src=logos/google_threat_intelligence.png height=60>

An expansion module to have the observable's threat score assessed by Google Threat Intelligence.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/google_threat_intelligence.py)]

- **features**:
>GTI assessment for the given observable, this include information about level of severity, a clear verdict (malicious, suspicious, undetected and benign) and additional information provided by the Mandiant expertise combined with the VirusTotal database.
>
>[Output example screeshot](https://github.com/MISP/MISP/assets/4747608/e275db2f-bb1e-4413-8cc0-ec3cb05e0414)

- **config**:
> - apikey
> - event_limit
> - proxy_host
> - proxy_port
> - proxy_username
> - proxy_password

- **input**:
>A domain, hash (md5, sha1, sha256 or sha512), hostname or IP address attribute.

- **output**:
>Text fields containing the threat score, the severity, the verdict and the threat label of the observable inspected.

- **references**:
> - https://www.virustotal.com/
> - https://gtidocs.virustotal.com/reference

- **requirements**:
>An access to the Google Threat Intelligence API (apikey), with a high request rate limit.

-----

#### [GreyNoise Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/greynoise.py)

<img src=logos/greynoise.png height=60>

Module to query IP and CVE information from GreyNoise
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/greynoise.py)]

- **features**:
>This module supports: 1) Query an IP from GreyNoise to see if it is internet background noise or a common business service 2) Query a CVE from GreyNoise to see the total number of internet scanners looking for the CVE in the last 7 days.

- **config**:
> - api_key
> - api_type

- **input**:
>An IP address or CVE ID

- **output**:
>IP Lookup information or CVE scanning profile for past 7 days

- **references**:
> - https://greynoise.io/
> - https://docs.greyniose.io/
> - https://www.greynoise.io/viz/account/

- **requirements**:
>A Greynoise API key. Both Enterprise (Paid) and Community (Free) API keys are supported, however Community API users will only be able to perform IP lookups.

-----

#### [Hashdd Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/hashdd.py)

A hover module to check hashes against hashdd.com including NSLR dataset.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/hashdd.py)]

- **features**:
>This module takes a hash attribute as input to check its known level, using the hashdd API. This information is then displayed.

- **input**:
>A hash MISP attribute (md5).

- **output**:
>Text describing the known level of the hash in the hashdd databases.

- **references**:
>https://hashdd.com/

-----

#### [CIRCL Hashlookup Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/hashlookup.py)

<img src=logos/circl.png height=60>

An expansion module to query the CIRCL hashlookup services to find it if a hash is part of a known set such as NSRL.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/hashlookup.py)]

- **features**:
>The module takes file hashes as input such as a MD5 or SHA1.
> It queries the public CIRCL.lu hashlookup service and return all the hits if the hashes are known in an existing dataset. The module can be configured with a custom hashlookup url if required.
> The module can be used an hover module but also an expansion model to add related MISP objects.
>

- **config**:
>custom_API

- **input**:
>File hashes (MD5, SHA1)

- **output**:
>Object with the filename associated hashes if the hash is part of a known set.

- **references**:
>https://www.circl.lu/services/hashlookup/

-----

#### [Have I Been Pwned Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/hibp.py)

<img src=logos/hibp.png height=60>

Module to access haveibeenpwned.com API.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/hibp.py)]

- **features**:
>The module takes an email address as input and queries haveibeenpwned.com API to find additional information about it. This additional information actually tells if any account using the email address has already been compromised in a data breach.

- **config**:
>api_key

- **input**:
>An email address

- **output**:
>Additional information about the email address.

- **references**:
>https://haveibeenpwned.com/

-----

#### [HTML to Markdown](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/html_to_markdown.py)

Expansion module to fetch the html content from an url and convert it into markdown.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/html_to_markdown.py)]

- **features**:
>The module take an URL as input and the HTML content is fetched from it. This content is then converted into markdown that is returned as text.

- **input**:
>URL attribute.

- **output**:
>Markdown content converted from the HTML fetched from the url.

- **requirements**:
>The markdownify python library

-----

#### [HYAS Insight Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/hyasinsight.py)

<img src=logos/hyas.png height=60>

HYAS Insight integration to MISP provides direct, high volume access to HYAS Insight data. It enables investigators and analysts to understand and defend against cyber adversaries and their infrastructure.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/hyasinsight.py)]

- **features**:
>This Module takes the IP Address, Domain, URL, Email, Phone Number, MD5, SHA1, Sha256, SHA512 MISP Attributes as input to query the HYAS Insight API.
> The results of the HYAS Insight API are than are then returned and parsed into Hyas Insight Objects. 
>
>An API key is required to submit queries to the HYAS Insight API.
>

- **config**:
>apikey

- **input**:
>A MISP attribute of type IP Address(ip-src, ip-dst), Domain(hostname, domain), Email Address(email, email-src, email-dst, target-email, whois-registrant-email), Phone Number(phone-number, whois-registrant-phone), MDS(md5, x509-fingerprint-md5, ja3-fingerprint-md5, hassh-md5, hasshserver-md5), SHA1(sha1, x509-fingerprint-sha1), SHA256(sha256, x509-fingerprint-sha256), SHA512(sha512)

- **output**:
>Hyas Insight objects, resulting from the query on the HYAS Insight API.

- **references**:
>https://www.hyas.com/hyas-insight/

- **requirements**:
>A HYAS Insight API Key.

-----

#### [Intel471 Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/intel471.py)

<img src=logos/intel471.png height=60>

Module to access Intel 471
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/intel471.py)]

- **features**:
>The module uses the Intel471 python library to query the Intel471 API with the value of the input attribute. The result of the query is then returned as freetext so the Freetext import parses it.

- **config**:
> - email
> - authkey

- **descrption**:
>An expansion module to query Intel471 in order to get additional information about a domain, ip address, email address, url or hash.

- **input**:
>A MISP attribute whose type is included in the following list:
>- hostname
>- domain
>- url
>- ip-src
>- ip-dst
>- email-src
>- email-dst
>- target-email
>- whois-registrant-email
>- whois-registrant-name
>- md5
>- sha1
>- sha256

- **output**:
>Freetext

- **references**:
>https://public.intel471.com/

- **requirements**:
>The intel471 python library

-----

#### [IP2Location.io Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/ip2locationio.py)

<img src=logos/ip2locationio.png height=60>

An expansion module to query IP2Location.io to gather more information on a given IP address.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/ip2locationio.py)]

- **features**:
>The module takes an IP address attribute as input and queries the IP2Location.io API.  
>Free plan user will get the basic geolocation informaiton, and different subsription plan will get more information on the IP address. 
> Refer to [pricing page](https://www.ip2location.io/pricing) for more information on data available for each plan. 
>
>More information on the responses content is available in the [documentation](https://www.ip2location.io/ip2location-documentation).

- **config**:
>key

- **input**:
>IP address attribute.

- **output**:
>Additional information on the IP address, such as geolocation, proxy and so on. Refer to the Response Format section in https://www.ip2location.io/ip2location-documentation to find out the full format of the data returned.

- **references**:
>https://www.ip2location.io/ip2location-documentation

- **requirements**:
>An IP2Location.io token

-----

#### [IPASN-History Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/ipasn.py)

Module to query an IP ASN history service (https://github.com/D4-project/IPASN-History).
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/ipasn.py)]

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

#### [IPInfo.io Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/ipinfo.py)

<img src=logos/ipinfo.png height=60>

An expansion module to query ipinfo.io to gather more information on a given IP address.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/ipinfo.py)]

- **features**:
>The module takes an IP address attribute as input and queries the ipinfo.io API.  
>The geolocation information on the IP address is always returned.
>
>Depending on the subscription plan, the API returns different pieces of information then:
>- With a basic plan (free) you get the AS number and the AS organisation name concatenated in the `org` field.
>- With a paid subscription, the AS information is returned in the `asn` field with additional AS information, and depending on which plan the user has, you can also get information on the privacy method used to protect the IP address, the related domains, or the point of contact related to the IP address in case of an abuse.
>
>More information on the responses content is available in the [documentation](https://ipinfo.io/developers).

- **config**:
>token

- **input**:
>IP address attribute.

- **output**:
>Additional information on the IP address, like its geolocation, the autonomous system it is included in, and the related domain(s).

- **references**:
>https://ipinfo.io/developers

- **requirements**:
>An ipinfo.io token

-----

#### [IPQualityScore Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/ipqs_fraud_and_risk_scoring.py)

<img src=logos/ipqualityscore.png height=60>

IPQualityScore MISP Expansion Module for IP reputation, Email Validation, Phone Number Validation, Malicious Domain and Malicious URL Scanner.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/ipqs_fraud_and_risk_scoring.py)]

- **features**:
>This Module takes the IP Address, Domain, URL, Email and Phone Number MISP Attributes as input to query the IPQualityScore API.
> The results of the IPQualityScore API are than returned as IPQS Fraud and Risk Scoring Object. 
> The object contains a copy of the enriched attribute with added tags presenting the verdict based on fraud score,risk score and other attributes from IPQualityScore.

- **config**:
>apikey

- **input**:
>A MISP attribute of type IP Address(ip-src, ip-dst), Domain(hostname, domain), URL(url, uri), Email Address(email, email-src, email-dst, target-email, whois-registrant-email) and Phone Number(phone-number, whois-registrant-phone).

- **output**:
>IPQualityScore object, resulting from the query on the IPQualityScore API.

- **references**:
>https://www.ipqualityscore.com/

- **requirements**:
>A IPQualityScore API Key.

-----

#### [IPRep Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/iprep.py)

Module to query IPRep data for IP addresses.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/iprep.py)]

- **features**:
>This module takes an IP address attribute as input and queries the database from packetmail.net to get some information about the reputation of the IP.

- **config**:
>apikey

- **input**:
>An IP address MISP attribute.

- **output**:
>Text describing additional information about the input after a query on the IPRep API.

- **references**:
>https://github.com/mahesh557/packetmail

- **requirements**:
>An access to the packetmail API (apikey)

-----

#### [Ninja Template Rendering](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/jinja_template_rendering.py)

Render the template with the data passed
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/jinja_template_rendering.py)]

- **features**:
>

-----

#### [Joe Sandbox Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/joesandbox_query.py)

<img src=logos/joesandbox.png height=60>

Query Joe Sandbox API with a submission url to get the json report and extract its data that is parsed and converted into MISP attributes and objects.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/joesandbox_query.py)]

- **features**:
>Module using the new format of modules able to return attributes and objects.
>
>The module returns the same results as the import module [joe_import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/joe_import.py) taking directly the json report as input.
>
>Even if the introspection will allow all kinds of links to call this module, obviously only the ones presenting a sample or url submission in the Joe Sandbox API will return results.
>
>To make it work you will need to fill the 'apikey' configuration with your Joe Sandbox API key and provide a valid link as input.

- **config**:
> - apiurl
> - apikey
> - import_executable
> - import_mitre_attack

- **input**:
>Link of a Joe Sandbox sample or url submission.

- **output**:
>MISP attributes & objects parsed from the analysis report.

- **references**:
> - https://www.joesecurity.org
> - https://www.joesandbox.com/

- **requirements**:
>jbxapi: Joe Sandbox API python3 library

-----

#### [Joe Sandbox Submit](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/joesandbox_submit.py)

<img src=logos/joesandbox.png height=60>

A module to submit files or URLs to Joe Sandbox for an advanced analysis, and return the link of the submission.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/joesandbox_submit.py)]

- **features**:
>The module requires a Joe Sandbox API key to submit files or URL, and returns the link of the submitted analysis.
>
>It is then possible, when the analysis is completed, to query the Joe Sandbox API to get the data related to the analysis, using the [joesandbox_query module](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/joesandbox_query.py) directly on this submission link.

- **config**:
> - apiurl
> - apikey
> - accept-tac
> - report-cache
> - systems

- **input**:
>Sample, url (or domain) to submit to Joe Sandbox for an advanced analysis.

- **output**:
>Link of the report generated in Joe Sandbox.

- **references**:
> - https://www.joesecurity.org
> - https://www.joesandbox.com/

- **requirements**:
>jbxapi: Joe Sandbox API python3 library

-----

#### [Lastline Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/lastline_query.py)

<img src=logos/lastline.png height=60>

Deprecation notice: this module will be deprecated by December 2021, please use vmware_nsx module.

Query Lastline with an analysis link and parse the report into MISP attributes and objects.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/lastline_query.py)]

- **features**:
>The module requires a Lastline Portal `username` and `password`.
>The module uses the new format and it is able to return MISP attributes and objects.
>The module returns the same results as the [lastline_import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/lastline_import.py) import module.

- **config**:
> - username
> - password
> - verify_ssl

- **input**:
>Link to a Lastline analysis.

- **output**:
>MISP attributes and objects parsed from the analysis report.

- **references**:
>https://www.lastline.com

-----

#### [Lastline Submit](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/lastline_submit.py)

<img src=logos/lastline.png height=60>

Deprecation notice: this module will be deprecated by December 2021, please use vmware_nsx module.

Module to submit a file or URL to Lastline.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/lastline_submit.py)]

- **features**:
>The module requires a Lastline Analysis `api_token` and `key`.
>When the analysis is completed, it is possible to import the generated report by feeding the analysis link to the [lastline_query](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/lastline_query.py) module.

- **config**:
> - url
> - api_token
> - key

- **input**:
>File or URL to submit to Lastline.

- **output**:
>Link to the report generated by Lastline.

- **references**:
>https://www.lastline.com

-----

#### [Macaddress.io Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/macaddress_io.py)

<img src=logos/macaddress_io.png height=60>

MISP hover module for macaddress.io
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/macaddress_io.py)]

- **features**:
>This module takes a MAC address attribute as input and queries macaddress.io for additional information.
>
>This information contains data about:
>- MAC address details
>- Vendor details
>- Block details

- **config**:
>api_key

- **input**:
>MAC address MISP attribute.

- **output**:
>Text containing information on the MAC address fetched from a query on macaddress.io.

- **references**:
> - https://macaddress.io/
> - https://github.com/CodeLineFi/maclookup-python

- **requirements**:
> - maclookup: macaddress.io python library
> - An access to the macaddress.io API (apikey)

-----

#### [Macvendors Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/macvendors.py)

<img src=logos/macvendors.png height=60>

Module to access Macvendors API.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/macvendors.py)]

- **features**:
>The module takes a MAC address as input and queries macvendors.com for some information about it. The API returns the name of the vendor related to the address.

- **config**:
>user-agent

- **input**:
>A MAC address.

- **output**:
>Additional information about the MAC address.

- **references**:
> - https://macvendors.com/
> - https://macvendors.com/api

-----

#### [MalShare Upload](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/malshare_upload.py)

Module to push malware samples to MalShare
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/malshare_upload.py)]

- **config**:
>malshare_apikey

- **requirements**:
>requests library

-----

#### [Malware Bazaar Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/malwarebazaar.py)

Query Malware Bazaar to get additional information about the input hash.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/malwarebazaar.py)]

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

#### [McAfee MVISION Insights Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/mcafee_insights_enrich.py)

Lookup McAfee MVISION Insights Details
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/mcafee_insights_enrich.py)]

- **features**:
>

- **config**:
> - api_key
> - client_id
> - client_secret

-----

#### [GeoIP Enrichment](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/mmdb_lookup.py)

<img src=logos/circl.png height=60>

A hover and expansion module to enrich an ip with geolocation and ASN information from an mmdb server instance, such as CIRCL's ip.circl.lu.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/mmdb_lookup.py)]

- **features**:
>The module takes an IP address related attribute as input.
> It queries the public CIRCL.lu mmdb-server instance, available at ip.circl.lu, by default. The module can be configured with a custom mmdb server url if required.
> It is also possible to filter results on 1 db_source by configuring db_source_filter.

- **config**:
> - custom_API
> - db_source_filter
> - max_country_info_qt

- **input**:
>An IP address attribute (for example ip-src or ip-src|port).

- **output**:
>Geolocation and asn objects.

- **references**:
> - https://data.public.lu/fr/datasets/geo-open-ip-address-geolocation-per-country-in-mmdb-format/
> - https://github.com/adulau/mmdb-server

-----

#### [MWDB Submit](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/mwdb.py)

Module to push malware samples to a MWDB instance
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/mwdb.py)]

- **features**:
>An expansion module to push malware samples to a MWDB (https://github.com/CERT-Polska/mwdb-core) instance. This module does not push samples to a sandbox. This can be achieved via Karton (connected to the MWDB). Does: * Upload of attachment or malware sample to MWDB * Tags of events and/or attributes are added to MWDB. * Comment of the MISP attribute is added to MWDB. * A link back to the MISP event is added to MWDB via the MWDB attribute.  * A link to the MWDB attribute is added as an enrichted attribute to the MISP event.

- **config**:
> - mwdb_apikey
> - mwdb_url
> - mwdb_misp_attribute
> - mwdb_public
> - include_tags_event
> - include_tags_attribute

- **input**:
>Attachment or malware sample

- **output**:
>Link attribute that points to the sample at the MWDB instane

- **requirements**:
>* mwdblib installed (pip install mwdblib) ; * (optional) keys.py file to add tags of events/attributes to MWDB * (optional) MWDB attribute created for the link back to MISP (defined in mwdb_misp_attribute)

-----

#### [OCR Enrich](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/ocr_enrich.py)

Module to process some optical character recognition on pictures.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/ocr_enrich.py)]

- **features**:
>The module takes an attachment attributes as input and process some optical character recognition on it. The text found is then passed to the Freetext importer to extract potential IoCs.

- **input**:
>A picture attachment.

- **output**:
>Text and freetext fetched from the input picture.

- **requirements**:
>cv2: The OpenCV python library.

-----

#### [ODS Enrich](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/ods_enrich.py)

<img src=logos/ods.png height=60>

Module to extract freetext from a .ods document.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/ods_enrich.py)]

- **features**:
>The module reads the text contained in a .ods document. The result is passed to the freetext import parser so IoCs can be extracted out of it.

- **input**:
>Attachment attribute containing a .ods document.

- **output**:
>Text and freetext parsed from the document.

- **requirements**:
> - ezodf: Python package to create/manipulate OpenDocumentFormat files.
> - pandas_ods_reader: Python library to read in ODS files.

-----

#### [ODT Enrich](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/odt_enrich.py)

<img src=logos/odt.png height=60>

Module to extract freetext from a .odt document.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/odt_enrich.py)]

- **features**:
>The module reads the text contained in a .odt document. The result is passed to the freetext import parser so IoCs can be extracted out of it.

- **input**:
>Attachment attribute containing a .odt document.

- **output**:
>Text and freetext parsed from the document.

- **requirements**:
>ODT reader python library.

-----

#### [Onion Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/onion_lookup.py)

<img src=logos/onion.png height=60>

MISP module using the MISP standard. Uses the onion-lookup service to get information about an onion.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/onion_lookup.py)]

- **references**:
>https://onion.ail-project.org/

-----

#### [Onyphe Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/onyphe.py)

<img src=logos/onyphe.jpg height=60>

Module to process a query on Onyphe.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/onyphe.py)]

- **features**:
>This module takes a domain, hostname, or IP address attribute as input in order to query the Onyphe API. Data fetched from the query is then parsed and MISP attributes are extracted.

- **config**:
>apikey

- **input**:
>A domain, hostname or IP address MISP attribute.

- **output**:
>MISP attributes fetched from the Onyphe query.

- **references**:
> - https://www.onyphe.io/
> - https://github.com/sebdraven/pyonyphe

- **requirements**:
> - onyphe python library
> - An access to the Onyphe API (apikey)

-----

#### [Onyphe Full Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/onyphe_full.py)

<img src=logos/onyphe.jpg height=60>

Module to process a full query on Onyphe.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/onyphe_full.py)]

- **features**:
>This module takes a domain, hostname, or IP address attribute as input in order to query the Onyphe API. Data fetched from the query is then parsed and MISP attributes are extracted.
>
>The parsing is here more advanced than the one on onyphe module, and is returning more attributes, since more fields of the query result are watched and parsed.

- **config**:
>apikey

- **input**:
>A domain, hostname or IP address MISP attribute.

- **output**:
>MISP attributes fetched from the Onyphe query.

- **references**:
> - https://www.onyphe.io/
> - https://github.com/sebdraven/pyonyphe

- **requirements**:
> - onyphe python library
> - An access to the Onyphe API (apikey)

-----

#### [AlienVault OTX Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/otx.py)

<img src=logos/otx.png height=60>

Module to get information from AlienVault OTX.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/otx.py)]

- **features**:
>This module takes a MISP attribute as input to query the OTX Alienvault API. The API returns then the result of the query with some types we map into compatible types we add as MISP attributes.

- **config**:
>apikey

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

#### [Passive SSH Enrichment](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/passive_ssh.py)

An expansion module to enrich, SSH key fingerprints and IP addresses with information collected by passive-ssh
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/passive_ssh.py)]

- **features**:
>

- **config**:
> - custom_api_url
> - api_user
> - api_key

-----

#### [PassiveTotal Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/passivetotal.py)

<img src=logos/passivetotal.png height=60>

The PassiveTotal MISP expansion module brings the datasets derived from Internet scanning directly into your MISP instance. This module supports passive DNS, historic SSL, WHOIS, and host attributes. In order to use the module, you must have a valid PassiveTotal account username and API key. Registration is free and can be done by visiting https://www.passivetotal.org/register
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/passivetotal.py)]

- **features**:
>The PassiveTotal MISP expansion module brings the datasets derived from Internet scanning directly into your MISP instance. This module supports passive DNS, historic SSL, WHOIS, and host attributes. In order to use the module, you must have a valid PassiveTotal account username and API key. Registration is free and can be done by visiting https://www.passivetotal.org/register

- **config**:
> - username
> - api_key

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
> - Passivetotal python library
> - An access to the PassiveTotal API (apikey)

-----

#### [PDF Enrich](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/pdf_enrich.py)

<img src=logos/pdf.jpg height=60>

Module to extract freetext from a PDF document.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/pdf_enrich.py)]

- **features**:
>The module reads the text contained in a PDF document. The result is passed to the freetext import parser so IoCs can be extracted out of it.

- **input**:
>Attachment attribute containing a PDF document.

- **output**:
>Text and freetext parsed from the document.

- **requirements**:
>pdftotext: Python library to extract text from PDF.

-----

#### [PPTX Enrich](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/pptx_enrich.py)

<img src=logos/pptx.png height=60>

Module to extract freetext from a .pptx document.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/pptx_enrich.py)]

- **features**:
>The module reads the text contained in a .pptx document. The result is passed to the freetext import parser so IoCs can be extracted out of it.

- **input**:
>Attachment attribute containing a .pptx document.

- **output**:
>Text and freetext parsed from the document.

- **requirements**:
>pptx: Python library to read PowerPoint files.

-----

#### [Qintel QSentry Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/qintel_qsentry.py)

<img src=logos/qintel.png height=60>

A hover and expansion module which queries Qintel QSentry for ip reputation data
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/qintel_qsentry.py)]

- **features**:
>This module takes an ip-address (ip-src or ip-dst) attribute as input, and queries the Qintel QSentry API to retrieve ip reputation data

- **config**:
> - token
> - remote

- **input**:
>ip address attribute

- **ouput**:
>Objects containing the enriched IP, threat tags, last seen attributes and associated Autonomous System information

- **references**:
>https://www.qintel.com/products/qsentry/

- **requirements**:
>A Qintel API token

-----

#### [QR Code Decode](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/qrcode.py)

Module to decode QR codes.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/qrcode.py)]

- **features**:
>The module reads the QR code and returns the related address, which can be an URL or a bitcoin address.

- **input**:
>A QR code stored as attachment attribute.

- **output**:
>The URL or bitcoin address the QR code is pointing to.

- **requirements**:
> - cv2: The OpenCV python library.
> - pyzbar: Python library to read QR codes.

-----

#### [RandomcoinDB Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/ransomcoindb.py)

Module to access the ransomcoinDB (see https://ransomcoindb.concinnity-risks.com)
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/ransomcoindb.py)]

- **features**:
>The module takes either a hash attribute or a btc attribute as input to query the ransomcoinDB API for some additional data.
>
>If the input is a btc address, we will get the associated hashes returned in a file MISP object. If we query ransomcoinDB with a hash, the response contains the associated btc addresses returned as single MISP btc attributes.

- **config**:
>api-key

- **descrption**:
>Module to access the ransomcoinDB with a hash or btc address attribute and get the associated btc address of hashes.

- **input**:
>A hash (md5, sha1 or sha256) or btc attribute.

- **output**:
>Hashes associated to a btc address or btc addresses associated to a hash.

- **references**:
>https://ransomcoindb.concinnity-risks.com

- **requirements**:
>A ransomcoinDB API key.

-----

#### [Real-time Blackhost Lists Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/rbl.py)

Module to check an IPv4 address against known RBLs.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/rbl.py)]

- **features**:
>This module takes an IP address attribute as input and queries multiple know Real-time Blackhost Lists to check if they have already seen this IP address.
>
>We display then all the information we get from those different sources.

- **config**:
>timeout

- **input**:
>IP address attribute.

- **output**:
>Text with additional data from Real-time Blackhost Lists about the IP address.

- **references**:
>[RBLs list](https://github.com/MISP/misp-modules/blob/8817de476572a10a9c9d03258ec81ca70f3d926d/misp_modules/modules/expansion/rbl.py#L20)

- **requirements**:
>dnspython3: DNS python3 library

-----

#### [Recorded Future Enrich](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/recordedfuture.py)

<img src=logos/recordedfuture.png height=60>

Module to enrich attributes with threat intelligence from Recorded Future.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/recordedfuture.py)]

- **features**:
>Enrich an attribute to add a custom enrichment object to the event. The object contains a copy of the enriched attribute with added tags presenting risk score and triggered risk rules from Recorded Future. Malware and Threat Actors related to the enriched indicator in Recorded Future is matched against MISP's galaxy clusters and applied as galaxy tags. The custom enrichment object also includes a list of related indicators from Recorded Future (IP's, domains, hashes, URL's and vulnerabilities) added as additional attributes.

- **config**:
> - token
> - proxy_host
> - proxy_port
> - proxy_username
> - proxy_password

- **input**:
>A MISP attribute of one of the following types: ip, ip-src, ip-dst, domain, hostname, md5, sha1, sha256, uri, url, vulnerability, weakness.

- **output**:
>A MISP object containing a copy of the enriched attribute with added tags from Recorded Future and a list of new attributes related to the enriched attribute.

- **references**:
>https://www.recordedfuture.com/

- **requirements**:
>A Recorded Future API token.

-----

#### [Reverse DNS](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/reversedns.py)

Simple Reverse DNS expansion service to resolve reverse DNS from MISP attributes.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/reversedns.py)]

- **features**:
>The module takes an IP address as input and tries to find the hostname this IP address is resolved into.
>
>The address of the DNS resolver to use is also configurable, but if no configuration is set, we use the Google public DNS address (8.8.8.8).
>
>Please note that composite MISP attributes containing IP addresses are supported as well.

- **config**:
>nameserver

- **input**:
>An IP address attribute.

- **output**:
>Hostname attribute the input is resolved into.

- **requirements**:
>DNS python library

-----

#### [SecurityTrails Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/securitytrails.py)

<img src=logos/securitytrails.png height=60>

An expansion modules for SecurityTrails.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/securitytrails.py)]

- **features**:
>The module takes a domain, hostname or IP address attribute as input and queries the SecurityTrails API with it.
>
>Multiple parsing operations are then processed on the result of the query to extract a much information as possible.
>
>From this data extracted are then mapped MISP attributes.

- **config**:
>apikey

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
> - dnstrails python library
> - An access to the SecurityTrails API (apikey)

-----

#### [Shodan Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/shodan.py)

<img src=logos/shodan.png height=60>

Module to query on Shodan.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/shodan.py)]

- **features**:
>The module takes an IP address as input and queries the Shodan API to get some additional data about it.

- **config**:
>apikey

- **input**:
>An IP address MISP attribute.

- **output**:
>Text with additional data about the input, resulting from the query on Shodan.

- **references**:
>https://www.shodan.io/

- **requirements**:
> - shodan python library
> - An access to the Shodan API (apikey)

-----

#### [Sigma Rule Converter](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/sigma_queries.py)

<img src=logos/sigma.png height=60>

An expansion hover module to display the result of sigma queries.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/sigma_queries.py)]

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

#### [Sigma Syntax Validator](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/sigma_syntax_validator.py)

<img src=logos/sigma.png height=60>

An expansion hover module to perform a syntax check on sigma rules.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/sigma_syntax_validator.py)]

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
> - Sigma python library
> - Yaml python library

-----

#### [SigMF Expansion](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/sigmf_expand.py)

Expands a SigMF Recording object into a SigMF Expanded Recording object, extracts a SigMF archive into a SigMF Recording object.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/sigmf_expand.py)]

- **features**:
>

-----

#### [Socialscan Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/socialscan.py)

A hover module to get information on the availability of an email address or username on some online platforms.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/socialscan.py)]

- **features**:
>The module takes an email address or username as input and check its availability on some online platforms. The results for each platform are then returned to see if the email address or the username is used, available or if there is an issue with it.

- **input**:
>An email address or usename attribute.

- **output**:
>Text containing information about the availability of an email address or a username in some online platforms.

- **references**:
>https://github.com/iojw/socialscan

- **requirements**:
>The socialscan python library

-----

#### [SophosLabs Intelix Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/sophoslabs_intelix.py)

<img src=logos/sophoslabs_intelix.svg height=60>

An expansion module to query the Sophoslabs intelix API to get additional information about an ip address, url, domain or sha256 attribute.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/sophoslabs_intelix.py)]

- **features**:
>The module takes an ip address, url, domain or sha256 attribute and queries the SophosLabs Intelix API with the attribute value. The result of this query is a SophosLabs Intelix hash report, or an ip or url lookup, that is then parsed and returned in a MISP object.

- **config**:
> - client_id
> - client_secret

- **input**:
>An ip address, url, domain or sha256 attribute.

- **output**:
>SophosLabs Intelix report and lookup objects

- **references**:
>https://aws.amazon.com/marketplace/pp/B07SLZPMCS

- **requirements**:
>A client_id and client_secret pair to authenticate to the SophosLabs Intelix API

-----

#### [URL Archiver](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/sourcecache.py)

Module to cache web pages of analysis reports, OSINT sources. The module returns a link of the cached page.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/sourcecache.py)]

- **features**:
>This module takes a link or url attribute as input and caches the related web page. It returns then a link of the cached page.

- **config**:
>archivepath

- **input**:
>A link or url attribute.

- **output**:
>A malware-sample attribute describing the cached page.

- **references**:
>https://github.com/adulau/url_archiver

- **requirements**:
>urlarchiver: python library to fetch and archive URL on the file-system

-----

#### [Stairwell Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/stairwell.py)

<img src=logos/stairwell.png height=60>

Module to query the Stairwell API to get additional information about the input hash attribute
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/stairwell.py)]

- **features**:
>The module takes a hash attribute as input and queries Stariwell's API to fetch additional data about it. The result, if the payload is observed in Stariwell, is a file object describing the file the input hash is related to.

- **config**:
>apikey

- **input**:
>A hash attribute (md5, sha1, sha256).

- **output**:
>File object related to the input attribute found on Stairwell platform.

- **references**:
> - https://stairwell.com
> - https://docs.stairwell.com

- **requirements**:
>Access to Stairwell platform (apikey)

-----

#### [STIX2 Pattern Syntax Validator](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/stix2_pattern_syntax_validator.py)

<img src=logos/stix.png height=60>

An expansion hover module to perform a syntax check on stix2 patterns.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/stix2_pattern_syntax_validator.py)]

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

#### [ThreatCrowd Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/threatcrowd.py)

<img src=logos/threatcrowd.png height=60>

Module to get information from ThreatCrowd.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/threatcrowd.py)]

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

#### [ThreadFox Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/threatfox.py)

Module to search for an IOC on ThreatFox by abuse.ch.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/threatfox.py)]

- **features**:
>

-----

#### [ThreatMiner Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/threatminer.py)

<img src=logos/threatminer.png height=60>

Module to get information from ThreatMiner.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/threatminer.py)]

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

#### [Triage Submit](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/triage_submit.py)

Module to submit samples to tria.ge
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/triage_submit.py)]

- **config**:
> - apikey
> - url_mode

-----

#### [TruSTAR Enrich](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/trustar_enrich.py)

<img src=logos/trustar.png height=60>

Module to get enrich indicators with TruSTAR.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/trustar_enrich.py)]

- **features**:
>This module enriches MISP attributes with scoring and metadata from TruSTAR.
>
>The TruSTAR indicator summary is appended to the attributes along with links to any associated reports.

- **config**:
> - user_api_key
> - user_api_secret
> - enclave_ids

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

#### [URLhaus Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/urlhaus.py)

<img src=logos/urlhaus.png height=60>

Query of the URLhaus API to get additional information about the input attribute.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/urlhaus.py)]

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

#### [URLScan Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/urlscan.py)

<img src=logos/urlscan.jpg height=60>

An expansion module to query urlscan.io.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/urlscan.py)]

- **features**:
>This module takes a MISP attribute as input and queries urlscan.io with it.
>
>The result of this query is then parsed and some data is mapped into MISP attributes in order to enrich the input attribute.

- **config**:
>apikey

- **input**:
>A domain, hostname or url attribute.

- **output**:
>MISP attributes mapped from the result of the query on urlscan.io.

- **references**:
>https://urlscan.io/

- **requirements**:
>An access to the urlscan.io API

-----

#### [VARIoT db Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/variotdbs.py)

<img src=logos/variot.png height=60>

An expansion module to query the VARIoT db API for more information about a vulnerability.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/variotdbs.py)]

- **features**:
>The module takes a vulnerability attribute as input and queries que VARIoT db API to gather additional information.
>
>The `vuln` endpoint is queried first to look for additional information about the vulnerability itself.
>
>The `exploits` endpoint is also queried then to look for the information of the potential related exploits, which are parsed and added to the results using the `exploit` object template.

- **config**:
>API_key

- **input**:
>Vulnerability attribute.

- **output**:
>Additional information about the vulnerability, as it is stored on the VARIoT db, about the vulnerability itself, and the potential related exploits.

- **references**:
>https://www.variotdbs.pl/

- **requirements**:
>A VARIoT db API key (if you do not want to be limited to 100 queries / day)

-----

#### [VirusTotal v3 Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/virustotal.py)

<img src=logos/virustotal.png height=60>

Enrich observables with the VirusTotal v3 API
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/virustotal.py)]

- **features**:
>New format of modules able to return attributes and objects.
>
>A module to take a MISP attribute as input and query the VirusTotal API to get additional data about it.
>
>Compared to the [standard VirusTotal expansion module](https://github.com/MISP/misp-modules/blob/main/misp_modules/modules/expansion/virustotal_public.py), this module is made for advanced parsing of VirusTotal report, with a recursive analysis of the elements found after the first request.
>
>Thus, it requires a higher request rate limit to avoid the API to return a 204 error (Request rate limit exceeded), and the data parsed from the different requests are returned as MISP attributes and objects, with the corresponding relations between each one of them.

- **config**:
> - apikey
> - event_limit
> - proxy_host
> - proxy_port
> - proxy_username
> - proxy_password

- **input**:
>A domain, hash (md5, sha1, sha256 or sha512), hostname or IP address attribute.

- **output**:
>MISP attributes and objects resulting from the parsing of the VirusTotal report concerning the input attribute.

- **references**:
> - https://www.virustotal.com/
> - https://docs.virustotal.com/reference/overview

- **requirements**:
>An access to the VirusTotal API (apikey), with a high request rate limit.

-----

#### [VirusTotal Public API Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/virustotal_public.py)

<img src=logos/virustotal.png height=60>

Enrich observables with the VirusTotal v3 public API
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/virustotal_public.py)]

- **features**:
>New format of modules able to return attributes and objects.
>
>A module to take a MISP attribute as input and query the VirusTotal API to get additional data about it.
>
>Compared to the [more advanced VirusTotal expansion module](https://github.com/MISP/misp-modules/blob/main/misp_modules/modules/expansion/virustotal.py), this module is made for VirusTotal users who have a low request rate limit.
>
>Thus, it only queries the API once and returns the results that is parsed into MISP attributes and objects.

- **config**:
> - apikey
> - proxy_host
> - proxy_port
> - proxy_username
> - proxy_password

- **input**:
>A domain, hostname, ip, url or hash (md5, sha1, sha256 or sha512) attribute.

- **output**:
>MISP attributes and objects resulting from the parsing of the VirusTotal report concerning the input attribute.

- **references**:
> - https://www.virustotal.com
> - https://docs.virustotal.com/reference/overview

- **requirements**:
>An access to the VirusTotal API (apikey)

-----

#### [VirusTotal Upload](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/virustotal_upload.py)

<img src=logos/virustotal.png height=60>

Module to push malware samples to VirusTotal
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/virustotal_upload.py)]

- **config**:
>virustotal_apikey

- **requirements**:
>requests library

-----

#### [VMRay Submit](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/vmray_submit.py)

<img src=logos/vmray.png height=60>

Module to submit a sample to VMRay.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/vmray_submit.py)]

- **features**:
>This module takes an attachment or malware-sample attribute as input to query the VMRay API.
>
>The sample contained within the attribute in then enriched with data from VMRay mapped into MISP attributes.

- **config**:
> - apikey
> - url
> - shareable
> - do_not_reanalyze
> - do_not_include_vmrayjobids

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

#### [VMware NSX Defender Enrich](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/vmware_nsx.py)

<img src=logos/vmware_nsx.png height=60>

Module to enrich a file or URL with VMware NSX Defender.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/vmware_nsx.py)]

- **features**:
>This module takes an IoC such as file hash, file attachment, malware-sample or url as input to query VMware NSX Defender.
>
>The IoC is then enriched with data from VMware NSX Defender.

- **config**:
> - analysis_url
> - analysis_verify_ssl
> - analysis_key
> - analysis_api_token
> - vt_key
> - misp_url
> - misp_verify_ssl
> - misp_key

- **input**:
>File hash, attachment or URL to be enriched with VMware NSX Defender.

- **output**:
>Objects and tags generated by VMware NSX Defender.

- **references**:
>https://www.vmware.com

- **requirements**:
>The module requires a VMware NSX Defender Analysis `api_token` and `key`.

-----

#### [VulnDB Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/vulndb.py)

<img src=logos/vulndb.png height=60>

Module to query VulnDB (RiskBasedSecurity.com).
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/vulndb.py)]

- **features**:
>This module takes a vulnerability attribute as input and queries VulnDB in order to get some additional data about it.
>
>The API gives the result of the query which can be displayed in the screen, and/or mapped into MISP attributes to add in the event.

- **config**:
> - apikey
> - apisecret
> - discard_dates
> - discard_external_references
> - discard_cvss
> - discard_productinformation
> - discard_classification
> - discard_cpe

- **input**:
>A vulnerability attribute.

- **output**:
>Additional data enriching the CVE input, fetched from VulnDB.

- **references**:
>https://vulndb.cyberriskanalytics.com/

- **requirements**:
>An access to the VulnDB API (apikey, apisecret)

-----

#### [Vulnerability Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/vulnerability_lookup.py)

<img src=logos/vulnerability_lookup.png height=60>

An expansion module to query Vulnerability Lookup
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/vulnerability_lookup.py)]

- **features**:
>The module takes a vulnerability attribute as input and queries Vulnerability Lookup to gather additional information based on the Vulnerability ID. The result of the query is then parsed and converted into MISP content which can be added to the original event to enrich the input attribute.

- **input**:
>Vulnerability Attribute

- **output**:
>Additional information on the vulnerability, gathered from the Vulnerability Lookup API.

- **references**:
>https://vulnerability.circl.lu

-----

#### [Vulners Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/vulners.py)

<img src=logos/vulners.png height=60>

An expansion hover module to expand information about CVE id using Vulners API.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/vulners.py)]

- **features**:
>This module takes a vulnerability attribute as input and queries the Vulners API in order to get some additional data about it.
>
>The API then returns details about the vulnerability.

- **config**:
>apikey

- **input**:
>A vulnerability attribute.

- **output**:
>Text giving additional information about the CVE in input.

- **references**:
>https://vulners.com/

- **requirements**:
> - Vulners python library
> - An access to the Vulners API

-----

#### [Vysion Enrich](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/vysion.py)

<img src=logos/vysion.png height=60>

Module to enrich the information by making use of the Vysion API.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/vysion.py)]

- **features**:
>This module gets correlated information from Byron Labs' dark web intelligence database. With this you will get several objects containing information related to, for example, an organization victim of a ransomware attack.

- **config**:
> - apikey
> - event_limit
> - proxy_host
> - proxy_port
> - proxy_username
> - proxy_password

- **input**:
>company(target-org), country, info, BTC, XMR and DASH address.

- **output**:
>MISP objects containing title, link to our webapp and TOR, i2p or clearnet URLs.

- **references**:
> - https://vysion.ai/
> - https://developers.vysion.ai/
> - https://github.com/ByronLabs/vysion-cti/tree/main

- **requirements**:
> - Vysion python library
> - Vysion API Key

-----

#### [Whois Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/whois.py)

Module to query a local instance of uwhois (https://github.com/rafiot/uwhoisd).
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/whois.py)]

- **features**:
>This module takes a domain or IP address attribute as input and queries a 'Univseral Whois proxy server' to get the correct details of the Whois query on the input value (check the references for more details about this whois server).

- **config**:
> - server
> - port

- **input**:
>A domain or IP address attribute.

- **output**:
>Text describing the result of a whois request for the input value.

- **references**:
>https://github.com/Lookyloo/uwhoisd

- **requirements**:
>uwhois: A whois python library

-----

#### [WhoisFreaks Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/whoisfreaks.py)

<img src=logos/whoisfreaks.png height=60>

An expansion module for https://whoisfreaks.com/ that will provide an enriched analysis of the provided domain, including WHOIS and DNS information.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/whoisfreaks.py)]

- **features**:
>The module takes a domain as input and queries the Whoisfreaks API with it.
>
>Some parsing operations are then processed on the result of the query to extract as much information as possible.
>
>After this we map the extracted data to MISP attributes.

- **config**:
>apikey

- **input**:
>A domain whose Data is required

- **output**:
>MISP attributes resulting from the query on Whoisfreaks API, included in the following list:
>- domain
>- dns-soa-email
>- whois-registrant-email
>- whois-registrant-phone
>- whois-registrant-name
>- whois-registrar
>- whois-creation-date
>- domain

- **references**:
>https://whoisfreaks.com/

- **requirements**:
>An access to the Whoisfreaks API_KEY

-----

#### [Wikidata Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/wiki.py)

<img src=logos/wikidata.png height=60>

An expansion hover module to extract information from Wikidata to have additional information about particular term for analysis.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/wiki.py)]

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

#### [IBM X-Force Exchange Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/xforceexchange.py)

<img src=logos/xforce.png height=60>

An expansion module for IBM X-Force Exchange.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/xforceexchange.py)]

- **features**:
>This module takes a MISP attribute as input to query the X-Force API. The API returns then additional information known in their threats data, that is mapped into MISP attributes.

- **config**:
> - apikey
> - apipassword

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

#### [XLXS Enrich](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/xlsx_enrich.py)

<img src=logos/xlsx.png height=60>

Module to extract freetext from a .xlsx document.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/xlsx_enrich.py)]

- **features**:
>The module reads the text contained in a .xlsx document. The result is passed to the freetext import parser so IoCs can be extracted out of it.

- **input**:
>Attachment attribute containing a .xlsx document.

- **output**:
>Text and freetext parsed from the document.

- **requirements**:
>pandas: Python library to perform data analysis, time series and statistics.

-----

#### [YARA Rule Generator](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/yara_query.py)

<img src=logos/yara.png height=60>

The module takes a hash attribute (md5, sha1, sha256, imphash) as input, and is returning a YARA rule from it.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/yara_query.py)]

- **features**:
>The module takes a hash attribute (md5, sha1, sha256, imphash) as input, and is returning a YARA rule from it. This YARA rule is also validated using the same method as in 'yara_syntax_validator' module.
>Both hover and expansion functionalities are supported with this module, where the hover part is displaying the resulting YARA rule and the expansion part allows you to add the rule as a new attribute, as usual with expansion modules.

- **input**:
>MISP Hash attribute (md5, sha1, sha256, imphash, or any of the composite attribute with filename and one of the previous hash type).

- **output**:
>YARA rule.

- **references**:
> - https://virustotal.github.io/yara/
> - https://github.com/virustotal/yara-python

- **require_standard_format**:
>True

- **requirements**:
>yara-python python library

-----

#### [YARA Syntax Validator](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/yara_syntax_validator.py)

<img src=logos/yara.png height=60>

An expansion hover module to perform a syntax check on if yara rules are valid or not.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/yara_syntax_validator.py)]

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

#### [Yeti Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/yeti.py)

<img src=logos/yeti.png height=60>

Module to process a query on Yeti.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/yeti.py)]

- **features**:
>This module add context and links between observables using yeti

- **config**:
> - apikey
> - url

- **input**:
>A domain, hostname,IP, sha256,sha1, md5, url of MISP attribute.

- **output**:
>MISP attributes and objects fetched from the Yeti instances.

- **references**:
> - https://github.com/yeti-platform/yeti
> - https://github.com/sebdraven/pyeti

- **requirements**:
> - pyeti
> - API key 

-----

## Export Modules

#### [CEF Export](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/export_mod/cef_export.py)

Module to export a MISP event in CEF format.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/export_mod/cef_export.py)]

- **features**:
>The module takes a MISP event in input, to look every attribute. Each attribute matching with some predefined types is then exported in Common Event Format.
>Thus, there is no particular feature concerning MISP Events since any event can be exported. However, 4 configuration parameters recognized by CEF format are required and should be provided by users before exporting data: the device vendor, product and version, as well as the default severity of data.

- **config**:
> - Default_Severity
> - Device_Vendor
> - Device_Product
> - Device_Version

- **input**:
>MISP Event attributes

- **output**:
>Common Event Format file

- **references**:
>https://community.softwaregrp.com/t5/ArcSight-Connectors/ArcSight-Common-Event-Format-CEF-Guide/ta-p/1589306?attachment-id=65537

-----

#### [Cisco fireSIGHT blockrule Export](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/export_mod/cisco_firesight_manager_ACL_rule_export.py)

<img src=logos/cisco.png height=60>

Module to export malicious network activity attributes to Cisco fireSIGHT manager block rules.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/export_mod/cisco_firesight_manager_ACL_rule_export.py)]

- **features**:
>The module goes through the attributes to find all the network activity ones in order to create block rules for the Cisco fireSIGHT manager.

- **config**:
> - fmc_ip_addr
> - fmc_login
> - fmc_pass
> - domain_id
> - acpolicy_id

- **input**:
>Network activity attributes (IPs, URLs).

- **output**:
>Cisco fireSIGHT manager block rules.

- **requirements**:
>Firesight manager console credentials

-----

#### [Microsoft Defender for Endpoint KQL Export](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/export_mod/defender_endpoint_export.py)

<img src=logos/defender_endpoint.png height=60>

Defender for Endpoint KQL hunting query export module
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/export_mod/defender_endpoint_export.py)]

- **features**:
>This module export an event as Defender for Endpoint KQL queries that can then be used in your own python3 or Powershell tool. If you are using Microsoft Sentinel, you can directly connect your MISP instance to Sentinel and then create queries using the `ThreatIntelligenceIndicator` table to match events against imported IOC.

- **config**:
>Period

- **input**:
>MISP Event attributes

- **output**:
>Defender for Endpoint KQL queries

- **references**:
>https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/advanced-hunting-schema-reference

-----

#### [GoAML Export](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/export_mod/goamlexport.py)

<img src=logos/goAML.jpg height=60>

This module is used to export MISP events containing transaction objects into GoAML format.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/export_mod/goamlexport.py)]

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

- **config**:
>rentity_id

- **input**:
>MISP objects (transaction, bank-account, person, legal-entity, geolocation), with references, describing financial transactions and their origin and target.

- **output**:
>GoAML format file, describing financial transactions, with their origin and target (bank accounts, persons or entities).

- **references**:
>http://goaml.unodc.org/

- **require_standard_format**:
>True

- **requirements**:
> - PyMISP
> - MISP objects

-----

#### [Lite Export](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/export_mod/liteexport.py)

Lite export of a MISP event.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/export_mod/liteexport.py)]

- **features**:
>This module is simply producing a json MISP event format file, but exporting only Attributes from the Event. Thus, MISP Events exported with this module should have attributes that are not internal references, otherwise the resulting event would be empty.

- **config**:
>indent_json_export

- **input**:
>MISP Event attributes

- **output**:
>Lite MISP Event

-----

#### [EQL Query Export](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/export_mod/mass_eql_export.py)

<img src=logos/eql.png height=60>

Export MISP event in Event Query Language
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/export_mod/mass_eql_export.py)]

- **features**:
>This module produces EQL queries for all relevant attributes in a MISP event.

- **input**:
>MISP Event attributes

- **output**:
>Text file containing one or more EQL queries

- **references**:
>https://eql.readthedocs.io/en/latest/

-----

#### [Nexthink NXQL Export](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/export_mod/nexthinkexport.py)

<img src=logos/nexthink.svg height=60>

Nexthink NXQL query export module
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/export_mod/nexthinkexport.py)]

- **features**:
>This module export an event as Nexthink NXQL queries that can then be used in your own python3 tool or from wget/powershell

- **config**:
>Period

- **input**:
>MISP Event attributes

- **output**:
>Nexthink NXQL queries

- **references**:
>https://doc.nexthink.com/Documentation/Nexthink/latest/APIAndIntegrations/IntroducingtheWebAPIV2

-----

#### [OSQuery Export](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/export_mod/osqueryexport.py)

<img src=logos/osquery.png height=60>

OSQuery export of a MISP event.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/export_mod/osqueryexport.py)]

- **features**:
>This module export an event as osquery queries that can be used in packs or in fleet management solution like Kolide.

- **input**:
>MISP Event attributes

- **output**:
>osquery SQL queries

-----

#### [Event to PDF Export](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/export_mod/pdfexport.py)

Simple export of a MISP event to PDF.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/export_mod/pdfexport.py)]

- **features**:
>The module takes care of the PDF file building, and work with any MISP Event. Except the requirement of reportlab, used to create the file, there is no special feature concerning the Event. Some parameters can be given through the config dict. 'MISP_base_url_for_dynamic_link' is your MISP URL, to attach an hyperlink to your event on your MISP instance from the PDF. Keep it clear to avoid hyperlinks in the generated pdf.
>  'MISP_name_for_metadata' is your CERT or MISP instance name. Used as text in the PDF' metadata
>  'Activate_textual_description' is a boolean (True or void) to activate the textual description/header abstract of an event
>  'Activate_galaxy_description' is a boolean (True or void) to activate the description of event related galaxies.
>  'Activate_related_events' is a boolean (True or void) to activate the description of related event. Be aware this might leak information on confidential events linked to the current event !
>  'Activate_internationalization_fonts' is a boolean (True or void) to activate Noto fonts instead of default fonts (Helvetica). This allows the support of CJK alphabet. Be sure to have followed the procedure to download Noto fonts (~70Mo) in the right place (/tools/pdf_fonts/Noto_TTF), to allow PyMisp to find and use them during PDF generation.
>  'Custom_fonts_path' is a text (path or void) to the TTF file of your choice, to create the PDF with it. Be aware the PDF won't support bold/italic/special style anymore with this option 

- **config**:
> - MISP_base_url_for_dynamic_link
> - MISP_name_for_metadata
> - Activate_textual_description
> - Activate_galaxy_description
> - Activate_related_events
> - Activate_internationalization_fonts
> - Custom_fonts_path

- **input**:
>MISP Event

- **output**:
>MISP Event in a PDF file.

- **references**:
>https://acrobat.adobe.com/us/en/acrobat/about-adobe-pdf.html

- **require_standard_format**:
>True

- **requirements**:
> - PyMISP
> - reportlab

-----

#### [ThreatStream Export](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/export_mod/threatStream_misp_export.py)

<img src=logos/threatstream.png height=60>

Module to export a structured CSV file for uploading to threatStream.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/export_mod/threatStream_misp_export.py)]

- **features**:
>The module takes a MISP event in input, to look every attribute. Each attribute matching with some predefined types is then exported in a CSV format recognized by ThreatStream.

- **input**:
>MISP Event attributes

- **output**:
>ThreatStream CSV format file

- **references**:
> - https://www.anomali.com/platform/threatstream
> - https://github.com/threatstream

- **requirements**:
>csv

-----

#### [ThreadConnect Export](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/export_mod/threat_connect_export.py)

<img src=logos/threatconnect.png height=60>

Module to export a structured CSV file for uploading to ThreatConnect.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/export_mod/threat_connect_export.py)]

- **features**:
>The module takes a MISP event in input, to look every attribute. Each attribute matching with some predefined types is then exported in a CSV format recognized by ThreatConnect.
>Users should then provide, as module configuration, the source of data they export, because it is required by the output format.

- **config**:
>Default_Source

- **input**:
>MISP Event attributes

- **output**:
>ThreatConnect CSV format file

- **references**:
>https://www.threatconnect.com

- **requirements**:
>csv

-----

#### [VirusTotal Collections Export](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/export_mod/virustotal_collections.py)

<img src=logos/virustotal.png height=60>

Creates a VT Collection from an event iocs.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/export_mod/virustotal_collections.py)]

- **features**:
>This export module which takes advantage of a new endpoint in VT APIv3 to create VT Collections from IOCs contained in a MISP event. With this module users will be able to create a collection just using the Download as... button.

- **config**:
> - vt_api_key
> - proxy_host
> - proxy_port
> - proxy_username
> - proxy_password

- **input**:
>A domain, hash (md5, sha1, sha256 or sha512), hostname, url or IP address attribute.

- **output**:
>A VirusTotal collection in VT.

- **references**:
> - https://www.virustotal.com/
> - https://blog.virustotal.com/2021/11/introducing-virustotal-collections.html

- **requirements**:
>An access to the VirusTotal API (apikey).

-----

#### [VirusTotal Graph Export](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/export_mod/vt_graph.py)

<img src=logos/virustotal.png height=60>

This module is used to create a VirusTotal Graph from a MISP event.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/export_mod/vt_graph.py)]

- **features**:
>The module takes the MISP event as input and queries the VirusTotal Graph API to create a new graph out of the event.
>
>Once the graph is ready, we get the url of it, which is returned so we can view it on VirusTotal.

- **config**:
> - vt_api_key
> - fetch_information
> - private
> - fetch_vt_enterprise
> - expand_one_level
> - user_editors
> - user_viewers
> - group_editors
> - group_viewers

- **input**:
>A MISP event.

- **output**:
>Link of the VirusTotal Graph created for the event.

- **references**:
>https://www.virustotal.com/gui/graph-overview

- **requirements**:
>vt_graph_api, the python library to query the VirusTotal graph API

-----

#### [YARA Rule Export](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/export_mod/yara_export.py)

<img src=logos/yara.png height=60>

This module is used to export MISP events to YARA.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/export_mod/yara_export.py)]

- **features**:
>The module will dynamically generate YARA rules for attributes that are marked as to IDS. Basic metadata about the event is added to the rule.
>Attributes that are already YARA rules are also exported, with a rewritten rule name.

- **input**:
>Attributes and Objects.

- **output**:
>A YARA file that can be used with the YARA scanning tool.

- **references**:
>https://virustotal.github.io/yara/

- **requirements**:
>yara-python python library

-----

## Import Modules

#### [PDNS COF Importer](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/cof2misp.py)

Passive DNS Common Output Format (COF) MISP importer
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/cof2misp.py)]

- **features**:
>Takes as input a valid COF file or the output of the dnsdbflex utility and creates MISP objects for the input.

- **input**:
>Passive DNS output in Common Output Format (COF)

- **output**:
>MISP objects

- **references**:
>https://tools.ietf.org/id/draft-dulaunoy-dnsop-passive-dns-cof-08.html

- **requirements**:
>PyMISP

-----

#### [CSV Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/csvimport.py)

Module to import MISP attributes from a csv file.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/csvimport.py)]

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
> - https://tools.ietf.org/html/rfc4180
> - https://tools.ietf.org/html/rfc7111

- **requirements**:
>PyMISP

-----

#### [Cuckoo Sandbox Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/cuckooimport.py)

<img src=logos/cuckoo.png height=60>

Module to import Cuckoo JSON.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/cuckooimport.py)]

- **features**:
>Import a Cuckoo archive (zipfile or bzip2 tarball), either downloaded manually or exported from the API (/tasks/report/<task_id>/all).

- **input**:
>Cuckoo JSON file

- **output**:
>MISP Event attributes

- **references**:
> - https://cuckoosandbox.org/
> - https://github.com/cuckoosandbox/cuckoo

-----

#### [Email Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/email_import.py)

Email import module for MISP
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/email_import.py)]

- **features**:
>This module can be used to import e-mail text as well as attachments and urls.
>3 configuration parameters are then used to unzip attachments, guess zip attachment passwords, and extract urls: set each one of them to True or False to process or not the respective corresponding actions.

- **config**:
> - unzip_attachments
> - guess_zip_attachment_passwords
> - extract_urls

- **input**:
>E-mail file

- **output**:
>MISP Event attributes

-----

#### [GoAML Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/goamlimport.py)

<img src=logos/goAML.jpg height=60>

Module to import MISP objects about financial transactions from GoAML files.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/goamlimport.py)]

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

#### [Import Blueprint](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/import_blueprint.py)

Generic blueprint to be copy-pasted to quickly boostrap creation of import module.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/import_blueprint.py)]

- **features**:
>

-----

#### [Joe Sandbox Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/joe_import.py)

<img src=logos/joesandbox.png height=60>

A module to import data from a Joe Sandbox analysis json report.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/joe_import.py)]

- **features**:
>Module using the new format of modules able to return attributes and objects.
>
>The module returns the same results as the expansion module [joesandbox_query](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/joesandbox_query.py) using the submission link of the analysis to get the json report.

- **input**:
>Json report of a Joe Sandbox analysis.

- **output**:
>MISP attributes & objects parsed from the analysis report.

- **references**:
> - https://www.joesecurity.org
> - https://www.joesandbox.com/

-----

#### [Lastline Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/lastline_import.py)

<img src=logos/lastline.png height=60>

Deprecation notice: this module will be deprecated by December 2021, please use vmware_nsx module.

Module to import and parse reports from Lastline analysis links.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/lastline_import.py)]

- **features**:
>The module requires a Lastline Portal `username` and `password`.
>The module uses the new format and it is able to return MISP attributes and objects.
>The module returns the same results as the [lastline_query](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/lastline_query.py) expansion module.

- **config**:
> - username
> - password
> - verify_ssl

- **input**:
>Link to a Lastline analysis.

- **output**:
>MISP attributes and objects parsed from the analysis report.

- **references**:
>https://www.lastline.com

-----

#### [MISP JSON Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/mispjson.py)

Module to import MISP JSON format for merging MISP events.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/mispjson.py)]

- **features**:
>The module simply imports MISP Attributes from an other MISP Event in order to merge events together. There is thus no special feature to make it work.

- **input**:
>MISP Event

- **output**:
>MISP Event attributes

-----

#### [OCR Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/ocr.py)

Optical Character Recognition (OCR) module for MISP.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/ocr.py)]

- **features**:
>The module tries to recognize some text from an image and import the result as a freetext attribute, there is then no special feature asked to users to make it work.

- **input**:
>Image

- **output**:
>freetext MISP attribute

-----

#### [OpenIOC Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/openiocimport.py)

Module to import OpenIOC packages.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/openiocimport.py)]

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

#### [TAXII 2.1 Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/taxii21.py)

Import content from a TAXII 2.1 server
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/taxii21.py)]

- **features**:
>

- **config**:
>stix_object_limit

- **requirements**:
> - misp-lib-stix2
> - misp-stix

-----

#### [ThreadAnalyzer Sandbox Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/threatanalyzer_import.py)

Module to import ThreatAnalyzer archive.zip / analysis.json files.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/threatanalyzer_import.py)]

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

#### [URL Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/url_import.py)

Simple URL import tool with Faup
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/url_import.py)]

- **features**:
>

-----

#### [VMRay API Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/vmray_import.py)

<img src=logos/vmray.png height=60>

Module to import VMRay (VTI) results.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/vmray_import.py)]

- **features**:
>The module imports MISP Attributes from VMRay format, using the VMRay api.
>Users should then provide as the module configuration the API Key as well as the server url in order to fetch their data to import.

- **config**:
> - apikey
> - url
> - disable_tags
> - disable_misp_objects
> - ignore_analysis_finished

- **input**:
>VMRay format

- **output**:
>MISP Event attributes

- **references**:
>https://www.vmray.com/

- **requirements**:
>vmray_rest_api

-----

#### [VMRay Summary JSON Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/vmray_summary_json_import.py)

Import a VMRay Summary JSON report.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/vmray_summary_json_import.py)]

- **features**:
>

- **config**:
>disable_tags

-----

## Action Modules

#### [Mattermost](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/action_mod/mattermost.py)

Simplistic module to send message to a Mattermost channel.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/action_mod/mattermost.py)]

- **features**:
>

- **config**:
>{'params': {'mattermost_hostname': {'type': 'string', 'description': 'The Mattermost domain or URL', 'value': 'example.mattermost.com'}, 'bot_access_token': {'type': 'string', 'description': 'Access token generated when you created the bot account'}, 'channel_id': {'type': 'string', 'description': 'The channel you added the bot to'}, 'message_template': {'type': 'large_string', 'description': 'The template to be used to generate the message to be posted', 'value': 'The **template** will be rendered using *Jinja2*!', 'jinja_supported': True}}, 'blocking': False, 'support_filters': True, 'expect_misp_core_format': False}

-----

#### [Slack](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/action_mod/slack.py)

Simplistic module to send messages to a Slack channel.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/action_mod/slack.py)]

- **features**:
>

- **config**:
>{'params': {'slack_bot_token': {'type': 'string', 'description': 'The Slack bot token generated when you created the bot account'}, 'channel_id': {'type': 'string', 'description': 'The channel ID you want to post messages to'}, 'message_template': {'type': 'large_string', 'description': 'The template to be used to generate the message to be posted', 'value': 'The **template** will be rendered using *Jinja2*!', 'jinja_supported': True}}, 'blocking': False, 'support_filters': True, 'expect_misp_core_format': False}

-----

#### [Test action](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/action_mod/testaction.py)

This module is merely a test, always returning true. Triggers on event publishing.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/action_mod/testaction.py)]

- **features**:
>

- **config**:
>{'params': {'foo': {'type': 'string', 'description': 'blablabla', 'value': 'xyz'}, 'Data extraction path': {'type': 'hash_path', 'description': 'Only post content extracted from this path', 'value': 'Attribute.{n}.AttributeTag.{n}.Tag.name'}}, 'blocking': False, 'support_filters': False, 'expect_misp_core_format': False}

-----
