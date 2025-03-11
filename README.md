# MISP modules

[![Build status](https://github.com/MISP/misp-modules/actions/workflows/test-package.yml/badge.svg)](https://github.com/MISP/misp-modules/actions/workflows/test-package.yml)[![Coverage Status](https://coveralls.io/repos/github/MISP/misp-modules/badge.svg?branch=main)](https://coveralls.io/github/MISP/misp-modules?branch=main)
[![codecov](https://codecov.io/gh/MISP/misp-modules/branch/main/graph/badge.svg)](https://codecov.io/gh/MISP/misp-modules)

MISP modules are autonomous modules that can be used to extend [MISP](https://github.com/MISP/MISP) for new services such as expansion, import, export and workflow action.

MISP modules can be also installed and used without MISP as a [standalone tool accessible via a convenient web interface](./website).

The modules are written in Python 3 following a simple API interface. The objective is to ease the extensions of MISP functionalities
without modifying core components. The API is available via a simple REST API which is independent from MISP installation or configuration and can be used with other tools.

For more information: [Extending MISP with Python modules](https://www.misp-project.org/misp-training/3.1-misp-modules.pdf) slides from [MISP training](https://github.com/MISP/misp-training).

# Installation
Installation instructions can be found in the [installation documentation](https://misp.github.io/misp-modules/install/).

# How to add your own MISP modules?
Developing a MISP module yourself is fairly easy. Start with a template or existing module and continue from there. \
More information can be found in the [contribute](https://misp.github.io/misp-modules/contribute/) section of the documentation.

# Documentation

In order to provide documentation about some modules that require specific input / output / configuration, the [documentation](https://misp.github.io/misp-modules/) contains detailed information about the general purpose, requirements, features, input and ouput of each of these modules:

- ***description** - quick description of the general purpose of the module, as the one given by the moduleinfo
- **requirements** - special libraries needed to make the module work
- **features** - description of the way to use the module, with the required MISP features to make the module give the intended result
- **references** - link(s) giving additional information about the format concerned in the module
- **input** - description of the format of data used in input
- **output** - description of the format given as the result of the module execution

## Licenses
For further Information see the [license file](https://misp.github.io/misp-modules/license/).

# List of MISP modules

## Expansion Modules
* [Abuse IPDB](https://misp.github.io/misp-modules/expansion/#abuse-ipdb) - AbuseIPDB MISP expansion module
* [OSINT DigitalSide](https://misp.github.io/misp-modules/expansion/#osint-digitalside) - On demand query API for OSINT.digitalside.it project.
* [APIVoid](https://misp.github.io/misp-modules/expansion/#apivoid) - Module to query APIVoid with some domain attributes.
* [AssemblyLine Query](https://misp.github.io/misp-modules/expansion/#assemblyline-query) - A module tu query the AssemblyLine API with a submission ID to get the submission report and parse it.
* [AssemblyLine Submit](https://misp.github.io/misp-modules/expansion/#assemblyline-submit) - A module to submit samples and URLs to AssemblyLine for advanced analysis, and return the link of the submission.
* [Backscatter.io](https://misp.github.io/misp-modules/expansion/#backscatter.io) - Backscatter.io module to bring mass-scanning observations into MISP.
* [BTC Scam Check](https://misp.github.io/misp-modules/expansion/#btc-scam-check) - An expansion hover module to query a special dns blacklist to check if a bitcoin address has been abused.
* [BTC Steroids](https://misp.github.io/misp-modules/expansion/#btc-steroids) - An expansion hover module to get a blockchain balance from a BTC address in MISP.
* [Censys Enrich](https://misp.github.io/misp-modules/expansion/#censys-enrich) - An expansion module to enrich attributes in MISP by quering the censys.io API
* [CIRCL Passive DNS](https://misp.github.io/misp-modules/expansion/#circl-passive-dns) - Module to access CIRCL Passive DNS.
* [CIRCL Passive SSL](https://misp.github.io/misp-modules/expansion/#circl-passive-ssl) - Modules to access CIRCL Passive SSL.
* [ClaamAV](https://misp.github.io/misp-modules/expansion/#claamav) - Submit file to ClamAV
* [Cluster25 Expand](https://misp.github.io/misp-modules/expansion/#cluster25-expand) - Module to query Cluster25 CTI.
* [Markdown to PDF converter](https://misp.github.io/misp-modules/expansion/#markdown-to-pdf-converter) - Render the markdown (under GFM) into PDF. Requires pandoc (https://pandoc.org/), wkhtmltopdf (https://wkhtmltopdf.org/) and mermaid dependencies.
* [Country Code](https://misp.github.io/misp-modules/expansion/#country-code) - Module to expand country codes.
* [CPE Lookup](https://misp.github.io/misp-modules/expansion/#cpe-lookup) - An expansion module to query the CVE search API with a cpe code to get its related vulnerabilities.
* [CrowdSec CTI](https://misp.github.io/misp-modules/expansion/#crowdsec-cti) - Module to access CrowdSec CTI API.
* [CrowdStrike Falcon](https://misp.github.io/misp-modules/expansion/#crowdstrike-falcon) - Module to query CrowdStrike Falcon.
* [Cuckoo Submit](https://misp.github.io/misp-modules/expansion/#cuckoo-submit) - Submit files and URLs to Cuckoo Sandbox
* [CVE Lookup](https://misp.github.io/misp-modules/expansion/#cve-lookup) - An expansion hover module to expand information about CVE id.
* [CVE Advanced Lookup](https://misp.github.io/misp-modules/expansion/#cve-advanced-lookup) - An expansion module to query the CIRCL CVE search API for more information about a vulnerability (CVE).
* [Cytomic Orion Lookup](https://misp.github.io/misp-modules/expansion/#cytomic-orion-lookup) - An expansion module to enrich attributes in MISP by quering the Cytomic Orion API
* [DBL Spamhaus Lookup](https://misp.github.io/misp-modules/expansion/#dbl-spamhaus-lookup) - Checks Spamhaus DBL for a domain name.
* [DNS Resolver](https://misp.github.io/misp-modules/expansion/#dns-resolver) - Simple DNS expansion service to resolve IP address from MISP attributes
* [DOCX Enrich](https://misp.github.io/misp-modules/expansion/#docx-enrich) - Module to extract freetext from a .docx document.
* [DomainTools Lookup](https://misp.github.io/misp-modules/expansion/#domaintools-lookup) - DomainTools MISP expansion module.
* [EQL Query Generator](https://misp.github.io/misp-modules/expansion/#eql-query-generator) - EQL query generation for a MISP attribute.
* [EUPI Lookup](https://misp.github.io/misp-modules/expansion/#eupi-lookup) - A module to query the Phishing Initiative service (https://phishing-initiative.lu).
* [URL Components Extractor](https://misp.github.io/misp-modules/expansion/#url-components-extractor) - Extract URL components
* [Farsight DNSDB Lookup](https://misp.github.io/misp-modules/expansion/#farsight-dnsdb-lookup) - Module to access Farsight DNSDB Passive DNS.
* [GeoIP ASN Lookup](https://misp.github.io/misp-modules/expansion/#geoip-asn-lookup) - Query a local copy of the Maxmind Geolite ASN database (MMDB format)
* [GeoIP City Lookup](https://misp.github.io/misp-modules/expansion/#geoip-city-lookup) - An expansion module to query a local copy of Maxmind's Geolite database with an IP address, in order to get information about the city where it is located.
* [GeoIP Country Lookup](https://misp.github.io/misp-modules/expansion/#geoip-country-lookup) - Query a local copy of Maxminds Geolite database, updated for MMDB format
* [Google Safe Browsing Lookup](https://misp.github.io/misp-modules/expansion/#google-safe-browsing-lookup) - Google safe browsing expansion module
* [Google Threat Intelligence Lookup](https://misp.github.io/misp-modules/expansion/#google-threat-intelligence-lookup) - An expansion module to have the observable's threat score assessed by Google Threat Intelligence.
* [GreyNoise Lookup](https://misp.github.io/misp-modules/expansion/#greynoise-lookup) - Module to query IP and CVE information from GreyNoise
* [Hashdd Lookup](https://misp.github.io/misp-modules/expansion/#hashdd-lookup) - A hover module to check hashes against hashdd.com including NSLR dataset.
* [CIRCL Hashlookup Lookup](https://misp.github.io/misp-modules/expansion/#circl-hashlookup-lookup) - An expansion module to query the CIRCL hashlookup services to find it if a hash is part of a known set such as NSRL.
* [Have I Been Pwned Lookup](https://misp.github.io/misp-modules/expansion/#have-i-been-pwned-lookup) - Module to access haveibeenpwned.com API.
* [HTML to Markdown](https://misp.github.io/misp-modules/expansion/#html-to-markdown) - Expansion module to fetch the html content from an url and convert it into markdown.
* [HYAS Insight Lookup](https://misp.github.io/misp-modules/expansion/#hyas-insight-lookup) - HYAS Insight integration to MISP provides direct, high volume access to HYAS Insight data. It enables investigators and analysts to understand and defend against cyber adversaries and their infrastructure.
* [Intel471 Lookup](https://misp.github.io/misp-modules/expansion/#intel471-lookup) - Module to access Intel 471
* [IP2Location.io Lookup](https://misp.github.io/misp-modules/expansion/#ip2location.io-lookup) - An expansion module to query IP2Location.io to gather more information on a given IP address.
* [IPASN-History Lookup](https://misp.github.io/misp-modules/expansion/#ipasn-history-lookup) - Module to query an IP ASN history service (https://github.com/D4-project/IPASN-History).
* [IPInfo.io Lookup](https://misp.github.io/misp-modules/expansion/#ipinfo.io-lookup) - An expansion module to query ipinfo.io to gather more information on a given IP address.
* [IPQualityScore Lookup](https://misp.github.io/misp-modules/expansion/#ipqualityscore-lookup) - IPQualityScore MISP Expansion Module for IP reputation, Email Validation, Phone Number Validation, Malicious Domain and Malicious URL Scanner.
* [IPRep Lookup](https://misp.github.io/misp-modules/expansion/#iprep-lookup) - Module to query IPRep data for IP addresses.
* [Ninja Template Rendering](https://misp.github.io/misp-modules/expansion/#ninja-template-rendering) - Render the template with the data passed
* [Joe Sandbox Import](https://misp.github.io/misp-modules/expansion/#joe-sandbox-import) - Query Joe Sandbox API with a submission url to get the json report and extract its data that is parsed and converted into MISP attributes and objects.
* [Joe Sandbox Submit](https://misp.github.io/misp-modules/expansion/#joe-sandbox-submit) - A module to submit files or URLs to Joe Sandbox for an advanced analysis, and return the link of the submission.
* [Lastline Lookup](https://misp.github.io/misp-modules/expansion/#lastline-lookup) - Deprecation notice: this module will be deprecated by December 2021, please use vmware_nsx module.  Query Lastline with an analysis link and parse the report into MISP attributes and objects.
* [Lastline Submit](https://misp.github.io/misp-modules/expansion/#lastline-submit) - Deprecation notice: this module will be deprecated by December 2021, please use vmware_nsx module.  Module to submit a file or URL to Lastline.
* [Macaddress.io Lookup](https://misp.github.io/misp-modules/expansion/#macaddress.io-lookup) - MISP hover module for macaddress.io
* [Macvendors Lookup](https://misp.github.io/misp-modules/expansion/#macvendors-lookup) - Module to access Macvendors API.
* [MalShare Upload](https://misp.github.io/misp-modules/expansion/#malshare-upload) - Module to push malware samples to MalShare
* [Malware Bazaar Lookup](https://misp.github.io/misp-modules/expansion/#malware-bazaar-lookup) - Query Malware Bazaar to get additional information about the input hash.
* [McAfee MVISION Insights Lookup](https://misp.github.io/misp-modules/expansion/#mcafee-mvision-insights-lookup) - Lookup McAfee MVISION Insights Details
* [GeoIP Enrichment](https://misp.github.io/misp-modules/expansion/#geoip-enrichment) - A hover and expansion module to enrich an ip with geolocation and ASN information from an mmdb server instance, such as CIRCL's ip.circl.lu.
* [MWDB Submit](https://misp.github.io/misp-modules/expansion/#mwdb-submit) - Module to push malware samples to a MWDB instance
* [OCR Enrich](https://misp.github.io/misp-modules/expansion/#ocr-enrich) - Module to process some optical character recognition on pictures.
* [ODS Enrich](https://misp.github.io/misp-modules/expansion/#ods-enrich) - Module to extract freetext from a .ods document.
* [ODT Enrich](https://misp.github.io/misp-modules/expansion/#odt-enrich) - Module to extract freetext from a .odt document.
* [Onion Lookup](https://misp.github.io/misp-modules/expansion/#onion-lookup) - MISP module using the MISP standard. Uses the onion-lookup service to get information about an onion.
* [Onyphe Lookup](https://misp.github.io/misp-modules/expansion/#onyphe-lookup) - Module to process a query on Onyphe.
* [Onyphe Full Lookup](https://misp.github.io/misp-modules/expansion/#onyphe-full-lookup) - Module to process a full query on Onyphe.
* [AlienVault OTX Lookup](https://misp.github.io/misp-modules/expansion/#alienvault-otx-lookup) - Module to get information from AlienVault OTX.
* [Passive SSH Enrichment](https://misp.github.io/misp-modules/expansion/#passive-ssh-enrichment) - An expansion module to enrich, SSH key fingerprints and IP addresses with information collected by passive-ssh
* [PassiveTotal Lookup](https://misp.github.io/misp-modules/expansion/#passivetotal-lookup) - The PassiveTotal MISP expansion module brings the datasets derived from Internet scanning directly into your MISP instance. This module supports passive DNS, historic SSL, WHOIS, and host attributes. In order to use the module, you must have a valid PassiveTotal account username and API key. Registration is free and can be done by visiting https://www.passivetotal.org/register
* [PDF Enrich](https://misp.github.io/misp-modules/expansion/#pdf-enrich) - Module to extract freetext from a PDF document.
* [PPTX Enrich](https://misp.github.io/misp-modules/expansion/#pptx-enrich) - Module to extract freetext from a .pptx document.
* [Qintel QSentry Lookup](https://misp.github.io/misp-modules/expansion/#qintel-qsentry-lookup) - A hover and expansion module which queries Qintel QSentry for ip reputation data
* [QR Code Decode](https://misp.github.io/misp-modules/expansion/#qr-code-decode) - Module to decode QR codes.
* [RandomcoinDB Lookup](https://misp.github.io/misp-modules/expansion/#randomcoindb-lookup) - Module to access the ransomcoinDB (see https://ransomcoindb.concinnity-risks.com)
* [Real-time Blackhost Lists Lookup](https://misp.github.io/misp-modules/expansion/#real-time-blackhost-lists-lookup) - Module to check an IPv4 address against known RBLs.
* [Recorded Future Enrich](https://misp.github.io/misp-modules/expansion/#recorded-future-enrich) - Module to enrich attributes with threat intelligence from Recorded Future.
* [Reverse DNS](https://misp.github.io/misp-modules/expansion/#reverse-dns) - Simple Reverse DNS expansion service to resolve reverse DNS from MISP attributes.
* [SecurityTrails Lookup](https://misp.github.io/misp-modules/expansion/#securitytrails-lookup) - An expansion modules for SecurityTrails.
* [Shodan Lookup](https://misp.github.io/misp-modules/expansion/#shodan-lookup) - Module to query on Shodan.
* [Sigma Rule Converter](https://misp.github.io/misp-modules/expansion/#sigma-rule-converter) - An expansion hover module to display the result of sigma queries.
* [Sigma Syntax Validator](https://misp.github.io/misp-modules/expansion/#sigma-syntax-validator) - An expansion hover module to perform a syntax check on sigma rules.
* [SigMF Expansion](https://misp.github.io/misp-modules/expansion/#sigmf-expansion) - Expands a SigMF Recording object into a SigMF Expanded Recording object, extracts a SigMF archive into a SigMF Recording object.
* [Socialscan Lookup](https://misp.github.io/misp-modules/expansion/#socialscan-lookup) - A hover module to get information on the availability of an email address or username on some online platforms.
* [SophosLabs Intelix Lookup](https://misp.github.io/misp-modules/expansion/#sophoslabs-intelix-lookup) - An expansion module to query the Sophoslabs intelix API to get additional information about an ip address, url, domain or sha256 attribute.
* [URL Archiver](https://misp.github.io/misp-modules/expansion/#url-archiver) - Module to cache web pages of analysis reports, OSINT sources. The module returns a link of the cached page.
* [Stairwell Lookup](https://misp.github.io/misp-modules/expansion/#stairwell-lookup) - Module to query the Stairwell API to get additional information about the input hash attribute
* [STIX2 Pattern Syntax Validator](https://misp.github.io/misp-modules/expansion/#stix2-pattern-syntax-validator) - An expansion hover module to perform a syntax check on stix2 patterns.
* [ThreatCrowd Lookup](https://misp.github.io/misp-modules/expansion/#threatcrowd-lookup) - Module to get information from ThreatCrowd.
* [ThreadFox Lookup](https://misp.github.io/misp-modules/expansion/#threadfox-lookup) - Module to search for an IOC on ThreatFox by abuse.ch.
* [ThreatMiner Lookup](https://misp.github.io/misp-modules/expansion/#threatminer-lookup) - Module to get information from ThreatMiner.
* [Triage Submit](https://misp.github.io/misp-modules/expansion/#triage-submit) - Module to submit samples to tria.ge
* [TruSTAR Enrich](https://misp.github.io/misp-modules/expansion/#trustar-enrich) - Module to get enrich indicators with TruSTAR.
* [URLhaus Lookup](https://misp.github.io/misp-modules/expansion/#urlhaus-lookup) - Query of the URLhaus API to get additional information about the input attribute.
* [URLScan Lookup](https://misp.github.io/misp-modules/expansion/#urlscan-lookup) - An expansion module to query urlscan.io.
* [VARIoT db Lookup](https://misp.github.io/misp-modules/expansion/#variot-db-lookup) - An expansion module to query the VARIoT db API for more information about a vulnerability.
* [VirusTotal v3 Lookup](https://misp.github.io/misp-modules/expansion/#virustotal-v3-lookup) - Enrich observables with the VirusTotal v3 API
* [VirusTotal Public API Lookup](https://misp.github.io/misp-modules/expansion/#virustotal-public-api-lookup) - Enrich observables with the VirusTotal v3 public API
* [VirusTotal Upload](https://misp.github.io/misp-modules/expansion/#virustotal-upload) - Module to push malware samples to VirusTotal
* [VMRay Submit](https://misp.github.io/misp-modules/expansion/#vmray-submit) - Module to submit a sample to VMRay.
* [VMware NSX Defender Enrich](https://misp.github.io/misp-modules/expansion/#vmware-nsx-defender-enrich) - Module to enrich a file or URL with VMware NSX Defender.
* [VulnDB Lookup](https://misp.github.io/misp-modules/expansion/#vulndb-lookup) - Module to query VulnDB (RiskBasedSecurity.com).
* [Vulnerability Lookup](https://misp.github.io/misp-modules/expansion/#vulnerability-lookup) - An expansion module to query Vulnerability Lookup
* [Vulners Lookup](https://misp.github.io/misp-modules/expansion/#vulners-lookup) - An expansion hover module to expand information about CVE id using Vulners API.
* [Vysion Enrich](https://misp.github.io/misp-modules/expansion/#vysion-enrich) - Module to enrich the information by making use of the Vysion API.
* [Whois Lookup](https://misp.github.io/misp-modules/expansion/#whois-lookup) - Module to query a local instance of uwhois (https://github.com/rafiot/uwhoisd).
* [WhoisFreaks Lookup](https://misp.github.io/misp-modules/expansion/#whoisfreaks-lookup) - An expansion module for https://whoisfreaks.com/ that will provide an enriched analysis of the provided domain, including WHOIS and DNS information.
* [Wikidata Lookup](https://misp.github.io/misp-modules/expansion/#wikidata-lookup) - An expansion hover module to extract information from Wikidata to have additional information about particular term for analysis.
* [IBM X-Force Exchange Lookup](https://misp.github.io/misp-modules/expansion/#ibm-x-force-exchange-lookup) - An expansion module for IBM X-Force Exchange.
* [XLXS Enrich](https://misp.github.io/misp-modules/expansion/#xlxs-enrich) - Module to extract freetext from a .xlsx document.
* [YARA Rule Generator](https://misp.github.io/misp-modules/expansion/#yara-rule-generator) - The module takes a hash attribute (md5, sha1, sha256, imphash) as input, and is returning a YARA rule from it.
* [YARA Syntax Validator](https://misp.github.io/misp-modules/expansion/#yara-syntax-validator) - An expansion hover module to perform a syntax check on if yara rules are valid or not.
* [Yeti Lookup](https://misp.github.io/misp-modules/expansion/#yeti-lookup) - Module to process a query on Yeti.

## Export Modules
* [CEF Export](https://misp.github.io/misp-modules/export_mod/#cef-export) - Module to export a MISP event in CEF format.
* [Cisco fireSIGHT blockrule Export](https://misp.github.io/misp-modules/export_mod/#cisco-firesight-blockrule-export) - Module to export malicious network activity attributes to Cisco fireSIGHT manager block rules.
* [Microsoft Defender for Endpoint KQL Export](https://misp.github.io/misp-modules/export_mod/#microsoft-defender-for-endpoint-kql-export) - Defender for Endpoint KQL hunting query export module
* [GoAML Export](https://misp.github.io/misp-modules/export_mod/#goaml-export) - This module is used to export MISP events containing transaction objects into GoAML format.
* [Lite Export](https://misp.github.io/misp-modules/export_mod/#lite-export) - Lite export of a MISP event.
* [EQL Query Export](https://misp.github.io/misp-modules/export_mod/#eql-query-export) - Export MISP event in Event Query Language
* [Nexthink NXQL Export](https://misp.github.io/misp-modules/export_mod/#nexthink-nxql-export) - Nexthink NXQL query export module
* [OSQuery Export](https://misp.github.io/misp-modules/export_mod/#osquery-export) - OSQuery export of a MISP event.
* [Event to PDF Export](https://misp.github.io/misp-modules/export_mod/#event-to-pdf-export) - Simple export of a MISP event to PDF.
* [Test Export](https://misp.github.io/misp-modules/export_mod/#test-export) - Skeleton export module.
* [ThreatStream Export](https://misp.github.io/misp-modules/export_mod/#threatstream-export) - Module to export a structured CSV file for uploading to threatStream.
* [ThreadConnect Export](https://misp.github.io/misp-modules/export_mod/#threadconnect-export) - Module to export a structured CSV file for uploading to ThreatConnect.
* [VirusTotal Collections Export](https://misp.github.io/misp-modules/export_mod/#virustotal-collections-export) - Creates a VT Collection from an event iocs.
* [VirusTotal Graph Export](https://misp.github.io/misp-modules/export_mod/#virustotal-graph-export) - This module is used to create a VirusTotal Graph from a MISP event.
* [YARA Rule Export](https://misp.github.io/misp-modules/export_mod/#yara-rule-export) - This module is used to export MISP events to YARA.

## Import Modules
* [PDNS COF Importer](https://misp.github.io/misp-modules/import_mod/#pdns-cof-importer) - Passive DNS Common Output Format (COF) MISP importer
* [CSV Import](https://misp.github.io/misp-modules/import_mod/#csv-import) - Module to import MISP attributes from a csv file.
* [Cuckoo Sandbox Import](https://misp.github.io/misp-modules/import_mod/#cuckoo-sandbox-import) - Module to import Cuckoo JSON.
* [Email Import](https://misp.github.io/misp-modules/import_mod/#email-import) - Email import module for MISP
* [GoAML Import](https://misp.github.io/misp-modules/import_mod/#goaml-import) - Module to import MISP objects about financial transactions from GoAML files.
* [Import Blueprint](https://misp.github.io/misp-modules/import_mod/#import-blueprint) - Generic blueprint to be copy-pasted to quickly boostrap creation of import module.
* [Joe Sandbox Import](https://misp.github.io/misp-modules/import_mod/#joe-sandbox-import) - A module to import data from a Joe Sandbox analysis json report.
* [Lastline Import](https://misp.github.io/misp-modules/import_mod/#lastline-import) - Deprecation notice: this module will be deprecated by December 2021, please use vmware_nsx module.  Module to import and parse reports from Lastline analysis links.
* [MISP JSON Import](https://misp.github.io/misp-modules/import_mod/#misp-json-import) - Module to import MISP JSON format for merging MISP events.
* [OCR Import](https://misp.github.io/misp-modules/import_mod/#ocr-import) - Optical Character Recognition (OCR) module for MISP.
* [OpenIOC Import](https://misp.github.io/misp-modules/import_mod/#openioc-import) - Module to import OpenIOC packages.
* [TAXII 2.1 Import](https://misp.github.io/misp-modules/import_mod/#taxii-2.1-import) - Import content from a TAXII 2.1 server
* [CSV Test Import](https://misp.github.io/misp-modules/import_mod/#csv-test-import) - Simple CSV import tool with mapable columns
* [ThreadAnalyzer Sandbox Import](https://misp.github.io/misp-modules/import_mod/#threadanalyzer-sandbox-import) - Module to import ThreatAnalyzer archive.zip / analysis.json files.
* [URL Import](https://misp.github.io/misp-modules/import_mod/#url-import) - Simple URL import tool with Faup
* [VMRay API Import](https://misp.github.io/misp-modules/import_mod/#vmray-api-import) - Module to import VMRay (VTI) results.
* [VMRay Summary JSON Import](https://misp.github.io/misp-modules/import_mod/#vmray-summary-json-import) - Import a VMRay Summary JSON report.

## Action Modules
* [Mattermost](https://misp.github.io/misp-modules/action_mod/#mattermost) - Simplistic module to send message to a Mattermost channel.
* [Slack](https://misp.github.io/misp-modules/action_mod/#slack) - Simplistic module to send messages to a Slack channel.
* [Test action](https://misp.github.io/misp-modules/action_mod/#test-action) - This module is merely a test, always returning true. Triggers on event publishing.


