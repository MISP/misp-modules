# MISP modules

[![Build status](https://github.com/MISP/misp-modules/actions/workflows/python-package.yml/badge.svg)](https://github.com/MISP/misp-modules/actions/workflows/python-package.yml)[![Coverage Status](https://coveralls.io/repos/github/MISP/misp-modules/badge.svg?branch=main)](https://coveralls.io/github/MISP/misp-modules?branch=main)
[![codecov](https://codecov.io/gh/MISP/misp-modules/branch/main/graph/badge.svg)](https://codecov.io/gh/MISP/misp-modules)

MISP modules are autonomous modules that can be used to extend [MISP](https://github.com/MISP/MISP) for new services such as expansion, import, export and workflow action.

MISP modules can be also installed and used without MISP as a [standalone tool accessible via a convenient web interface](./website).

The modules are written in Python 3 following a simple API interface. The objective is to ease the extensions of MISP functionalities
without modifying core components. The API is available via a simple REST API which is independent from MISP installation or configuration and can be used with other tools.

For more information: [Extending MISP with Python modules](https://www.misp-project.org/misp-training/3.1-misp-modules.pdf) slides from [MISP training](https://github.com/MISP/misp-training).

# Existing MISP modules

## Expansion Modules
* [Abuse IPDB](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/abuseipdb.py) - AbuseIPDB MISP expansion module
* [OSINT DigitalSide](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/apiosintds.py) - On demand query API for OSINT.digitalside.it project.
* [APIVoid](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/apivoid.py) - Module to query APIVoid with some domain attributes.
* [AssemblyLine Query](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/assemblyline_query.py) - A module tu query the AssemblyLine API with a submission ID to get the submission report and parse it.
* [AssemblyLine Submit](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/assemblyline_submit.py) - A module to submit samples and URLs to AssemblyLine for advanced analysis, and return the link of the submission.
* [Backscatter.io](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/backscatter_io.py) - Backscatter.io module to bring mass-scanning observations into MISP.
* [BGP Ranking](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/bgpranking.py) - Query BGP Ranking to get the ranking of an Autonomous System number.
* [BTC Scam Check](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/btc_scam_check.py) - An expansion hover module to query a special dns blacklist to check if a bitcoin address has been abused.
* [BTC Steroids](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/btc_steroids.py) - An expansion hover module to get a blockchain balance from a BTC address in MISP.
* [Censys Enrich](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/censys_enrich.py) - An expansion module to enrich attributes in MISP by quering the censys.io API
* [CIRCL Passive DNS](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/circl_passivedns.py) - Module to access CIRCL Passive DNS.
* [CIRCL Passive SSL](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/circl_passivessl.py) - Modules to access CIRCL Passive SSL.
* [ClaamAV](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/clamav.py) - Submit file to ClamAV
* [Cluster25 Expand](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/cluster25_expand.py) - Module to query Cluster25 CTI.
* [Country Code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/countrycode.py) - Module to expand country codes.
* [CPE Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/cpe.py) - An expansion module to query the CVE search API with a cpe code to get its related vulnerabilities.
* [CrowdSec CTI](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/crowdsec.py) - Hover module to lookup an IP in CrowdSec's CTI
* [CrowdStrike Falcon](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/crowdstrike_falcon.py) - Module to query CrowdStrike Falcon.
* [Cuckoo Submit](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/cuckoo_submit.py) - Submit files and URLs to Cuckoo Sandbox
* [CVE Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/cve.py) - An expansion hover module to expand information about CVE id.
* [CVE Advanced Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/cve_advanced.py) - An expansion module to query the CIRCL CVE search API for more information about a vulnerability (CVE).
* [Cytomic Orion Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/cytomic_orion.py) - An expansion module to enrich attributes in MISP by quering the Cytomic Orion API
* [DBL Spamhaus Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/dbl_spamhaus.py) - Checks Spamhaus DBL for a domain name.
* [DNS Resolver](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/dns.py) - jj
* [DOCX Enrich](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/docx_enrich.py) - Module to extract freetext from a .docx document.
* [DomainTools Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/domaintools.py) - DomainTools MISP expansion module.
* [EQL Query Generator](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/eql.py) - EQL query generation for a MISP attribute.
* [EUPI Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/eupi.py) - A module to query the Phishing Initiative service (https://phishing-initiative.lu).
* [URL Components Extractor](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/extract_url_components.py) - Extract URL components
* [Farsight DNSDB Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/farsight_passivedns.py) - Module to access Farsight DNSDB Passive DNS.
* [GeoIP ASN Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/geoip_asn.py) - Query a local copy of the Maxmind Geolite ASN database (MMDB format)
* [GeoIP City Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/geoip_city.py) - An expansion module to query a local copy of Maxmind's Geolite database with an IP address, in order to get information about the city where it is located.
* [GeoIP Country Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/geoip_country.py) - Query a local copy of Maxminds Geolite database, updated for MMDB format
* [Google Safe Browsing Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/google_safe_browsing.py) - Google safe browsing expansion module
* [Google Search](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/google_search.py) - An expansion hover module to expand google search information about an URL
* [Google Threat Intelligence Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/google_threat_intelligence.py) - An expansion module to have the observable's threat score assessed by Google Threat Intelligence.
* [GreyNoise Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/greynoise.py) - Module to query IP and CVE information from GreyNoise
* [Hashdd Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/hashdd.py) - A hover module to check hashes against hashdd.com including NSLR dataset.
* [CIRCL Hashlookup Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/hashlookup.py) - An expansion module to query the CIRCL hashlookup services to find it if a hash is part of a known set such as NSRL.
* [Have I Been Pwned Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/hibp.py) - Module to access haveibeenpwned.com API.
* [HTML to Markdown](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/html_to_markdown.py) - Expansion module to fetch the html content from an url and convert it into markdown.
* [HYAS Insight Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/hyasinsight.py) - HYAS Insight integration to MISP provides direct, high volume access to HYAS Insight data. It enables investigators and analysts to understand and defend against cyber adversaries and their infrastructure.
* [Intel471 Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/intel471.py) - Module to access Intel 471
* [IP2Location.io Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/ip2locationio.py) - An expansion module to query IP2Location.io to gather more information on a given IP address.
* [IPASN-History Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/ipasn.py) - Module to query an IP ASN history service (https://github.com/D4-project/IPASN-History).
* [IPInfo.io Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/ipinfo.py) - An expansion module to query ipinfo.io to gather more information on a given IP address.
* [IPQualityScore Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/ipqs_fraud_and_risk_scoring.py) - IPQualityScore MISP Expansion Module for IP reputation, Email Validation, Phone Number Validation, Malicious Domain and Malicious URL Scanner.
* [IPRep Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/iprep.py) - Module to query IPRep data for IP addresses.
* [Ninja Template Rendering](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/jinja_template_rendering.py) - Render the template with the data passed
* [Joe Sandbox Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/joesandbox_query.py) - Query Joe Sandbox API with a submission url to get the json report and extract its data that is parsed and converted into MISP attributes and objects.
* [Joe Sandbox Submit](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/joesandbox_submit.py) - A module to submit files or URLs to Joe Sandbox for an advanced analysis, and return the link of the submission.
* [Lastline Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/lastline_query.py) - Deprecation notice: this module will be deprecated by December 2021, please use vmware_nsx module.

Query Lastline with an analysis link and parse the report into MISP attributes and objects.
* [Lastline Submit](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/lastline_submit.py) - Deprecation notice: this module will be deprecated by December 2021, please use vmware_nsx module.

Module to submit a file or URL to Lastline.
* [Macaddress.io Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/macaddress_io.py) - MISP hover module for macaddress.io
* [Macvendors Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/macvendors.py) - Module to access Macvendors API.
* [Malware Bazaar Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/malwarebazaar.py) - Query Malware Bazaar to get additional information about the input hash.
* [McAfee MVISION Insights Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/mcafee_insights_enrich.py) - Lookup McAfee MVISION Insights Details
* [GeoIP Enrichment](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/mmdb_lookup.py) - A hover and expansion module to enrich an ip with geolocation and ASN information from an mmdb server instance, such as CIRCL's ip.circl.lu.
* [MWDB Submit](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/mwdb.py) - Module to push malware samples to a MWDB instance
* [OCR Enrich](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/ocr_enrich.py) - Module to process some optical character recognition on pictures.
* [ODS Enrich](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/ods_enrich.py) - Module to extract freetext from a .ods document.
* [ODT Enrich](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/odt_enrich.py) - Module to extract freetext from a .odt document.
* [Onyphe Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/onyphe.py) - Module to process a query on Onyphe.
* [Onyphe Full Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/onyphe_full.py) - Module to process a full query on Onyphe.
* [AlienVault OTX Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/otx.py) - Module to get information from AlienVault OTX.
* [Passive SSH Enrichment](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/passive_ssh.py) - An expansion module to enrich, SSH key fingerprints and IP addresses with information collected by passive-ssh
* [PassiveTotal Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/passivetotal.py) - The PassiveTotal MISP expansion module brings the datasets derived from Internet scanning directly into your MISP instance. This module supports passive DNS, historic SSL, WHOIS, and host attributes. In order to use the module, you must have a valid PassiveTotal account username and API key. Registration is free and can be done by visiting https://www.passivetotal.org/register
* [PDF Enrich](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/pdf_enrich.py) - Module to extract freetext from a PDF document.
* [PPTX Enrich](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/pptx_enrich.py) - Module to extract freetext from a .pptx document.
* [Qintel QSentry Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/qintel_qsentry.py) - A hover and expansion module which queries Qintel QSentry for ip reputation data
* [QR Code Decode](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/qrcode.py) - Module to decode QR codes.
* [RandomcoinDB Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/ransomcoindb.py) - Module to access the ransomcoinDB (see https://ransomcoindb.concinnity-risks.com)
* [Real-time Blackhost Lists Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/rbl.py) - Module to check an IPv4 address against known RBLs.
* [Recorded Future Enrich](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/recordedfuture.py) - Module to enrich attributes with threat intelligence from Recorded Future.
* [Reverse DNS](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/reversedns.py) - Simple Reverse DNS expansion service to resolve reverse DNS from MISP attributes.
* [SecurityTrails Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/securitytrails.py) - An expansion modules for SecurityTrails.
* [Shodan Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/shodan.py) - Module to query on Shodan.
* [Sigma Rule Converter](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/sigma_queries.py) - An expansion hover module to display the result of sigma queries.
* [Sigma Syntax Validator](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/sigma_syntax_validator.py) - An expansion hover module to perform a syntax check on sigma rules.
* [SigMF Expansion](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/sigmf_expand.py) - Expands a SigMF Recording object into a SigMF Expanded Recording object, extracts a SigMF archive into a SigMF Recording object.
* [Socialscan Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/socialscan.py) - A hover module to get information on the availability of an email address or username on some online platforms.
* [SophosLabs Intelix Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/sophoslabs_intelix.py) - An expansion module to query the Sophoslabs intelix API to get additional information about an ip address, url, domain or sha256 attribute.
* [URL Archiver](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/sourcecache.py) - Module to cache web pages of analysis reports, OSINT sources. The module returns a link of the cached page.
* [Stairwell Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/stairwell.py) - Module to query the Stairwell API to get additional information about the input hash attribute
* [STIX2 Pattern Syntax Validator](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/stix2_pattern_syntax_validator.py) - An expansion hover module to perform a syntax check on stix2 patterns.
* [ThreatCrowd Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/threatcrowd.py) - Module to get information from ThreatCrowd.
* [ThreadFox Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/threatfox.py) - Module to search for an IOC on ThreatFox by abuse.ch.
* [ThreatMiner Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/threatminer.py) - Module to get information from ThreatMiner.
* [TruSTAR Enrich](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/trustar_enrich.py) - Module to get enrich indicators with TruSTAR.
* [URLhaus Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/urlhaus.py) - Query of the URLhaus API to get additional information about the input attribute.
* [URLScan Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/urlscan.py) - An expansion module to query urlscan.io.
* [VARIoT db Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/variotdbs.py) - An expansion module to query the VARIoT db API for more information about a vulnerability.
* [VirusTotal v3 Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/virustotal.py) - Enrich observables with the VirusTotal v3 API
* [VirusTotal Public API Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/virustotal_public.py) - Enrich observables with the VirusTotal v3 public API
* [VMRay Submit](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/vmray_submit.py) - Module to submit a sample to VMRay.
* [VMware NSX Defender Enrich](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/vmware_nsx.py) - Module to enrich a file or URL with VMware NSX Defender.
* [VulnDB Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/vulndb.py) - Module to query VulnDB (RiskBasedSecurity.com).
* [Vulnerability Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/vulnerability_lookup.py) - An expansion module to query Vulnerability Lookup
* [Vulners Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/vulners.py) - An expansion hover module to expand information about CVE id using Vulners API.
* [Vysion Enrich](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/vysion.py) - Module to enrich the information by making use of the Vysion API.
* [Whois Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/whois.py) - Module to query a local instance of uwhois (https://github.com/rafiot/uwhoisd).
* [WhoisFreaks Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/whoisfreaks.py) - An expansion module for https://whoisfreaks.com/ that will provide an enriched analysis of the provided domain, including WHOIS and DNS information.
* [Wikidata Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/wiki.py) - An expansion hover module to extract information from Wikidata to have additional information about particular term for analysis.
* [IBM X-Force Exchange Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/xforceexchange.py) - An expansion module for IBM X-Force Exchange.
* [XLXS Enrich](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/xlsx_enrich.py) - Module to extract freetext from a .xlsx document.
* [YARA Rule Generator](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/yara_query.py) - jj
* [YARA Syntax Validator](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/yara_syntax_validator.py) - An expansion hover module to perform a syntax check on if yara rules are valid or not.
* [Yeti Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/yeti.py) - Module to process a query on Yeti.

## Export Modules
* [CEF Export](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/export_mod/cef_export.py) - Module to export a MISP event in CEF format.
* [Cisco fireSIGHT blockrule Export](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/export_mod/cisco_firesight_manager_ACL_rule_export.py) - Module to export malicious network activity attributes to Cisco fireSIGHT manager block rules.
* [Microsoft Defender for Endpoint KQL Export](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/export_mod/defender_endpoint_export.py) - Defender for Endpoint KQL hunting query export module
* [GoAML Export](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/export_mod/goamlexport.py) - This module is used to export MISP events containing transaction objects into GoAML format.
* [Lite Export](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/export_mod/liteexport.py) - Lite export of a MISP event.
* [EQL Query Export](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/export_mod/mass_eql_export.py) - Export MISP event in Event Query Language
* [Nexthink NXQL Export](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/export_mod/nexthinkexport.py) - Nexthink NXQL query export module
* [OSQuery Export](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/export_mod/osqueryexport.py) - OSQuery export of a MISP event.
* [Event to PDF Export](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/export_mod/pdfexport.py) - Simple export of a MISP event to PDF.
* [ThreatStream Export](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/export_mod/threatStream_misp_export.py) - Module to export a structured CSV file for uploading to threatStream.
* [ThreadConnect Export](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/export_mod/threat_connect_export.py) - Module to export a structured CSV file for uploading to ThreatConnect.
* [VirusTotal Collections Export](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/export_mod/virustotal_collections.py) - Creates a VT Collection from an event iocs.
* [VirusTotal Graph Export](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/export_mod/vt_graph.py) - This module is used to create a VirusTotal Graph from a MISP event.
* [YARA Rule Export](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/export_mod/yara_export.py) - This module is used to export MISP events to YARA.

## Import Modules
* [PDNS COF Importer](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/cof2misp.py) - Passive DNS Common Output Format (COF) MISP importer
* [CSV Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/csvimport.py) - Module to import MISP attributes from a csv file.
* [Cuckoo Sandbox Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/cuckooimport.py) - Module to import Cuckoo JSON.
* [Email Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/email_import.py) - Email import module for MISP
* [GoAML Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/goamlimport.py) - Module to import MISP objects about financial transactions from GoAML files.
* [Import Blueprint](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/import_blueprint.py) - Generic blueprint to be copy-pasted to quickly boostrap creation of import module.
* [Joe Sandbox Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/joe_import.py) - A module to import data from a Joe Sandbox analysis json report.
* [Lastline Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/lastline_import.py) - Deprecation notice: this module will be deprecated by December 2021, please use vmware_nsx module.

Module to import and parse reports from Lastline analysis links.
* [MISP JSON Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/mispjson.py) - Module to import MISP JSON format for merging MISP events.
* [OCR Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/ocr.py) - Optical Character Recognition (OCR) module for MISP.
* [OpenIOC Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/openiocimport.py) - Module to import OpenIOC packages.
* [TAXII 2.1 Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/taxii21.py) - Import content from a TAXII 2.1 server
* [ThreadAnalyzer Sandbox Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/threatanalyzer_import.py) - Module to import ThreatAnalyzer archive.zip / analysis.json files.
* [URL Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/url_import.py) - Simple URL import tool with Faup
* [VMRay API Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/vmray_import.py) - Module to import VMRay (VTI) results.
* [VMRay Summary JSON Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/vmray_summary_json_import.py) - Import a VMRay Summary JSON report.

## Action Modules
* [Mattermost](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/action_mod/mattermost.py) - Simplistic module to send message to a Mattermost channel.
* [Slack](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/action_mod/slack.py) - Simplistic module to send messages to a Slack channel.
* [Test action](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/action_mod/testaction.py) - This module is merely a test, always returning true. Triggers on event publishing.


# Installation

## How to install and start MISP modules (in a Python virtualenv)? (recommended)

***Be sure to run the latest version of `pip`***. To install the latest version of pip, `pip install --upgrade pip` will do the job.

~~~~bash
SUDO_WWW="sudo -u www-data"

sudo apt-get install -y \
  python3-dev \
  python3-pip \
  git \
  libpq5 \
  libjpeg-dev \
  tesseract-ocr \
  libpoppler-cpp-dev \
  imagemagick virtualenv \
  libopencv-dev \
  zbar-tools \
  libzbar0 \
  libzbar-dev \
  libfuzzy-dev \
  libcaca-dev \
  build-essential

# BEGIN with virtualenv:
$SUDO_WWW virtualenv -p python3 /var/www/MISP/venv
# END with virtualenv

cd /usr/local/src/
# Ideally you add your user to the staff group and make /usr/local/src group writeable, below follows an example with user misp
sudo adduser misp staff
sudo chmod 2775 /usr/local/src
sudo chown root:staff /usr/local/src
git clone https://github.com/MISP/misp-modules.git
git clone git://github.com/stricaud/faup.git faup
git clone git://github.com/stricaud/gtcaca.git gtcaca

# Install gtcaca/faup
cd gtcaca
mkdir -p build
cd build
cmake .. && make
sudo make install
cd ../../faup
mkdir -p build
cd build
cmake .. && make
sudo make install
sudo ldconfig

cd ../../misp-modules

# BEGIN with virtualenv:
$SUDO_WWW  /var/www/MISP/venv/bin/pip install -I -r REQUIREMENTS
$SUDO_WWW  /var/www/MISP/venv/bin/pip install .
# END with virtualenv

# BEGIN without virtualenv:
sudo pip install -I -r REQUIREMENTS
sudo pip install .
# END without virtualenv

# Start misp-modules as a service
sudo cp etc/systemd/system/misp-modules.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now misp-modules
sudo service misp-modules start  # or
/var/www/MISP/venv/bin/misp-modules -l 127.0.0.1 -s & # to start the modules manually
~~~~

## How to install and start MISP modules on RHEL-based distributions ?

As of this writing, the official RHEL repositories only contain Ruby 2.0.0 and Ruby 2.1 or higher is required. As such, this guide installs Ruby 2.2 from the [SCL](https://access.redhat.com/documentation/en-us/red_hat_software_collections/3/html/3.2_release_notes/chap-installation#sect-Installation-Subscribe) repository.

~~~~bash
SUDO_WWW="sudo -u apache"
sudo yum install \
  rh-python36 \
  rh-ruby22 \
  openjpeg-devel \
  rubygem-rouge \
  rubygem-asciidoctor \
  zbar-devel \
  opencv-devel \
  gcc-c++ \
  pkgconfig \
  poppler-cpp-devel \
  python-devel \
  redhat-rpm-config
cd /var/www/MISP
$SUDO_WWW git clone https://github.com/MISP/misp-modules.git
cd misp-modules
$SUDO_WWW /usr/bin/scl enable rh-python36 "virtualenv -p python3 /var/www/MISP/venv"
$SUDO_WWW /var/www/MISP/venv/bin/pip install -U -I -r REQUIREMENTS
$SUDO_WWW /var/www/MISP/venv/bin/pip install -U .
~~~~

Create the service file /etc/systemd/system/misp-modules.service :

~~~~bash
echo "[Unit]
Description=MISP's modules
After=misp-workers.service

[Service]
Type=simple
User=apache
Group=apache
ExecStart=/usr/bin/scl enable rh-python36 rh-ruby22  '/var/www/MISP/venv/bin/misp-modules -l 127.0.0.1 -s'
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target" | sudo tee /etc/systemd/system/misp-modules.service
~~~~

The `After=misp-workers.service` must be changed or removed if you have not created a misp-workers service.
Then, enable the misp-modules service and start it:
~~~~bash
systemctl daemon-reload
systemctl enable --now misp-modules
~~~~

## How to use an MISP modules Docker container

### Docker build

~~~~bash
docker build -t misp-modules \
    --build-arg BUILD_DATE=$(date -u +"%Y-%m-%d") \
  docker/
~~~~

### Docker run

~~~~bash
# Start Redis
docker run --rm -d --name=misp-redis redis:alpine
# Start MISP-modules
docker run \
    --rm -d --name=misp-modules \
    -e REDIS_BACKEND=misp-redis \
    -e REDIS_PORT="6379" \
    -e REDIS_PW="" \
    -e REDIS_DATABASE="245" \
    -e MISP_MODULES_DEBUG="false" \
    dcso/misp-dockerized-misp-modules
~~~~

### Docker-compose

~~~~yml
services:
  misp-modules:
    # https://hub.docker.com/r/dcso/misp-dockerized-misp-modules
    image: dcso/misp-dockerized-misp-modules:3

    # Local image:
    #image: misp-modules
    #build:
    #  context: docker/

    environment:
      # Redis
      REDIS_BACKEND: misp-redis
      REDIS_PORT: "6379"
      REDIS_DATABASE: "245"
      # System PROXY (OPTIONAL)
      http_proxy:
      https_proxy:
      no_proxy: 0.0.0.0
      # Timezone (OPTIONAL)
      TZ: Europe/Berlin
      # MISP-Modules (OPTIONAL)
      MISP_MODULES_DEBUG: "false"
      # Logging options (OPTIONAL)
      LOG_SYSLOG_ENABLED: "no"
  misp-redis:
    # https://hub.docker.com/_/redis or alternative https://hub.docker.com/r/dcso/misp-dockerized-redis/
    image: redis:alpine
~~~~

## Install misp-module on an offline instance.
First, you need to grab all necessary packages for example like this :

Use pip wheel to create an archive
~~~
mkdir misp-modules-offline
pip3 wheel -r REQUIREMENTS shodan --wheel-dir=./misp-modules-offline
tar -cjvf misp-module-bundeled.tar.bz2 ./misp-modules-offline/*
~~~
On offline machine :
~~~
mkdir misp-modules-bundle
tar xvf misp-module-bundeled.tar.bz2 -C misp-modules-bundle
cd misp-modules-bundle
ls -1|while read line; do sudo pip3 install --force-reinstall --ignore-installed --upgrade --no-index --no-deps ${line};done
~~~
Next you can follow standard install procedure.

# How to add your own MISP modules?

Create your module in [misp_modules/modules/expansion/](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/), [misp_modules/modules/export_mod/](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/export_mod/), or [misp_modules/modules/import_mod/](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/). The module should have at minimum three functions:

* **introspection** function that returns a dict of the supported attributes (input and output) by your expansion module.
* **handler** function which accepts a JSON document to expand the values and return a dictionary of the expanded values.
* **version** function that returns a dict with the version and the associated meta-data including potential configurations required of the module.

Don't forget to return an error key and value if an error is raised to propagate it to the MISP user-interface.

Your module's script name should also be added in the `__all__` list of `<module type folder>/__init__.py` in order for it to be loaded.

~~~python
...
    # Checking for required value
    if not request.get('ip-src'):
        # Return an error message
        return {'error': "A source IP is required"}
...
~~~


### introspection

The function that returns a dict of the supported attributes (input and output) by your expansion module.

~~~python
mispattributes = {'input': ['link', 'url'],
                  'output': ['attachment', 'malware-sample']}

def introspection():
    return mispattributes
~~~

### version

The function that returns a dict with the version and the associated meta-data including potential configurations required of the module.


### Additional Configuration Values

If your module requires additional configuration (to be exposed via the MISP user-interface), you can define those in the moduleconfig value returned by the version function.

~~~python
# config fields that your code expects from the site admin
moduleconfig = ["apikey", "event_limit"]

def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
~~~


When you do this a config array is added to the meta-data output containing all the potential configuration values:

~~~
"meta": {
      "description": "PassiveTotal expansion service to expand values with multiple Passive DNS sources",
      "config": [
        "username",
        "password"
      ],
      "module-type": [
        "expansion",
        "hover"
      ],

...
~~~


If you want to use the configuration values set in the web interface they are stored in the key `config` in the JSON object passed to the handler.

~~~
def handler(q=False):

    # Check if we were given a configuration
    config = q.get("config", {})

    # Find out if there is a username field
    username = config.get("username", None)
~~~


### handler

The function which accepts a JSON document to expand the values and return a dictionary of the expanded values.

~~~python
def handler(q=False):
    "Fully functional rot-13 encoder"
    if q is False:
        return False
    request = json.loads(q)
    src = request.get('ip-src')
    if src is None:
        # Return an error message
        return {'error': "A source IP is required"}
    else:
        return {'results':
                codecs.encode(src, "rot-13")}
~~~

#### export module

For an export module, the `request["data"]` object corresponds to a list of events (dictionaries) to handle.

Iterating over events attributes is performed using their `Attribute` key.

~~~python
...
for event in request["data"]:
        for attribute in event["Attribute"]:
          # do stuff w/ attribute['type'], attribute['value'], ...
...

### Returning Binary Data

If you want to return a file or other data you need to add a data attribute.

~~~python
{"results": {"values": "filename.txt",
             "types": "attachment",
             "data"  : base64.b64encode(<ByteIO>)  # base64 encode your data first
             "comment": "This is an attachment"}}
~~~

If the binary file is malware you can use 'malware-sample' as the type. If you do this the malware sample will be automatically zipped and password protected ('infected') after being uploaded.


~~~python
{"results": {"values": "filename.txt",
             "types": "malware-sample",
             "data"  : base64.b64encode(<ByteIO>)  # base64 encode your data first
             "comment": "This is an attachment"}}
~~~

[To learn more about how data attributes are processed you can read the processing code here.](https://github.com/MISP/PyMISP/blob/4f230c9299ad9d2d1c851148c629b61a94f3f117/pymisp/mispevent.py#L185-L200)


### Module type

A MISP module can be of four types:

- **expansion** - service related to an attribute that can be used to extend and update an existing event.
- **hover** - service related to an attribute to provide additional information to the users without updating the event.
- **import** - service related to importing and parsing an external object that can be used to extend an existing event.
- **export** - service related to exporting an object, event, or data.

module-type is an array where the list of supported types can be added.

## Testing your modules?

MISP uses the **modules** function to discover the available MISP modules and their supported MISP attributes:

~~~
% curl -s http://127.0.0.1:6666/modules | jq .
[
  {
    "name": "passivetotal",
    "type": "expansion",
    "mispattributes": {
      "input": [
        "hostname",
        "domain",
        "ip-src",
        "ip-dst"
      ],
      "output": [
        "ip-src",
        "ip-dst",
        "hostname",
        "domain"
      ]
    },
    "meta": {
      "description": "PassiveTotal expansion service to expand values with multiple Passive DNS sources",
      "config": [
        "username",
        "password"
      ],
      "author": "Alexandre Dulaunoy",
      "version": "0.1"
    }
  },
  {
    "name": "sourcecache",
    "type": "expansion",
    "mispattributes": {
      "input": [
        "link"
      ],
      "output": [
        "link"
      ]
    },
    "meta": {
      "description": "Module to cache web pages of analysis reports, OSINT sources. The module returns a link of the cached page.",
      "author": "Alexandre Dulaunoy",
      "version": "0.1"
    }
  },
  {
    "name": "dns",
    "type": "expansion",
    "mispattributes": {
      "input": [
        "hostname",
        "domain"
      ],
      "output": [
        "ip-src",
        "ip-dst"
      ]
    },
    "meta": {
      "description": "Simple DNS expansion service to resolve IP address from MISP attributes",
      "author": "Alexandre Dulaunoy",
      "version": "0.1"
    }
  }
]

~~~

The MISP module service returns the available modules in a JSON array containing each module name along with their supported input attributes.

Based on this information, a query can be built in a JSON format and saved as body.json:

~~~json
{
  "hostname": "www.foo.be",
  "module": "dns"
}
~~~

Then you can POST this JSON format query towards the MISP object server:

~~~bash
curl -s http://127.0.0.1:6666/query -H "Content-Type: application/json" --data @body.json -X POST
~~~

The module should output the following JSON:

~~~json
{
  "results": [
    {
      "types": [
        "ip-src",
        "ip-dst"
      ],
      "values": [
        "188.65.217.78"
      ]
    }
  ]
}
~~~

It is also possible to restrict the category options of the resolved attributes by passing a list of categories along (optional):

~~~json
{
  "results": [
    {
      "types": [
        "ip-src",
        "ip-dst"
      ],
      "values": [
        "188.65.217.78"
      ],
      "categories": [
        "Network activity",
        "Payload delivery"
      ]
    }
  ]
}
~~~

For both the type and the category lists, the first item in the list will be the default setting on the interface.

### Enable your module in the web interface

For a module to be activated in the MISP web interface it must be enabled in the "Plugin Settings.

Go to "Administration > Server Settings" in the top menu
- Go to "Plugin Settings" in the top "tab menu bar"
- Click on the name of the type of module you have created to expand the list of plugins to show your module.
- Find the name of your plugin's "enabled" value in the Setting Column.
"Plugin.[MODULE NAME]_enabled"
- Double click on its "Value" column

~~~
Priority        Setting                         Value   Description                             Error Message
Recommended     Plugin.Import_ocr_enabled       false   Enable or disable the ocr module.       Value not set.
~~~

- Use the drop-down to set the enabled value to 'true'

~~~
Priority        Setting                         Value   Description                             Error Message
Recommended     Plugin.Import_ocr_enabled       true   Enable or disable the ocr module.       Value not set.
~~~

### Set any other required settings for your module

In this same menu set any other plugin settings that are required for testing.

## Install misp-module on an offline instance.
First, you need to grab all necessary packages for example like this :

Use pip wheel to create an archive
~~~
mkdir misp-modules-offline
pip3 wheel -r REQUIREMENTS shodan --wheel-dir=./misp-modules-offline
tar -cjvf misp-module-bundeled.tar.bz2 ./misp-modules-offline/*
~~~
On offline machine :
~~~
mkdir misp-modules-bundle
tar xvf misp-module-bundeled.tar.bz2 -C misp-modules-bundle
cd misp-modules-bundle
ls -1|while read line; do sudo pip3 install --force-reinstall --ignore-installed --upgrade --no-index --no-deps ${line};done
~~~
Next you can follow standard install procedure.

## How to contribute your own module?

Fork the project, add your module, test it and make a pull-request. Modules can be also private as you can add a module in your own MISP installation.


## Tips for developers creating modules

Download a pre-built virtual image from the [MISP training materials](https://www.circl.lu/services/misp-training-materials/).

- Create a Host-Only adapter in VirtualBox
- Set your Misp OVA to that Host-Only adapter
- Start the virtual machine
- Get the IP address of the virtual machine
- SSH into the machine (Login info on training page)
- Go into the misp-modules directory

~~~bash
cd /usr/local/src/misp-modules
~~~

Set the git repo to your fork and checkout your development branch. If you SSH'ed in as the misp user you will have to use sudo.

~~~bash
sudo git remote set-url origin https://github.com/YourRepo/misp-modules.git
sudo git pull
sudo git checkout MyModBranch
~~~

Remove the contents of the build directory and re-install misp-modules.

~~~bash
sudo rm -fr build/*
sudo -u www-data /var/www/MISP/venv/bin/pip install --upgrade .
~~~

SSH in with a different terminal and run `misp-modules` with debugging enabled.

~~~bash
# In case misp-modules is not a service do:
# sudo killall misp-modules
sudo systemctl disable --now misp-modules
sudo -u www-data /var/www/MISP/venv/bin/misp-modules -d
~~~


In your original terminal you can now run your tests manually and see any errors that arrive

~~~bash
cd tests/
curl -s http://127.0.0.1:6666/query -H "Content-Type: application/json" --data @MY_TEST_FILE.json -X POST
cd ../
~~~

## Documentation

In order to provide documentation about some modules that require specific input / output / configuration, the [index.md](docs/index.md) file within the [docs](docs) directory contains detailed information about the general purpose, requirements, features, input and ouput of each of these modules:

- ***description** - quick description of the general purpose of the module, as the one given by the moduleinfo
- **requirements** - special libraries needed to make the module work
- **features** - description of the way to use the module, with the required MISP features to make the module give the intended result
- **references** - link(s) giving additional information about the format concerned in the module
- **input** - description of the format of data used in input
- **output** - description of the format given as the result of the module execution

## Licenses
For further Information see also the [license file](license/).
