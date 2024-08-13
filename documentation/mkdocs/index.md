# Home

[![Build status](https://github.com/MISP/misp-modules/actions/workflows/python-package.yml/badge.svg)](https://github.com/MISP/misp-modules/actions/workflows/python-package.yml)[![Coverage Status](https://coveralls.io/repos/github/MISP/misp-modules/badge.svg?branch=main)](https://coveralls.io/github/MISP/misp-modules?branch=main)
[![codecov](https://codecov.io/gh/MISP/misp-modules/branch/main/graph/badge.svg)](https://codecov.io/gh/MISP/misp-modules)

MISP modules are autonomous modules that can be used to extend [MISP](https://github.com/MISP/MISP) for new services such as expansion, import, export and workflow action.

MISP modules can be also installed and used without MISP as a [standalone tool accessible via a convenient web interface](./website).

The modules are written in Python 3 following a simple API interface. The objective is to ease the extensions of MISP functionalities
without modifying core components. The API is available via a simple REST API which is independent from MISP installation or configuration and can be used with other tools.

For more information: [Extending MISP with Python modules](https://www.misp-project.org/misp-training/3.1-misp-modules.pdf) slides from [MISP training](https://github.com/MISP/misp-training).

## Existing MISP modules

### Expansion Modules
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
* [Lastline Lookup](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/lastline_query.py) - Deprecation notice: this module will be deprecated by December 2021, please use vmware_nsx module.  Query Lastline with an analysis link and parse the report into MISP attributes and objects.
* [Lastline Submit](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/expansion/lastline_submit.py) - Deprecation notice: this module will be deprecated by December 2021, please use vmware_nsx module.  Module to submit a file or URL to Lastline.
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

### Export Modules
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

### Import Modules
* [PDNS COF Importer](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/cof2misp.py) - Passive DNS Common Output Format (COF) MISP importer
* [CSV Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/csvimport.py) - Module to import MISP attributes from a csv file.
* [Cuckoo Sandbox Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/cuckooimport.py) - Module to import Cuckoo JSON.
* [Email Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/email_import.py) - Email import module for MISP
* [GoAML Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/goamlimport.py) - Module to import MISP objects about financial transactions from GoAML files.
* [Import Blueprint](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/import_blueprint.py) - Generic blueprint to be copy-pasted to quickly boostrap creation of import module.
* [Joe Sandbox Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/joe_import.py) - A module to import data from a Joe Sandbox analysis json report.
* [Lastline Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/lastline_import.py) - Deprecation notice: this module will be deprecated by December 2021, please use vmware_nsx module.  Module to import and parse reports from Lastline analysis links.
* [MISP JSON Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/mispjson.py) - Module to import MISP JSON format for merging MISP events.
* [OCR Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/ocr.py) - Optical Character Recognition (OCR) module for MISP.
* [OpenIOC Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/openiocimport.py) - Module to import OpenIOC packages.
* [TAXII 2.1 Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/taxii21.py) - Import content from a TAXII 2.1 server
* [ThreadAnalyzer Sandbox Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/threatanalyzer_import.py) - Module to import ThreatAnalyzer archive.zip / analysis.json files.
* [URL Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/url_import.py) - Simple URL import tool with Faup
* [VMRay API Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/vmray_import.py) - Module to import VMRay (VTI) results.
* [VMRay Summary JSON Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/vmray_summary_json_import.py) - Import a VMRay Summary JSON report.

### Action Modules
* [Mattermost](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/action_mod/mattermost.py) - Simplistic module to send message to a Mattermost channel.
* [Slack](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/action_mod/slack.py) - Simplistic module to send messages to a Slack channel.
* [Test action](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/action_mod/testaction.py) - This module is merely a test, always returning true. Triggers on event publishing.


## How to contribute your own module?

Fork the project, add your module, test it and make a pull-request. Modules can be also private as you can add a module in your own MISP installation.
For further information please see [Contribute](contribute/).


## Licenses
For further Information see also the [license file](license/).
