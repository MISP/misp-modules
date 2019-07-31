# Home

[![Build Status](https://travis-ci.org/MISP/misp-modules.svg?branch=master)](https://travis-ci.org/MISP/misp-modules)
[![Coverage Status](https://coveralls.io/repos/github/MISP/misp-modules/badge.svg?branch=master)](https://coveralls.io/github/MISP/misp-modules?branch=master)
[![codecov](https://codecov.io/gh/MISP/misp-modules/branch/master/graph/badge.svg)](https://codecov.io/gh/MISP/misp-modules)
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2F8ear%2Fmisp-modules.svg?type=shield)](https://app.fossa.io/projects/git%2Bgithub.com%2F8ear%2Fmisp-modules?ref=badge_shield)

MISP modules are autonomous modules that can be used for expansion and other services in [MISP](https://github.com/MISP/MISP).

The modules are written in Python 3 following a simple API interface. The objective is to ease the extensions of MISP functionalities
without modifying core components. The API is available via a simple REST API which is independent from MISP installation or configuration.

MISP modules support is included in MISP starting from version `2.4.28`.

For more information: [Extending MISP with Python modules](https://www.circl.lu/assets/files/misp-training/switch2016/2-misp-modules.pdf) slides from MISP training.


## Existing MISP modules

### Expansion modules

* [Backscatter.io](misp_modules/modules/expansion/backscatter_io.py) - a hover and expansion module to expand an IP address with mass-scanning observations.
* [BGP Ranking](misp_modules/modules/expansion/bgpranking.py) - a hover and expansion module to expand an AS number with the ASN description, its history, and position in BGP Ranking.
* [BTC scam check](misp_modules/modules/expansion/btc_scam_check.py) - An expansion hover module to instantly check if a BTC address has been abused.
* [BTC transactions](misp_modules/modules/expansion/btc_steroids.py) - An expansion hover module to get a blockchain balance and the transactions from a BTC address in MISP.
* [CIRCL Passive DNS](misp_modules/modules/expansion/circl_passivedns.py) - a hover and expansion module to expand hostname and IP addresses with passive DNS information.
* [CIRCL Passive SSL](misp_modules/modules/expansion/circl_passivessl.py) - a hover and expansion module to expand IP addresses with the X.509 certificate seen.
* [countrycode](misp_modules/modules/expansion/countrycode.py) - a hover module to tell you what country a URL belongs to.
* [CrowdStrike Falcon](misp_modules/modules/expansion/crowdstrike_falcon.py) - an expansion module to expand using CrowdStrike Falcon Intel Indicator API.
* [CVE](misp_modules/modules/expansion/cve.py) - a hover module to give more information about a vulnerability (CVE).
* [CVE advanced](misp_modules/modules/expansion/cve_advanced.py) - An expansion module to query the CIRCL CVE search API for more information about a vulnerability (CVE).
* [Cuckoo submit](misp_modules/modules/expansion/cuckoo_submit.py) - A hover module to submit malware sample, url, attachment, domain to Cuckoo Sandbox.
* [DBL Spamhaus](misp_modules/modules/expansion/dbl_spamhaus.py) - a hover module to check Spamhaus DBL for a domain name.
* [DNS](misp_modules/modules/expansion/dns.py) - a simple module to resolve MISP attributes like hostname and domain to expand IP addresses attributes.
* [docx-enrich](misp_modules/modules/expansion/docx-enrich.py) - an enrichment module to get text out of Word document into MISP (using free-text parser).
* [DomainTools](misp_modules/modules/expansion/domaintools.py) - a hover and expansion module to get information from [DomainTools](http://www.domaintools.com/) whois.
* [EUPI](misp_modules/modules/expansion/eupi.py) - a hover and expansion module to get information about an URL from the [Phishing Initiative project](https://phishing-initiative.eu/?lang=en).
* [Farsight DNSDB Passive DNS](misp_modules/modules/expansion/farsight_passivedns.py) - a hover and expansion module to expand hostname and IP addresses with passive DNS information.
* [GeoIP](misp_modules/modules/expansion/geoip_country.py) - a hover and expansion module to get GeoIP information from geolite/maxmind.
* [Greynoise](misp_modules/modules/expansion/greynoise.py) - a hover to get information from greynoise.
* [hashdd](misp_modules/modules/expansion/hashdd.py) - a hover module to check file hashes against [hashdd.com](http://www.hashdd.com) including NSLR dataset.
* [hibp](misp_modules/modules/expansion/hibp.py) - a hover module to lookup against Have I Been Pwned?
* [intel471](misp_modules/modules/expansion/intel471.py) - an expansion module to get info from [Intel471](https://intel471.com).
* [IPASN](misp_modules/modules/expansion/ipasn.py) - a hover and expansion to get the BGP ASN of an IP address.
* [iprep](misp_modules/modules/expansion/iprep.py) - an expansion module to get IP reputation from packetmail.net.
* [Joe Sandbox submit](misp_modules/modules/expansion/joesandbox_submit.py) - Submit files and URLs to Joe Sandbox.
* [Joe Sandbox query](misp_modules/modules/expansion/joesandbox_query.py) - Query Joe Sandbox with the link of an analysis and get the parsed data.
* [macaddress.io](misp_modules/modules/expansion/macaddress_io.py) - a hover module to retrieve vendor details and other information regarding a given MAC address or an OUI from [MAC address Vendor Lookup](https://macaddress.io). See [integration tutorial here](https://macaddress.io/integrations/MISP-module).
* [macvendors](misp_modules/modules/expansion/macvendors.py) - a hover module to retrieve mac vendor information.
* [ocr-enrich](misp_modules/modules/expansion/ocr-enrich.py) - an enrichment module to get OCRized data from images into MISP.
* [ods-enrich](misp_modules/modules/expansion/ods-enrich.py) - an enrichment module to get text out of OpenOffice spreadsheet document into MISP (using free-text parser).
* [odt-enrich](misp_modules/modules/expansion/odt-enrich.py) - an enrichment module to get text out of OpenOffice document into MISP (using free-text parser).
* [onyphe](misp_modules/modules/expansion/onyphe.py) - a modules to process queries on Onyphe.
* [onyphe_full](misp_modules/modules/expansion/onyphe_full.py) - a modules to process full queries on Onyphe.
* [OTX](misp_modules/modules/expansion/otx.py) - an expansion module for [OTX](https://otx.alienvault.com/).
* [passivetotal](misp_modules/modules/expansion/passivetotal.py) - a [passivetotal](https://www.passivetotal.org/) module that queries a number of different PassiveTotal datasets.
* [pdf-enrich](misp_modules/modules/expansion/pdf-enrich.py) - an enrichment module to extract text from PDF into MISP (using free-text parser).
* [pptx-enrich](misp_modules/modules/expansion/pptx-enrich.py) - an enrichment module to get text out of PowerPoint document into MISP (using free-text parser).
* [qrcode](misp_modules/modules/expansion/qrcode.py) - a module decode QR code, barcode and similar codes from an image and enrich with the decoded values.
* [rbl](misp_modules/modules/expansion/rbl.py) - a module to get RBL (Real-Time Blackhost List) values from an attribute.
* [reversedns](misp_modules/modules/expansion/reversedns.py) - Simple Reverse DNS expansion service to resolve reverse DNS from MISP attributes.
* [securitytrails](misp_modules/modules/expansion/securitytrails.py) - an expansion module for [securitytrails](https://securitytrails.com/).
* [shodan](misp_modules/modules/expansion/shodan.py) - a minimal [shodan](https://www.shodan.io/) expansion module.
* [Sigma queries](misp_modules/modules/expansion/sigma_queries.py) - Experimental expansion module querying a sigma rule to convert it into all the available SIEM signatures.
* [Sigma syntax validator](misp_modules/modules/expansion/sigma_syntax_validator.py) - Sigma syntax validator.
* [sourcecache](misp_modules/modules/expansion/sourcecache.py) - a module to cache a specific link from a MISP instance.
* [STIX2 pattern syntax validator](misp_modules/modules/expansion/stix2_pattern_syntax_validator.py) - a module to check a STIX2 pattern syntax.
* [ThreatCrowd](misp_modules/modules/expansion/threatcrowd.py) - an expansion module for [ThreatCrowd](https://www.threatcrowd.org/).
* [threatminer](misp_modules/modules/expansion/threatminer.py) - an expansion module to expand from [ThreatMiner](https://www.threatminer.org/).
* [urlhaus](misp_modules/modules/expansion/urlhaus.py) - Query urlhaus to get additional data about a domain, hash, hostname, ip or url.
* [urlscan](misp_modules/modules/expansion/urlscan.py) - an expansion module to query [urlscan.io](https://urlscan.io).
* [virustotal](misp_modules/modules/expansion/virustotal.py) - an expansion module to query the [VirusTotal](https://www.virustotal.com/gui/home) API with a high request rate limit required. (More details about the API: [here](https://developers.virustotal.com/reference))
* [virustotal_public](misp_modules/modules/expansion/virustotal_public.py) - an expansion module to query the [VirusTotal](https://www.virustotal.com/gui/home) API with a public key and a low request rate limit. (More details about the API: [here](https://developers.virustotal.com/reference))
* [VMray](misp_modules/modules/expansion/vmray_submit.py) - a module to submit a sample to VMray.
* [VulnDB](misp_modules/modules/expansion/vulndb.py) - a module to query [VulnDB](https://www.riskbasedsecurity.com/).
* [Vulners](misp_modules/modules/expansion/vulners.py) - an expansion module to expand information about CVEs using Vulners API.
* [whois](misp_modules/modules/expansion/whois.py) - a module to query a local instance of [uwhois](https://github.com/rafiot/uwhoisd).
* [wikidata](misp_modules/modules/expansion/wiki.py) - a [wikidata](https://www.wikidata.org) expansion module.
* [xforce](misp_modules/modules/expansion/xforceexchange.py) - an IBM X-Force Exchange expansion module.
* [xlsx-enrich](misp_modules/modules/expansion/xlsx-enrich.py) - an enrichment module to get text out of an Excel document into MISP (using free-text parser).
* [YARA query](misp_modules/modules/expansion/yara_query.py) - a module to create YARA rules from single hash attributes.
* [YARA syntax validator](misp_modules/modules/expansion/yara_syntax_validator.py) - YARA syntax validator.

### Export modules

* [CEF](misp_modules/modules/export_mod/cef_export.py) module to export Common Event Format (CEF).
* [Cisco FireSight Manager ACL rule](misp_modules/modules/export_mod/cisco_firesight_manager_ACL_rule_export.py) module to export as rule for the Cisco FireSight manager ACL.
* [GoAML export](misp_modules/modules/export_mod/goamlexport.py) module to export in [GoAML format](http://goaml.unodc.org/goaml/en/index.html).
* [Lite Export](misp_modules/modules/export_mod/liteexport.py) module to export a lite event.
* [PDF export](misp_modules/modules/export_mod/pdfexport.py) module to export an event in PDF.
* [Nexthink query format](misp_modules/modules/export_mod/nexthinkexport.py) module to export in Nexthink query format.
* [osquery](misp_modules/modules/export_mod/osqueryexport.py) module to export in [osquery](https://osquery.io/) query format.
* [ThreatConnect](misp_modules/modules/export_mod/threat_connect_export.py) module to export in ThreatConnect CSV format.
* [ThreatStream](misp_modules/modules/export_mod/threatStream_misp_export.py) module to export in ThreatStream format.

### Import modules

* [CSV import](misp_modules/modules/import_mod/csvimport.py) Customizable CSV import module.
* [Cuckoo JSON](misp_modules/modules/import_mod/cuckooimport.py) Cuckoo JSON import.
* [Email Import](misp_modules/modules/import_mod/email_import.py) Email import module for MISP to import basic metadata.
* [GoAML import](misp_modules/modules/import_mod/goamlimport.py) Module to import [GoAML](http://goaml.unodc.org/goaml/en/index.html) XML format.
* [Joe Sandbox import](misp_modules/modules/import_mod/joe_import.py) Parse data from a Joe Sandbox json report.
* [OCR](misp_modules/modules/import_mod/ocr.py) Optical Character Recognition (OCR) module for MISP to import attributes from images, scan or faxes.
* [OpenIOC](misp_modules/modules/import_mod/openiocimport.py) OpenIOC import based on PyMISP library.
* [ThreatAnalyzer](misp_modules/modules/import_mod/threatanalyzer_import.py) - An import module to process ThreatAnalyzer archive.zip/analysis.json sandbox exports.
* [VMRay](misp_modules/modules/import_mod/vmray_import.py) - An import module to process VMRay export.


## How to contribute your own module?

Fork the project, add your module, test it and make a pull-request. Modules can be also private as you can add a module in your own MISP installation.
For further information please see [Contribute](contribute/).


## Licenses
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%misp%2Fmisp-modules.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2Fmisp%2Fmisp-modules?ref=badge_large)

For further Information see also the [license file](license/).