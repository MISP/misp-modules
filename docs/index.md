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

* [BGP Ranking](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/bgpranking.py) - a hover and expansion module to expand an AS number with the ASN description, its history, and position in BGP Ranking.
* [BTC transactions](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/btc_steroids.py) - An expansion hover module to get a blockchain balance and the transactions from a BTC address in MISP.
* [CIRCL Passive DNS](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/circl_passivedns.py) - a hover and expansion module to expand hostname and IP addresses with passive DNS information.
* [CIRCL Passive SSL](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/circl_passivessl.py) - a hover and expansion module to expand IP addresses with the X.509 certificate seen.
* [countrycode](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/countrycode.py) - a hover module to tell you what country a URL belongs to.
* [CrowdStrike Falcon](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/crowdstrike_falcon.py) - an expansion module to expand using CrowdStrike Falcon Intel Indicator API.
* [CVE](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/cve.py) - a hover module to give more information about a vulnerability (CVE).
* [DBL Spamhaus](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/dbl_spamhaus.py) - a hover module to check Spamhaus DBL for a domain name.
* [DNS](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/dns.py) - a simple module to resolve MISP attributes like hostname and domain to expand IP addresses attributes.
* [DomainTools](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/domaintools.py) - a hover and expansion module to get information from [DomainTools](http://www.domaintools.com/) whois.
* [EUPI](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/eupi.py) - a hover and expansion module to get information about an URL from the [Phishing Initiative project](https://phishing-initiative.eu/?lang=en).
* [Farsight DNSDB Passive DNS](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/farsight_passivedns.py) - a hover and expansion module to expand hostname and IP addresses with passive DNS information.
* [GeoIP](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/geoip_country.py) - a hover and expansion module to get GeoIP information from geolite/maxmind.
* [hashdd](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/hashdd.py) - a hover module to check file hashes against [hashdd.com](http://www.hashdd.com) including NSLR dataset.
* [intel471](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/intel471.py) - an expansion module to get info from [Intel471](https://intel471.com).
* [IPASN](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/ipasn.py) - a hover and expansion to get the BGP ASN of an IP address.
* [iprep](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/iprep.py) - an expansion module to get IP reputation from packetmail.net.
* [macaddress.io](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/macaddress_io.py) - a hover module to retrieve vendor details and other information regarding a given MAC address or an OUI from [MAC address Vendor Lookup](https:/macaddress.io). See [integration tutorial here](https:/macaddress.io/integrations/MISP-module).
* [onyphe](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/onyphe.py) - a modules to process queries on Onyphe.
* [onyphe_full](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/onyphe_full.py) - a modules to process full queries on Onyphe.
* [OTX](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/otx.py) - an expansion module for [OTX](https://otx.alienvault.com/).
* [passivetotal](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/passivetotal.py) - a [passivetotal](https://www.passivetotal.org/) module that queries a number of different PassiveTotal datasets.
* [rbl](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/rbl.py) - a module to get RBL (Real-Time Blackhost List) values from an attribute.
* [reversedns](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/reversedns.py) - Simple Reverse DNS expansion service to resolve reverse DNS from MISP attributes.
* [securitytrails](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/securitytrails.py) - an expansion module for [securitytrails](https://securitytrails.com/).
* [shodan](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/shodan.py) - a minimal [shodan](https://www.shodan.io/) expansion module.
* [Sigma queries](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/sigma_queries.py) - Experimental expansion module querying a sigma rule to convert it into all the available SIEM signatures.
* [Sigma syntax validator](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/sigma_syntax_validator.py) - Sigma syntax validator.
* [sourcecache](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/sourcecache.py) - a module to cache a specific link from a MISP instance.
* [STIX2 pattern syntax validator](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/stix2_pattern_syntax_validator.py) - a module to check a STIX2 pattern syntax.
* [ThreatCrowd](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/threatcrowd.py) - an expansion module for [ThreatCrowd](https://www.threatcrowd.org/).
* [threatminer](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/threatminer.py) - an expansion module to expand from [ThreatMiner](https://www.threatminer.org/).
* [urlscan](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/urlscan.py) - an expansion module to query [urlscan.io](https://urlscan.io).
* [virustotal](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/virustotal.py) - an expansion module to pull known resolutions and malware samples related with an IP/Domain from virusTotal (this modules require a VirusTotal private API key)
* [VMray](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/vmray_submit.py) - a module to submit a sample to VMray.
* [VulnDB](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/vulndb.py) - a module to query [VulnDB](https://www.riskbasedsecurity.com/).
* [Vulners](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/vulners.py) - an expansion module to expand information about CVEs using Vulners API.
* [whois](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion) - a module to query a local instance of [uwhois](https://github.com/rafiot/uwhoisd).
* [wikidata](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/wiki.py) - a [wikidata](https://www.wikidata.org) expansion module.
* [xforce](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/xforceexchange.py) - an IBM X-Force Exchange expansion module.
* [YARA query](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/yara_query.py) - a module to create YARA rules from single hash attributes.
* [YARA syntax validator](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/expansion/yara_syntax_validator.py) - YARA syntax validator.

### Export modules

* [CEF](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/export_mod/cef_export.py) module to export Common Event Format (CEF).
* [GoAML export](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/export_mod/goamlexport.py) module to export in [GoAML format](http://goaml.unodc.org/goaml/en/index.html).
* [Lite Export](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/export_mod/liteexport.py) module to export a lite event.
* [Simple PDF export](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/export_mod/pdfexport.py) module to export in PDF (required: asciidoctor-pdf).
* [Nexthink query format](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/export_mod/nexthinkexport.py) module to export in Nexthink query format.
* [osquery](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/export_mod/osqueryexport.py) module to export in [osquery](https://osquery.io/) query format.
* [ThreatConnect](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/export_mod/threat_connect_export.py) module to export in ThreatConnect CSV format.
* [ThreatStream](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/export_mod/threatStream_misp_export.py) module to export in ThreatStream format.

### Import modules

* [CSV import](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/import_mod/csvimport.py) Customizable CSV import module.
* [Cuckoo JSON](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/import_mod/cuckooimport.py) Cuckoo JSON import.
* [Email Import](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/import_mod/email_import.py) Email import module for MISP to import basic metadata.
* [GoAML import](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/import_mod/) Module to import [GoAML](http://goaml.unodc.org/goaml/en/index.html) XML format.
* [OCR](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/import_mod/ocr.py) Optical Character Recognition (OCR) module for MISP to import attributes from images, scan or faxes.
* [OpenIOC](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/import_mod/openiocimport.py) OpenIOC import based on PyMISP library.
* [ThreatAnalyzer](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/import_mod/threatanalyzer_import.py) - An import module to process ThreatAnalyzer archive.zip/analysis.json sandbox exports.
* [VMRay](https://github.com/MISP/misp-modules/tree/master/misp_modules/modules/import_mod/vmray_import.py) - An import module to process VMRay export.


## How to contribute your own module?

Fork the project, add your module, test it and make a pull-request. Modules can be also private as you can add a module in your own MISP installation.
For further information please see [Contribute](contribute/).


## Licenses
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%misp%2Fmisp-modules.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2Fmisp%2Fmisp-modules?ref=badge_large)

For further Information see also the [license file](license/).