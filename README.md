# MISP modules

![MISP modules logo](https://raw.githubusercontent.com/MISP/misp-modules/1f5306710613960b158131f7757db1e08ccc8e4f/documentation/logos/misp-modules-logo.png)

[![Build status](https://github.com/MISP/misp-modules/actions/workflows/test-package.yml/badge.svg)](https://github.com/MISP/misp-modules/actions/workflows/test-package.yml)[![Coverage Status](https://coveralls.io/repos/github/MISP/misp-modules/badge.svg?branch=main)](https://coveralls.io/github/MISP/misp-modules?branch=main)
[![codecov](https://codecov.io/gh/MISP/misp-modules/branch/main/graph/badge.svg)](https://codecov.io/gh/MISP/misp-modules)

MISP modules are autonomous modules that can be used to extend [MISP](https://github.com/MISP/MISP) for new services such as expansion, import, export and workflow action.

MISP modules can be also installed and used without [MISP](https://misp-project.org/) as a [standalone tool accessible via a convenient web interface](./website) or using a [cli tool](https://github.com/MISP/misp-modules-cli).

The modules are written in Python 3 following a simple API interface. The objective is to ease the extensions of MISP functionalities without modifying core components. The API is available via a simple REST API which is independent from MISP installation or configuration and can be used with other tools. The API is also documented automatically via an OpenAPI end-point or a swagger file.

For more information: [Extending MISP with Python modules](https://www.misp-project.org/misp-training/3.1-misp-modules.pdf) slides from [MISP training](https://github.com/MISP/misp-training).

# Installation

Installation instructions can be found in the [installation documentation](https://misp.github.io/misp-modules/install/).

For optional server-local defaults for module API keys, URLs, and other settings,
see [Local module configuration defaults](documentation/mkdocs/module-config.md).
Enable them with `--module-config /etc/misp-modules/modules.json`; API-supplied
values take precedence and existing operation is unchanged without this option.

To optionally restrict PAP:RED expansion, start with `--restrict-pap-red`.
See [PAP:RED restrictions](documentation/mkdocs/pap-red.md) for source declarations
and the tag and hover context clients must supply. The default behavior is unchanged.

# How to add your own MISP modules?

Developing a MISP module yourself is fairly easy. Start with a template or existing module and continue from there.
More information can be found in the [contribute](https://misp.github.io/misp-modules/contribute/) section of the documentation.
To make a custom module appear in MISP, follow the
[installation, discovery and enablement checklist](documentation/mkdocs/contribute.md#install-and-enable-your-module).

# Documentation

In order to provide documentation about some modules that require specific input / output / configuration, the [documentation](https://misp.github.io/misp-modules/) contains detailed information about the general purpose, requirements, features, input and ouput of each of these modules:

- ***description** - quick description of the general purpose of the module, as the one given by the moduleinfo
- **requirements** - special libraries needed to make the module work
- **features** - description of the way to use the module, with the required MISP features to make the module give the intended result
- **references** - link(s) giving additional information about the format concerned in the module
- **input** - description of the format of data used in input
- **output** - description of the format given as the result of the module execution

## OpenAPI and API explorer

When the service is running you can discover the available endpoints in a machine-readable way via `/openapi.json`.
An interactive Swagger UI that consumes the same specification is available at `/openapi`.
The specification is generated during service startup, so restart `misp-modules` after adding or removing modules to refresh what those endpoints expose.

## Module statistics

`GET /statistics` returns per-module and aggregate query counts, successes, errors
(module errors, exceptions and timeouts), in-flight requests, success/error rates,
response times, cumulative latency histograms, body byte counts and last-use timestamps.
It includes loaded modules that have never been queried, including custom modules.

```bash
curl http://localhost:6666/statistics
```

Statistics are held in memory per server process and reset on restart. See
[statistics details](documentation/mkdocs/install.md#module-statistics) for metric semantics.
The endpoint is also described in `/openapi.json` and the `/openapi` explorer.

## Optional result caching

Use `--cache-config /etc/misp-modules/cache.json` to enable bounded, in-memory
result caching for individually selected expansion modules. Each module has its
own lifetime, entry limit and response byte limit. Identical concurrent queries
share one execution, and `/statistics` reports cache hits and avoided executions.
Caching is disabled by default and adds no dependencies or external services.
See [result caching](documentation/mkdocs/caching.md) for configuration and limits.

## Extended HTTP debugging

Run `misp-modules --debug-extended` to enable normal debug logging plus full outbound
HTTP request and response logging for modules and SDKs using `requests`. Logs include
methods, URLs, headers, and untruncated bodies, with an exchange ID and module name.
Streamed bodies are logged as they are transferred, without reading ahead.

This option logs credentials and sensitive payloads without redaction; enable it only
while troubleshooting. See the [installation documentation](documentation/mkdocs/install.md#debugging-outbound-http-requests)
for coverage and streaming details.

## Licenses
For further Information see the [license file](https://misp.github.io/misp-modules/license/).

## Existing MISP modules

<!-- Regenerate with: poetry run python documentation/generate.py --readme-only -->

### Expansion Modules
* [Abuse IPDB](misp_modules/modules/expansion/abuseipdb.py) - AbuseIPDB MISP expansion module
* [alphaMountain_risk](misp_modules/modules/expansion/alphaMountain.py) - alphaMountain threat intelligence lookup for IPs, domains, hostnames, and URLs - adds risk score tags
* [ANY.RUN Threat Intelligence Lookup](documentation/expansion/anyrun_lookup.md) - Search ANY.RUN threat intelligence for existing observations without submitting a sandbox task. lookup_days defaults to 180 (1–365). Each result section is capped by max_results. Returned summaries preserve provider threat levels, tags and observation dates.
* [ANYRUN Sandbox Submit](misp_modules/modules/expansion/anyrun_sandbox_submit.py) - A module designed to submit URLs or files to the ANY.RUN Sandbox for analysis and return the unique analysis link and ID.
* [APIFreaks Lookup](misp_modules/modules/expansion/apifreaks.py) - An expansion module for https://apifreaks.com/ that provides an enriched analysis of a domain, hostname, IP address, ASN or email address, including WHOIS, DNS, subdomains and domain-availability information.
* [OSINT DigitalSide](misp_modules/modules/expansion/apiosintds.py) - On demand query API for OSINT.digitalside.it project.
* [APIVoid](misp_modules/modules/expansion/apivoid.py) - Query APIVoid v2 for DNS records, SSL certificates and email verification.
* [AssemblyLine Query](documentation/expansion/assemblyline_query.md) - A module to query the AssemblyLine API with a submission ID to get the submission report and parse it.
* [AssemblyLine Submit](misp_modules/modules/expansion/assemblyline_submit.py) - A module to submit samples and URLs to AssemblyLine for advanced analysis, and return the link of the submission.
* [Backscatter.io](misp_modules/modules/expansion/backscatter_io.py) - Backscatter.io module to bring mass-scanning observations into MISP.
* [BeaconBeagle Lookup](documentation/expansion/beaconbeagle.md) - Look up Cobalt Strike beacon and C2 infrastructure, configurations and configuration-field pivots.
* [BGP Ranking](documentation/expansion/bgpranking.md) - Query CIRCL BGP Ranking for the daily ranking of an Autonomous System number.
* [binGraph](documentation/expansion/bingraph.md) - Create entropy and byte histogram PNG plots of an attachment or malware sample.
* [BTC Scam Check](misp_modules/modules/expansion/btc_scam_check.py) - An expansion hover module to query a special dns blacklist to check if a bitcoin address has been abused.
* [BTC Steroids](misp_modules/modules/expansion/btc_steroids.py) - An expansion hover module to get a blockchain balance from a BTC address in MISP.
* [CAPE Sandbox Enrichment](documentation/expansion/cape_sandbox.md) - Submit supplied samples to CAPEv2 or retrieve a completed JSON report by numeric task ID. Set api_url to the API v2 base, for example https://cape.example/apiv2. api_key is optional when the server permits unauthenticated requests. submit_samples defaults to false. max_size_mb defaults to 25 (1–100). Submission returns task IDs; use a text attribute containing a task ID for a later report lookup. Completed reports yield file hashes, network pivots and extracted configurations.
* [CCCS YARA Metadata Validator](documentation/expansion/cccs_yara.md) - Validate YARA rule metadata against the CCCS YARA specification.
* [Censys Enrich](misp_modules/modules/expansion/censys_enrich.py) - An expansion module to enrich attributes in MISP by quering the censys.io API
* [Censys Enrichment APIs](documentation/expansion/censys_enrichmentapis.md) - Retrieve Censys host enrichment, web properties on ports 80 and 443, or certificate metadata. Configure a platform API token and organization ID. Host service results are bounded; the annotation retains provider fields including scores and labels when present. Web property and certificate requests may consume standard credits under the account plan.
* [CIRCL Passive DNS](misp_modules/modules/expansion/circl_passivedns.py) - Module to access CIRCL Passive DNS.
* [CIRCL Passive SSL](misp_modules/modules/expansion/circl_passivessl.py) - Modules to access CIRCL Passive SSL.
* [Cisco PSIRT](documentation/expansion/cisco_psirt.md) - Retrieve Cisco PSIRT security advisories by CVE, Cisco advisory ID or Cisco bug ID.
* [Cisco Umbrella Investigate](documentation/expansion/cisco_umbrella.md) - Enrich a domain with Cisco Umbrella Investigate categorization and risk scores.
* [ClaamAV](misp_modules/modules/expansion/clamav.py) - Submit file to ClamAV
* [Cluster25 Expand](misp_modules/modules/expansion/cluster25_expand.py) - Module to query Cluster25 CTI.
* [Content fingerprint](documentation/expansion/content_fingerprint.md) - Fingerprint text, images and video, and compare supplied content with a reference item.
* [Markdown to PDF converter](misp_modules/modules/expansion/convert_markdown_to_pdf.py) - Render the markdown (under GFM) into PDF. Requires pandoc (https://pandoc.org/), wkhtmltopdf (https://wkhtmltopdf.org/) and mermaid dependencies.
* [Cortex XDR IOC Lookup](documentation/expansion/cortex_xdr_ioc_lookup.md) - Look up exact hash, domain and IP IOC rules in a Cortex XDR tenant.
* [Cortex XSOAR Indicator Lookup](documentation/expansion/cortex_xsoar_indicator_lookup.md) - Look up a MISP observable in Cortex XSOAR 8's indicator store with reputation and expiration metadata.
* [Country Code](misp_modules/modules/expansion/countrycode.py) - Module to expand country codes.
* [CPE Lookup](misp_modules/modules/expansion/cpe.py) - An expansion module to query the CVE search API with a cpe code to get its related vulnerabilities.
* [Criminal IP Enrichment](documentation/expansion/criminal_ip.md) - Retrieve IPv4 risk and infrastructure reports, existing domain scan listings, or a completed domain scan by numeric text ID. Provider JSON retains risk scores, flags and available vulnerability data. submit_unknown defaults to false; true submits a domain only when its report listing is empty. Submission returns a scan receipt without polling. Use its scan_id as text input to retrieve the full report.
* [CrowdSec CTI](misp_modules/modules/expansion/crowdsec.py) - Module to access CrowdSec CTI API.
* [CrowdStrike Falcon](documentation/expansion/crowdstrike_falcon.md) - Query CrowdStrike Falcon Intelligence indicators on demand.
* [Cuckoo Submit](misp_modules/modules/expansion/cuckoo_submit.py) - Submit files and URLs to Cuckoo Sandbox
* [CVE Lookup](misp_modules/modules/expansion/cve.py) - An expansion hover module to expand information about CVE id.
* [CVE Advanced Lookup](misp_modules/modules/expansion/cve_advanced.py) - An expansion module to query the CIRCL CVE search API for more information about a vulnerability (CVE).
* [Cytomic Orion Lookup](misp_modules/modules/expansion/cytomic_orion.py) - An expansion module to enrich attributes in MISP by quering the Cytomic Orion API
* [DarkEye](documentation/expansion/darkeye.md) - Look up domain exposure metadata in HaveIBeenRansom and Breach House.
* [DBL Spamhaus Lookup](misp_modules/modules/expansion/dbl_spamhaus.py) - Checks Spamhaus DBL for a domain name.
* [DECTRAX Threat Intelligence Enrichment](misp_modules/modules/expansion/dectrax.py) - Enrich IP observables against DECTRAX honeypot telemetry, decoy interactions, and EDL interdiction status.
* [DNS Resolver](misp_modules/modules/expansion/dns.py) - Simple DNS expansion service to resolve IP address from MISP attributes
* [DNS Record Enumeration](misp_modules/modules/expansion/dns_query.py) - Enumerate DNS record types and extract domain, IP, email and URL pivots. [JSON documentation](documentation/expansion/dns_query.json).
* [DNSlytics Domain Search](documentation/expansion/dnslytics.md) - Run an explicit DNSlytics domain dataset query supplied as a text attribute. One request retrieves page 1; at most max_results domains are imported. Domain metadata preserves active or dropped status when supplied. The premium endpoint consumes credits; a local cap does not reduce the provider charge. This initial module does not perform additional DNS or IP2ASN requests.
* [DNSTwist Domain Enrichment](documentation/expansion/dnstwist.md) - Generate domain permutations locally with optional DNS resolution. Install dnstwist in the module server Python environment. resolve defaults to false and performs no DNS checks. Set resolve=true to return DNS-resolving candidates with available A, AAAA, NS and MX observations. timeout defaults to 30 seconds (1–120); threads defaults to 4 (1–16). An isolated subprocess prevents changes to the module server argument list and bounds runtime. Generated candidates and resolving domains are investigation leads, not maliciousness assertions. Each result preserves its mutation algorithm.
* [DOCX Enrich](misp_modules/modules/expansion/docx_enrich.py) - Module to extract freetext from a .docx document.
* [DomainTools Lookup](documentation/expansion/domaintools.md) - Legacy DomainTools WHOIS, reputation and reverse lookup expansion module.
* [DomainTools Iris Enrich](misp_modules/modules/expansion/domaintools_iris_enrich.py) - Retrieve DomainTools Iris Enrich results using the provider reference field and query conventions.
* [DomainTools Iris Investigate](misp_modules/modules/expansion/domaintools_iris_investigate.py) - Retrieve DomainTools Iris Investigate results using the provider reference field and query conventions.
* [DomainTools Iris Pivot](misp_modules/modules/expansion/domaintools_iris_pivot.py) - Retrieve DomainTools Iris Pivot results using the provider reference field and query conventions.
* [DShield SANS ISC](documentation/expansion/dshield.md) - Look up IP reports, target counts, network ownership and threat-feed observations in DShield / SANS ISC.
* [DuckDuckGo Search](misp_modules/modules/expansion/duckduckgo_search.py) - Search DuckDuckGo for web references to an attribute without an API key. [JSON documentation](documentation/expansion/duckduckgo_search.json).
* [Email Authentication](misp_modules/modules/expansion/email_authentication.py) - Gather published SPF, DKIM and DMARC DNS records for a hostname or domain. [JSON documentation](documentation/expansion/email_authentication.json).
* [Email Security Check](misp_modules/modules/expansion/email_security_check.py) - Check email security posture (SPF, DKIM, DMARC, MTA-STS) for a domain.
* [EQL Query Generator](misp_modules/modules/expansion/eql.py) - EQL query generation for a MISP attribute.
* [ESET Threat Intelligence Report](documentation/expansion/eset_report.md) - Download an ESET ETI PDF from a supported report download link and return a report object with its PDF attachment and SHA-256. Only HTTPS report paths on eti.eset.com, www.eset.com or eset.com are accepted. The complete generated api_token is forwarded unchanged as the provider Bearer credential. Redirects are rejected to keep credentials on the selected host. max_size_mb defaults to 25 (1–100); streamed responses are capped before importing. The report content hash supports duplicate detection when reviewing enrichment results.
* [EUPI Lookup](misp_modules/modules/expansion/eupi.py) - A module to query the Phishing Initiative service (https://phishing-initiative.lu).
* [URL Components Extractor](misp_modules/modules/expansion/extract_url_components.py) - Extract URL components
* [Extuno Lookup](misp_modules/modules/expansion/extuno.py) - Query Extuno for the reputation of a browser extension, an IDE extension or a package, identified by its store id or its listing URL.
* [Farsight DNSDB Lookup](documentation/expansion/farsight_passivedns.md) - Module to access Farsight DNSDB Passive DNS.
* [File and Media Metadata](documentation/expansion/file_metadata.md) - Extract selected file, document and media metadata locally with ExifTool.
* [FIRST EPSS Lookup](documentation/expansion/first_epss.md) - Query FIRST directly for a CVE EPSS probability, percentile and score date without requiring another vulnerability service. EPSS estimates exploitation probability over the next 30 days. Values remain in the provider range 0–1. The module reuses the bundled epss-score template. An empty response does not become a zero score.
* [Flowintel case lookup](documentation/expansion/flowintel.md) - Find Flowintel cases containing the queried attribute value.
* [Flowtriq DDoS Intelligence](misp_modules/modules/expansion/flowtriq.py) - Query Flowtriq for DDoS attack intelligence on IP addresses
* [FortiSandbox Enrichment](documentation/expansion/fortisandbox.md) - Authenticate to a FortiSandbox appliance and retrieve an existing rating by SHA-1 or SHA-256. Set api_url to the appliance HTTPS origin, without /jsonrpc. For supplied files, calculate SHA-256 and look up the rating first. submit_samples defaults to false; true permits submission when the rating is unknown. max_size_mb defaults to 25 (1–100). A submission receipt is returned without polling. Provider ratings remain in their original vocabulary.
* [GCVE CPE](documentation/expansion/gcve_cpe.md) - Expand CPE attributes with GCVE CPE catalog metadata, package mappings and vulnerability references.
* [GeoIP ASN Lookup](misp_modules/modules/expansion/geoip_asn.py) - Query a local copy of the MaxMind GeoLite2 ASN database (MMDB format)
* [GeoIP City Lookup](misp_modules/modules/expansion/geoip_city.py) - An expansion module to query a local copy of MaxMind GeoIP2 or GeoLite2 database with an IP address, in order to get information about the city where it is located.
* [GeoIP Country Lookup](misp_modules/modules/expansion/geoip_country.py) - Query a local MaxMind GeoIP2 or GeoLite2 Country database (MMDB format)
* [geoPlugin Lookup](documentation/expansion/geoplugin.md) - An expansion and hover module to geolocate an IP address with geoPlugin.
* [GLIMPS Malware Enrichment](documentation/expansion/glimps_malware.md) - Retrieve GLIMPS Detect results by SHA-256 or analysis UUID supplied as text. Set api_url to the service HTTPS origin. Supplied samples are hashed and looked up first. submit_samples defaults to false; true permits submitting a previously unknown sample. max_size_mb defaults to 25 (1–100). Submission returns an analysis UUID for later text lookup. Provider verdicts and analysis details are retained in a sandbox-report object. The access token for an expert view is excluded from imported report data.
* [Google Safe Browsing Lookup](misp_modules/modules/expansion/google_safe_browsing.py) - Google safe browsing expansion module
* [Google Threat Intelligence Lookup](misp_modules/modules/expansion/google_threat_intelligence.py) - An expansion module to have the observable's threat score assessed by Google Threat Intelligence.
* [GreyNoise Lookup](misp_modules/modules/expansion/greynoise.py) - Module to query IP and CVE information from GreyNoise
* [GreyNoise Vulnerability Intelligence](documentation/expansion/greynoise_vuln.md) - Retrieve dedicated GreyNoise CVE intelligence, including available exploitation activity, exploit counts, product details and prioritization fields. Provider fields are preserved in a referenced annotation. Coverage depends on the API key entitlement. An absent CVE returns no enrichment and does not imply no exploitation.
* [Hashdd Lookup](misp_modules/modules/expansion/hashdd.py) - A hover module to check hashes against hashdd.com including NSLR dataset.
* [CIRCL Hashlookup Lookup](misp_modules/modules/expansion/hashlookup.py) - An expansion module to query the CIRCL hashlookup services to find it if a hash is part of a known set such as NSRL.
* [Have I Been Pwned Lookup](misp_modules/modules/expansion/hibp.py) - Module to access haveibeenpwned.com API.
* [Host.io](documentation/expansion/hostio.md) - Retrieve Host.io DNS, website and co-hosted domain observations.
* [HTML to Markdown](misp_modules/modules/expansion/html_to_markdown.py) - Expansion module to fetch the html content from an url and convert it into markdown.
* [HYAS Insight Lookup](misp_modules/modules/expansion/hyasinsight.py) - HYAS Insight integration to MISP provides direct, high volume access to HYAS Insight data. It enables investigators and analysts to understand and defend against cyber adversaries and their infrastructure.
* [Hybrid Analysis Sandbox](documentation/expansion/hybrid_analysis.md) - Look up Hybrid Analysis reports or submit a file or URL for sandbox analysis.
* [Hygiene Warninglist Check](documentation/expansion/hygiene.md) - Check an observable against local MISP warninglists and record the matching lists.
* [Import External Reference](documentation/expansion/import_external_reference.md) - Capture a public web reference as Markdown or a PDF attachment.
* [Intel471 Lookup](misp_modules/modules/expansion/intel471.py) - Module to access Intel 471
* [Intel 471 Hunter](documentation/expansion/intel471_hunt.md) - Retrieve Intel 471 Hunter hunt packages, Sigma rules and analyst guidance.
* [Intezer Sandbox](documentation/expansion/intezer.md) - Retrieve Intezer Analyze file reports or submit an attachment for analysis.
* [IP2Location.io Lookup](misp_modules/modules/expansion/ip2locationio.py) - An expansion module to query IP2Location.io to gather more information on a given IP address.
* [ipapi.is Lookup](misp_modules/modules/expansion/ipapi_is.py) - An expansion and hover module to enrich an IP address with geolocation, ASN, company and abuse contact data, and VPN (with the provider), proxy, Tor and datacenter detection from ipapi.is.
* [IPASN-History Lookup](misp_modules/modules/expansion/ipasn.py) - Module to query an IP ASN history service (https://github.com/D4-project/IPASN-History).
* [IPGeolocation.io Lookup](misp_modules/modules/expansion/ipgeolocation.py) - An expansion and hover module to enrich an IP address with geolocation, ASN, company, threat intelligence (threat score, VPN, proxy, Tor, bot and spam signals) and abuse contact information from IPGeolocation.io, either through the API or from local IPGeolocation.io MMDB databases.
* [IPInfo.io Lookup](misp_modules/modules/expansion/ipinfo.py) - An expansion module to query IPinfo for geolocation, ASN and contextual IP intelligence.
* [IPQualityScore Lookup](misp_modules/modules/expansion/ipqs_fraud_and_risk_scoring.py) - IPQualityScore MISP Expansion Module for IP reputation,        Email Validation, Phone Number Validation, Malicious Domain,Malicious URL Scanner,Malicious File Scanner & Compromised username, Password, Email
* [IPRep Lookup](misp_modules/modules/expansion/iprep.py) - Module to query IPRep data for IP addresses.
* [isMalicious Lookup](misp_modules/modules/expansion/ismalicious.py) - Query isMalicious for IP, domain, hostname, and URL reputation.
* [IVRE](documentation/expansion/ivre.md) - Retrieve active scan observations from an IVRE web API.
* [Ninja Template Rendering](misp_modules/modules/expansion/jinja_template_rendering.py) - Render the template with the data passed
* [Joe Sandbox Import](misp_modules/modules/expansion/joesandbox_query.py) - Query Joe Sandbox API with a submission url to get the json report and extract its data that is parsed and converted into MISP attributes and objects.
* [Joe Sandbox Submit](misp_modules/modules/expansion/joesandbox_submit.py) - A module to submit files or URLs to Joe Sandbox for an advanced analysis, and return the link of the submission.
* [Kaspersky Threat Intelligence Portal](documentation/expansion/kaspersky.md) - Retrieve Kaspersky commercial Threat Intelligence Portal reports.
* [Lamis Network Lookup](misp_modules/modules/expansion/lamis_network.py) - Lamis Network IP Intelligence and Risk Scoring expansion module.
* [LastInfoSec](documentation/expansion/lastinfosec.md) - Retrieve LastInfoSec STIX 2.1 intelligence and convert it to MISP.
* [Lastline Lookup](misp_modules/modules/expansion/lastline_query.py) - Deprecation notice: this module will be deprecated by December 2021, please use vmware_nsx module.  Query Lastline with an analysis link and parse the report into MISP attributes and objects.
* [Lastline Submit](misp_modules/modules/expansion/lastline_submit.py) - Deprecation notice: this module will be deprecated by December 2021, please use vmware_nsx module.  Module to submit a file or URL to Lastline.
* [Lookyloo lookup](misp_modules/modules/expansion/lookyloo.py) - Find Lookyloo captures by UUID or containing an IP, hostname, URL, resource hash or favicon hash. [JSON documentation](documentation/expansion/lookyloo.json).
* [Lookyloo capture](misp_modules/modules/expansion/lookyloo_capture.py) - Enrich a Lookyloo capture link or UUID with observed resources and analysis context. [JSON documentation](documentation/expansion/lookyloo_capture.json).
* [Macaddress.io Lookup](misp_modules/modules/expansion/macaddress_io.py) - MISP hover module for macaddress.io
* [macadress.com Lookup](misp_modules/modules/expansion/macadress_com.py) - Module to access macadress.com API.
* [Macvendors Lookup](misp_modules/modules/expansion/macvendors.py) - Module to access Macvendors API.
* [MalBeacon](documentation/expansion/malbeacon.md) - Retrieve MalBeacon C2 and actor infrastructure observations.
* [Malpedia lookup](misp_modules/modules/expansion/malpedia.py) - Search Malpedia families and actors, or expand a sample hash or Malpedia record URL. [JSON documentation](documentation/expansion/malpedia.json).
* [MalShare Upload](misp_modules/modules/expansion/malshare_upload.py) - Module to push malware samples to MalShare
* [Malwagon Lookup](misp_modules/modules/expansion/malwagon.py) - Look up a SHA256 digest in the Malwagon sandbox and return the scans it already has for it.
* [Malwagon Submit](misp_modules/modules/expansion/malwagon_submit.py) - Detonate a sample or a URL in the Malwagon sandbox and return the analysis.
* [Malware Bazaar Lookup](misp_modules/modules/expansion/malwarebazaar.py) - Query Malware Bazaar to get additional information about the input hash.
* [Manalyze](documentation/expansion/manalyze.md) - Analyze PE attachments and malware samples with a local Manalyze installation.
* [McAfee MVISION Insights Lookup](misp_modules/modules/expansion/mcafee_insights_enrich.py) - Lookup McAfee MVISION Insights Details
* [Metras Enrichment](documentation/expansion/metras.md) - Enrich file hashes and IP addresses with Metras EDR inventory and fleet context.
* [GeoIP Enrichment](misp_modules/modules/expansion/mmdb_lookup.py) - A hover and expansion module to enrich an ip with geolocation and ASN information from an mmdb server instance, such as CIRCL's ip.circl.lu.
* [MobSF](documentation/expansion/mobsf.md) - Submit mobile applications to MobSF or retrieve static analysis reports by MD5.
* [MODAT Magnify](misp_modules/modules/expansion/modat.py) - Enrich internet infrastructure using MODAT Magnify host, service and DNS observations. [JSON documentation](documentation/expansion/modat.json).
* [MWDB Submit](documentation/expansion/mwdb.md) - Module to push malware samples to a MWDB instance
* [MWDB Query](documentation/expansion/mwdb_query.md) - Query an MWDB instance for an existing file by hash.
* [n8n Data Table Lookup](documentation/expansion/n8n_data_table_lookup.md) - Find an observable in a selected n8n Data Table string column using the public REST API.
* [NetAPI Lookup](misp_modules/modules/expansion/netapi.py) - Check a domain, hostname, URL or IP address against the NetAPI compromised feeds and get the domain's position in the NetAPI Top 1M.
* [NeutrinoAPI IP Blocklist](documentation/expansion/neutrino.md) - Enrich public IP addresses with NeutrinoAPI blocklist categories, detection flags, timestamps and sensor context.
* [OCR Enrich](misp_modules/modules/expansion/ocr_enrich.py) - Module to process some optical character recognition on pictures.
* [ODS Enrich](misp_modules/modules/expansion/ods_enrich.py) - Module to extract freetext from a .ods document.
* [ODT Enrich](misp_modules/modules/expansion/odt_enrich.py) - Module to extract freetext from a .odt document.
* [Offensive Agency Lookup](documentation/expansion/offensive_agency_lookup.md) - Look up an IP address in Offensive Agency's ONYPHE observations.
* [Onion Lookup](misp_modules/modules/expansion/onion_lookup.py) - MISP module using the MISP standard. Uses the onion-lookup service to get information about an onion.
* [Onyphe Lookup](documentation/expansion/onyphe.md) - Module to process a query on Onyphe.
* [Onyphe Full Lookup](misp_modules/modules/expansion/onyphe_full.py) - Module to process a full query on Onyphe.
* [OpenCTI Lookup](misp_modules/modules/expansion/opencti.py) - Query an OpenCTI instance for exact observable matches and their context and source references.
* [Orange Cyberdefense Datalake](documentation/expansion/orange_cyberdefense.md) - Look up indicators in the Orange Cyberdefense Datalake API.
* [Orion Malware](documentation/expansion/orion_malware.md) - Retrieve existing Orion Malware reports by file hash.
* [OSINT Industries](documentation/expansion/osint_industries.md) - Find OSINT Industries account and identity context for an email, phone, username or wallet.
* [OTI Labs Domain Intelligence](misp_modules/modules/expansion/otilabs.py) - An expansion module for the OTI Labs Domain Intelligence API (https://oti-labs.com/domain-intelligence-api). One request returns WHOIS/RDAP registration, DNS records, the certificate the domain serves, live subdomains with their IP addresses and the SPF, DMARC and DKIM records.
* [AlienVault OTX Lookup](misp_modules/modules/expansion/otx.py) - Module to get information from AlienVault OTX.
* [Palo Alto WildFire](documentation/expansion/paloalto_wildfire.md) - Retrieve WildFire verdicts and XML reports, or submit an attachment for analysis.
* [Pandora Submit](documentation/expansion/pandora_submit.md) - Submit attachments and malware samples to Pandora and return a link to the analysis.
* [Passive SSH Enrichment](misp_modules/modules/expansion/passive_ssh.py) - An expansion module to enrich, SSH key fingerprints and IP addresses with information collected by passive-ssh
* [PassiveTotal Lookup](misp_modules/modules/expansion/passivetotal.py) - Query PassiveTotal for passive DNS, historic SSL, WHOIS and host attributes. Requires a PassiveTotal username and API key. See the [Microsoft Defender Threat Intelligence documentation](https://learn.microsoft.com/en-us/defender-xdr/defender-threat-intelligence).
* [PDF Enrich](misp_modules/modules/expansion/pdf_enrich.py) - Module to extract freetext from a PDF document.
* [PGP Keyserver](misp_modules/modules/expansion/pgp_keyserver.py) - Pivot on OpenPGP key IDs, fingerprints, email addresses and UIDs using an HKP keyserver. [JSON documentation](documentation/expansion/pgp_keyserver.json).
* [phishunt Lookup](misp_modules/modules/expansion/phishunt.py) - Look up a host in phishunt (phishunt.io), the free CC0 feed of live phishing domains: the phishing URLs detected on that exact host, the brand they target, when they were first seen, where they are hosted and which other feeds flag them.
* [Phone Number Information](misp_modules/modules/expansion/phone_number_info.py) - Offline phone-number normalization, numbering-plan geography and original carrier lookup. [JSON documentation](documentation/expansion/phone_number_info.json).
* [Plum Island IP History](documentation/expansion/plum_island.md) - Retrieve historical scan observations from the Plum Island Discovery API v1.
* [Plum Island Search](documentation/expansion/plum_island_search.md) - Find IPs observed with a domain, hostname, network or certificate fingerprint in Plum Island.
* [PolySwarm Enrichment](documentation/expansion/polyswarm.md) - Retrieve PolySwarm sample reputation, engine verdicts and file metadata.
* [PolySwarm Sandbox](documentation/expansion/polyswarm_sandbox.md) - Retrieve PolySwarm sandbox tasks or submit an existing PolySwarm sample for sandbox analysis.
* [PPTX Enrich](misp_modules/modules/expansion/pptx_enrich.py) - Module to extract freetext from a .pptx document.
* [Proofpoint ET Intelligence](documentation/expansion/proofpoint_et_intelligence.md) - Enrich domains, IPv4 addresses and MD5 hashes using Proofpoint ET Intelligence.
* [PTR Classification](misp_modules/modules/expansion/ptrclassify.py) - Classify PTR hostnames and tag queried attributes with the ptrclassify taxonomy. [JSON documentation](documentation/expansion/ptrclassify.json).
* [Pulsedive](documentation/expansion/pulsedive.md) - Look up IP, domain and URL risk, linked threats, feeds and DNS observations in Pulsedive.
* [Qintel QSentry Lookup](misp_modules/modules/expansion/qintel_qsentry.py) - A hover and expansion module which queries Qintel QSentry for ip reputation data
* [QR Code Decode](misp_modules/modules/expansion/qrcode.py) - Decode QR codes from attachments OR remote URLs (Anti-Quishing).
* [Qualys CVE Enrichment](documentation/expansion/qualys_cve.md) - Retrieve Qualys KnowledgeBase vulnerability details for a CVE identifier.
* [RandomcoinDB Lookup](misp_modules/modules/expansion/ransomcoindb.py) - Module to access the ransomcoinDB (see https://ransomcoindb.concinnity-risks.com)
* [RansomLook Lookup](misp_modules/modules/expansion/ransomlook.py) - Query the RansomLook API and return matching ransomware leak-site posts as MISP objects.
* [Rapid7 AttackerKB lookup](misp_modules/modules/expansion/rapid7_attackerkb.py) - Module to lookup CVE attributes in Rapid7 AttackerKB.
* [Real-time Blackhost Lists Lookup](misp_modules/modules/expansion/rbl.py) - Module to check an IPv4 address against known RBLs.
* [RDAP Lookup](misp_modules/modules/expansion/rdap.py) - An expansion module to query the public RDAP bootstrap (rdap.org) for registration data of a domain, hostname, IP address or URL. RDAP (Registration Data Access Protocol, RFC 9082/9083) is the free, unauthenticated and structured successor to WHOIS.
* [Recorded Future Enrich](misp_modules/modules/expansion/recordedfuture.py) - Module to enrich attributes with threat intelligence from Recorded Future.
* [Reverse DNS](misp_modules/modules/expansion/reversedns.py) - Simple Reverse DNS expansion service to resolve reverse DNS from MISP attributes.
* [ReversingLabs Malware Presence](documentation/expansion/reversinglabs_malware_presence.md) - Retrieve ReversingLabs file reputation and malware presence.
* [ReversingLabs Spectra Analyze](misp_modules/modules/expansion/reversinglabs_spectra_analyze.py) - Module to enrich file hashes, domains, IPs and URLs with ReversingLabs Spectra Analyze threat intelligence.
* [ReversingLabs Spectra Intelligence Submission](documentation/expansion/reversinglabs_spectra_intel_submission.md) - Submit a file hash, URL or attachment to ReversingLabs Spectra Intelligence dynamic analysis.
* [RIPEstat](documentation/expansion/ripestat.md) - Query RIPEstat for the announcing ASNs, prefixes and ASN holders of IP, prefix and AS attributes.
* [RST Cloud Cobalt Strike Beacon](misp_modules/modules/expansion/rst_cs_beacon.py) - Scan a target IP[:port] for a Cobalt Strike beacon configuration via RST Scan API.
* [RST Cloud Favicon](misp_modules/modules/expansion/rst_favicon.py) - Fetch a target's favicon (image + all hashes for Shodan/Netlas/Censys pivoting) via RST Scan API.
* [RST Cloud HTML Fetcher](misp_modules/modules/expansion/rst_html.py) - Fetch rendered HTML body or extracted JavaScript for a URL/IP target via RST Scan API.
* [RST Cloud IoC Lookup](misp_modules/modules/expansion/rst_ioc.py) - Enrich indicators with RST Cloud threat intelligence. Returns an rst-ioc object (score, attribution, geo/ASN for IPs, DNS/WHOIS for domains, parsed components for URLs, related hashes for file hashes) linked back to the enriched attribute.
* [RST Cloud Noise Control](misp_modules/modules/expansion/rst_noise_control.py) - Check whether a value (IP, domain, URL or hash) is known-good / noise via RST Noise Control. Returns an rst-noise object (verdict, category) linked back to the enriched attribute.
* [RST Cloud Screenshot](misp_modules/modules/expansion/rst_screenshot.py) - Capture a page screenshot (first/full/last frame) of a URL/IP target via RST Scan API.
* [RST Cloud SSL Certificate](misp_modules/modules/expansion/rst_ssl.py) - Fetch the SSL certificate for an IP[:port] as an x509 object via RST Scan API.
* [RST Cloud Whois](misp_modules/modules/expansion/rst_whois.py) - Retrieve parsed WHOIS information for a domain via RST Cloud.
* [Rulezet Rule Validator](misp_modules/modules/expansion/rulezet_validator.py) - Validate the syntax of detection rules (YARA, Sigma, Suricata, Zeek, NOVA, Wazuh, Kunai, NSE, CRS, Splunk, Elastic, KQL, ATR, PLUM, Sagan) with the Rulezet API.
* [ScanMalware Lookup](misp_modules/modules/expansion/scanmalware.py) - Query ScanMalware for subdomains, browser-observed hosts and sandbox scan results.
* [SecurityTrails Lookup](misp_modules/modules/expansion/securitytrails.py) - An expansion modules for SecurityTrails.
* [ShadowTrackr](documentation/expansion/shadowtrackr.md) - Enrich IP addresses with ShadowTrackr false-positive and infrastructure context.
* [Sherlock Lookup](misp_modules/modules/expansion/sherlock.py) - Find social media accounts by username with Sherlock.
* [Shodan Lookup](misp_modules/modules/expansion/shodan.py) - Module to query on Shodan.
* [Shodan InternetDB](documentation/expansion/shodan_internetdb.md) - Look up exposed services, hostnames, CPEs and vulnerabilities in the free Shodan InternetDB API.
* [Shuffle Datastore Lookup](documentation/expansion/shuffle_datastore_lookup.md) - Look up a MISP observable's key in a selected Shuffle organization and Datastore category.
* [SiberKapan Lookup](documentation/expansion/siberkapan.md) - Hover and expansion module to look up an IP address in SiberKapan threat intelligence.
* [Sigma Rule Converter](misp_modules/modules/expansion/sigma_queries.py) - An expansion hover module to display the result of sigma queries.
* [Sigma Syntax Validator](misp_modules/modules/expansion/sigma_syntax_validator.py) - An expansion hover module to perform a syntax check on sigma rules.
* [SigMF Expansion](misp_modules/modules/expansion/sigmf_expand.py) - Expands a SigMF Recording object into a SigMF Expanded Recording object, extracts a SigMF archive into a SigMF Recording object.
* [Silent Push Enrichment](documentation/expansion/silentpush.md) - Retrieve domain and IP risk and infrastructure context from Silent Push.
* [SoChain](misp_modules/modules/expansion/sochain.py) - Get the balance, activity, counterparties and address poisoning findings of a BTC, LTC, DOGE or ZEC address from SoChain. [JSON documentation](documentation/expansion/sochain.json).
* [Socialscan Lookup](misp_modules/modules/expansion/socialscan.py) - A hover module to get information on the availability of an email address or username on some online platforms.
* [SOCRadar Threat Intelligence](misp_modules/modules/expansion/socradar_lookup.py) - Enrich MISP attributes with SOCRadar threat intelligence. Queries SOCRadar IoC Enrichment API for categorization, malware families, threat actors, confidence scores, feed source history, and geographic attribution.
* [SophosLabs Intelix Lookup](misp_modules/modules/expansion/sophoslabs_intelix.py) - An expansion module to query the Sophoslabs intelix API to get additional information about an ip address, url, domain or sha256 attribute.
* [URL Archiver](misp_modules/modules/expansion/sourcecache.py) - Module to cache web pages of analysis reports, OSINT sources. The module returns a page-capture object holding the cached page.
* [SpamCop Lookup](misp_modules/modules/expansion/spamcop.py) - Check an IPv4 address against the SpamCop Blocking List (SCBL).
* [SSH Fingerprint](misp_modules/modules/expansion/ssh_fingerprint.py) - Grab SSH server fingerprint from an IP and return as passive-ssh MISP object.
* [Qualys SSL Labs](documentation/expansion/ssllabs.md) - Retrieve SSL Labs API v4 TLS assessments, endpoint grades and certificate details for a hostname.
* [Stairwell Lookup](misp_modules/modules/expansion/stairwell.py) - Module to query the Stairwell API to get additional information about the input hash attribute
* [STIX2 Pattern Generator](documentation/expansion/stix2_pattern.md) - Generate a validated STIX 2.1 pattern from a MISP attribute.
* [STIX2 Pattern Syntax Validator](misp_modules/modules/expansion/stix2_pattern_syntax_validator.py) - An expansion hover module to perform a syntax check on stix2 patterns.
* [Team Cymru Scout](documentation/expansion/team_cymru_scout.md) - Retrieve Scout foundation intelligence for an IP address or search for a domain.
* [Team Cymru Scout Search](documentation/expansion/team_cymru_scout_search.md) - Run an explicit Scout search query and import the returned intelligence.
* [ThreatCrowd Lookup](misp_modules/modules/expansion/threatcrowd.py) - Module to get information from ThreatCrowd.
* [ThreadFox Lookup](misp_modules/modules/expansion/threatfox.py) - Module to search for an IOC on ThreatFox by abuse.ch.
* [ThreatMiner Lookup](misp_modules/modules/expansion/threatminer.py) - Module to get information from ThreatMiner.
* [Tines Record Lookup](documentation/expansion/tines_record_lookup.md) - Find a MISP observable in a selected Tines record type and field using Records v2 search.
* [TLS Certificate Check](misp_modules/modules/expansion/tls_certificate_check.py) - Extract TLS certificate details from a domain and return as x509 MISP object.
* [Torq Observable Lookup](documentation/expansion/torq_observable_lookup.md) - Look up a MISP observable in Torq and return verified matches with reputation and threat intelligence.
* [Triage Report Enrichment](documentation/expansion/triage_query.md) - Retrieve Triage overview reports by trusted report link or search existing analyses by file hash. api_url defaults to https://tria.ge/api; configure https://private.tria.ge/api for private accounts. Overview reports preserve verdicts, signatures, extracted configuration and available analysis metadata. This module performs lookups only. It does not submit samples or poll unfinished tasks.
* [Triage Submit](misp_modules/modules/expansion/triage_submit.py) - Module to submit samples to tria.ge
* [TruSTAR Enrich](misp_modules/modules/expansion/trustar_enrich.py) - Module to get enrich indicators with TruSTAR.
* [TweetFeed Lookup](misp_modules/modules/expansion/tweetfeed.py) - Look up an IOC in TweetFeed (tweetfeed.live), the free CC0 feed of URLs, domains, IPs and hashes shared by the infosec community on X/Twitter: who reported it and when, the source tweets and hashtags, cross-feed corroboration, AI-generated context and campaign membership.
* [UnpacMe Lookup](documentation/expansion/unpac_me.md) - Find existing UnpacMe unpacking results for a SHA-256 hash.
* [URL DNS and ASN Expansion](misp_modules/modules/expansion/url_dns.py) - Resolve URL hosts into IPv4/IPv6 IP-port objects and IPv4 ASN objects. [JSON documentation](documentation/expansion/url_dns.json).
* [URL Shortener Resolver](misp_modules/modules/expansion/url_shortener.py) - Resolve known HTTP(S) URL shorteners into a shortened-link object. [JSON documentation](documentation/expansion/url_shortener.json).
* [URLhaus Lookup](misp_modules/modules/expansion/urlhaus.py) - Query of the URLhaus API to get additional information about the input attribute.
* [URLScan Lookup](misp_modules/modules/expansion/urlscan.py) - An expansion module to query urlscan.io.
* [Validin DNS History](misp_modules/modules/expansion/validin.py) - Validin internet dataset expansion. Returns dns-records, web crawls, registration (WHOIS) records, and certificates from Validin's historic internet intelligence dataset.
* [VARIoT db Lookup](misp_modules/modules/expansion/variotdbs.py) - An expansion module to query the VARIoT db API for more information about a vulnerability.
* [VirusTotal v3 Lookup](misp_modules/modules/expansion/virustotal.py) - Enrich observables with the VirusTotal v3 API
* [VirusTotal Sample Downloader](documentation/expansion/virustotal_downloader.md) - Download an existing file from VirusTotal by hash.
* [VirusTotal Public API Lookup](misp_modules/modules/expansion/virustotal_public.py) - Enrich observables with the VirusTotal v3 public API
* [VirusTotal Upload](misp_modules/modules/expansion/virustotal_upload.py) - Module to push malware samples to VirusTotal
* [VMRay Analyzer Lookup](documentation/expansion/vmray_analyzer.md) - Retrieve existing VMRay sample and analysis context by file hash.
* [VMRay Submit](misp_modules/modules/expansion/vmray_submit.py) - Module to submit a sample to VMRay.
* [VMware NSX Defender Enrich](misp_modules/modules/expansion/vmware_nsx.py) - Module to enrich a file or URL with VMware NSX Defender.
* [VulDB](documentation/expansion/vuldb.md) - Expand CVEs, VulDB identifiers and CPEs using the VulDB API.
* [VulnDB Lookup](misp_modules/modules/expansion/vulndb.py) - Module to query VulnDB (Flashpoint).
* [Vulnerability Lookup](misp_modules/modules/expansion/vulnerability_lookup.py) - Expand vulnerabilities and CPEs with Vulnerability Lookup advisories and enrichment
* [Vulners Lookup](misp_modules/modules/expansion/vulners.py) - An expansion hover module to expand information about CVE id using Vulners API.
* [Vysion Enrich](misp_modules/modules/expansion/vysion.py) - Module to enrich the information by making use of the Vysion API.
* [Webarchive (Wayback Machine)](misp_modules/modules/expansion/webarchive.py) - Query the Internet Archive Wayback Machine for an existing web page snapshot. [JSON documentation](documentation/expansion/webarchive.json).
* [Webarchive Save Page Now](documentation/expansion/webarchive_save.md) - Submit the supplied URL to Internet Archive Save Page Now for archiving.
* [Website tracker extract](documentation/expansion/website_tracker_extract.md) - Extract analytics, advertising, affiliate and publisher identifiers from HTML, scripts or HAR.
* [Whisper](misp_modules/modules/expansion/whisper.py) - Enrich IPs, domains, and ASNs with threat intelligence and infrastructure context from the Whisper graph.
* [Whois Lookup](misp_modules/modules/expansion/whois.py) - Module to query a local instance of uwhois (https://github.com/rafiot/uwhoisd). It returns the registration record as raw text; the rdap module answers the same question as a structured whois object, over an unauthenticated protocol and without a local server, and is the better choice wherever RDAP covers the registry.
* [WhoisFreaks Lookup](misp_modules/modules/expansion/whoisfreaks.py) - An expansion module for https://whoisfreaks.com/ that enriches a domain or an IP address. For a domain it queries the WHOIS, DNS and Domain Reputation APIs; for an IP address it queries the IP WHOIS, Geolocation and IP Security APIs. All lookups for a given attribute are executed in parallel.
* [Wikidata Lookup](misp_modules/modules/expansion/wiki.py) - Look up Wikidata labels and aliases and return related annotation objects. [JSON documentation](documentation/expansion/wiki.json).
* [IBM X-Force Exchange Lookup](misp_modules/modules/expansion/xforceexchange.py) - An expansion module for IBM X-Force Exchange.
* [XLXS Enrich](misp_modules/modules/expansion/xlsx_enrich.py) - Module to extract freetext from a .xlsx document.
* [XposedOrNot Lookup](misp_modules/modules/expansion/xposedornot.py) - Query the XposedOrNot API to check whether an email address appears in known data breaches.
* [YARA Rule Generator](misp_modules/modules/expansion/yara_query.py) - The module takes a hash attribute (md5, sha1, sha256, imphash) as input, and is returning a YARA rule from it.
* [YARA Syntax Validator](misp_modules/modules/expansion/yara_syntax_validator.py) - An expansion hover module to perform a syntax check on if yara rules are valid or not.
* [Yeti Lookup](misp_modules/modules/expansion/yeti.py) - Module to process a query on Yeti.
* [Zetalytics Passive DNS](documentation/expansion/zetalytics.md) - Look up passive DNS records in Zetalytics.
* [ZoomEye](documentation/expansion/zoomeye.md) - Search ZoomEye API v2 for IP addresses, domains, hostnames and SHA-1 certificate fingerprints.

### Export Modules
* [BPF Export](documentation/export_mod/bpf_export.md) - Export IDS-marked event and object network attributes as a tcpdump/libpcap capture filter.
* [CEF Export](documentation/export_mod/cef_export.md) - Module to export a MISP event in CEF format.
* [Cisco IOS ACL Export](documentation/export_mod/cisco_acl_export.md) - Export IDS-marked network attributes as Cisco IOS/IOS-XE IPv4 and IPv6 ACL fragments.
* [Cisco ASA ACL Export](documentation/export_mod/cisco_asa_export.md) - Export IDS-marked network attributes as Cisco ASA 9.x IPv4/IPv6 extended ACL entries.
* [Cisco fireSIGHT blockrule Export](misp_modules/modules/export_mod/cisco_firesight_manager_ACL_rule_export.py) - Module to export malicious network activity attributes to Cisco fireSIGHT manager block rules.
* [CSV Export](documentation/export_mod/csv_export.md) - Export event and object attributes of any type as CSV.
* [Microsoft Defender for Endpoint KQL Export](documentation/export_mod/defender_endpoint_export.md) - Validated, table-specific Defender hunting queries with bounded indicator batches
* [Elastic ECS Export](documentation/export_mod/elastic_ecs_export.md) - Export event and object indicators as ECS threat indicators in Elasticsearch Bulk NDJSON.
* [Fortinet FortiOS ACL Export](documentation/export_mod/fortios_export.md) - Export IDS-marked network attributes as FortiOS 7.4+ address objects, services and firewall policies.
* [GeoJSON Export](documentation/export_mod/geojson_export.md) - Export geojson attachments and geolocation objects as GeoJSON.
* [GoAML Export](misp_modules/modules/export_mod/goamlexport.py) - This module is used to export MISP events containing transaction objects into GoAML format.
* [GPX Export](documentation/export_mod/gpx_export.md) - Export gpx attachments and geolocation objects as GPX.
* [Cited Intelligence Briefing Export](documentation/export_mod/intelligence_briefing_export.md) - Export an intelligence briefing with key judgments, evidence citations and analyst review checks.
* [Juniper Junos ACL Export](documentation/export_mod/junos_export.md) - Export IDS-marked network attributes as Junos inet/inet6 stateless firewall filter set commands.
* [KML Export](documentation/export_mod/kml_export.md) - Export geolocations as KML or return a single original KML attachment unchanged.
* [KMZ Export](misp_modules/modules/export_mod/kmz_export.py) - Export original KML/KMZ datasets and geolocations as a KMZ package.
* [Lite Export](misp_modules/modules/export_mod/liteexport.py) - Lite export of a MISP event.
* [EQL Query Export](misp_modules/modules/export_mod/mass_eql_export.py) - Export MISP event in Event Query Language
* [MikroTik RouterOS ACL Export](documentation/export_mod/mikrotik_export.md) - Export IDS-marked network attributes as RouterOS IPv4/IPv6 firewall filter commands.
* [Netfilter nftables Export](documentation/export_mod/netfilter_export.md) - Export IDS-marked event and object network attributes as nftables block or logging rules.
* [Nexthink NXQL Export](misp_modules/modules/export_mod/nexthinkexport.py) - Nexthink NXQL query export module
* [NMEA 0183 Export](documentation/export_mod/nmea_export.md) - Export original NMEA 0183 log attachments in a ZIP archive.
* [OSQuery Export](documentation/export_mod/osqueryexport.md) - Export MISP event and object indicators as an osquery query pack.
* [OWASP CRS Export](documentation/export_mod/owasp_crs_export.md) - Export IDS-marked proxy and HTTP indicators as custom ModSecurity rules alongside OWASP CRS.
* [Palo Alto PAN-OS ACL Export](documentation/export_mod/panos_export.md) - Export IDS-marked network attributes as PAN-OS local security policy set commands.
* [Event to PDF Export](misp_modules/modules/export_mod/pdfexport.py) - Simple export of a MISP event to PDF.
* [OpenBSD PF Export](documentation/export_mod/pf_export.md) - Export IDS-marked event and object network attributes as OpenBSD PF block or logging rules.
* [QRadar Reference Set Export](documentation/export_mod/qradar_reference_set_export.md) - Export deduplicated, typed MISP indicators as QRadar reference-set CSV or JSON values.
* [Sigma Rule Export](documentation/export_mod/sigma_export.md) - Export stored Sigma rules and optionally generate Windows IOC detections.
* [Splunk Lookup Export](documentation/export_mod/splunk_export.md) - Export event and object indicators as a Splunk CSV lookup with CIM field mapping hints.
* [Squid Proxy Export](documentation/export_mod/squid_export.md) - Export IDS-marked event and object attributes as Squid proxy ACLs and deny rules.
* [STIX2 Pattern Export](documentation/export_mod/stix2_pattern_export.md) - Export stored STIX patterns and generate patterns from IDS-marked MISP attributes.
* [Test Export](misp_modules/modules/export_mod/testexport.py) - Skeleton export module.
* [ThreatStream Export](misp_modules/modules/export_mod/threatStream_misp_export.py) - Module to export a structured CSV file for uploading to threatStream.
* [ThreadConnect Export](misp_modules/modules/export_mod/threat_connect_export.py) - Module to export a structured CSV file for uploading to ThreatConnect.
* [Timesketch Observations Export](documentation/export_mod/timesketch_export.md) - Export supported timestamped observations as Timesketch JSONL with MISP and source references.
* [VirusTotal Collections Export](misp_modules/modules/export_mod/virustotal_collections.py) - Creates a VT Collection from an event iocs.
* [VirusTotal Graph Export](documentation/export_mod/vt_graph.md) - This module is used to create a VirusTotal Graph from a MISP event.
* [Wazuh CDB Export](documentation/export_mod/wazuh_cdb_export.md) - Export MISP event and object indicators as a typed Wazuh CDB source list.
* [YARA Rule Export](documentation/export_mod/yara_export.md) - Export stored YARA collections and optionally generate literal IOC content searches.
* [Zeek Intel Export](documentation/export_mod/zeek_intel_export.md) - Export validated MISP event and object indicators as a Zeek Intel Framework feed.

### Import Modules
* [ADTimeline Import](documentation/import_mod/adtimeline_import.md) - Import ADTimeline CSV replication metadata with linked-value times, server-scoped counters and source provenance.
* [ANYRUN Sandbox Import](misp_modules/modules/import_mod/anyrun_sandbox_import.py) - A module designed to retrieve an analysis report from the ANY.RUN Sandbox by its unique ID and extract results (such as verdict, malware tags, and IOCs), converting them into MISP attributes within your event.
* [Atlassian Cloud Audit Logs Import](documentation/import_mod/atlassian_cloud_audit_import.md) - Import Atlassian Administration audit CSV and Organizations Events API JSON.
* [Autopsy and Mobile Forensic Selected Results Import](documentation/import_mod/autopsy_import.md) - Import selected browser, download, communication and application artifacts with forensic provenance.
* [AWS CloudTrail Audit Logs Import](documentation/import_mod/aws_cloudtrail_import.md) - Import AWS CloudTrail JSON or JSON.gz audit records with source provenance.
* [Azure Activity Log Import](documentation/import_mod/azure_activity_log_import.md) - Import Azure Resource Manager Activity Log evidence from local JSON exports.
* [PDNS COF Importer](misp_modules/modules/import_mod/cof2misp.py) - Passive DNS Common Output Format (COF) MISP importer
* [CSV Import](documentation/import_mod/csvimport.md) - Import MISP attributes from base64-encoded UTF-8 CSV contents.
* [Cuckoo Sandbox Import](misp_modules/modules/import_mod/cuckooimport.py) - Module to import Cuckoo and CAPE JSON reports or analysis archives.
* [Darkmoon Import](misp_modules/modules/import_mod/darkmoon_import.py) - Module to import the JSON findings of the Darkmoon autonomous AI penetration testing platform.
* [DMARC Import](misp_modules/modules/import_mod/dmarc_import.py) - Import DMARC aggregate XML reports, including gzip and ZIP files.
* [Email Import](documentation/import_mod/email_import.md) - Email import module for MISP
* [Hayabusa and Chainsaw Findings Import](documentation/import_mod/evtx_findings_import.md) - Import Hayabusa timelines and Chainsaw hunt results as unreviewed detections with linked Windows event context.
* [File and Media Metadata Import](misp_modules/modules/import_mod/file_metadata_import.py) - Import metadata from an uploaded file without an external service.
* [GeoJSON Import](documentation/import_mod/geojson_import.md) - Import GeoJSON datasets with linked geolocation objects for point features.
* [GitHub Enterprise Audit Logs Import](documentation/import_mod/github_enterprise_audit_import.md) - Import saved GitHub organization and enterprise audit logs and Git events.
* [GoAML Import](misp_modules/modules/import_mod/goamlimport.py) - Module to import MISP objects about financial transactions from GoAML files.
* [Google Cloud Audit Logs Import](documentation/import_mod/google_cloud_audit_import.md) - Import native Google Cloud Audit Logs with authorization decisions and IAM binding changes.
* [Google Workspace Audit Logs Import](documentation/import_mod/google_workspace_audit_import.md) - Import saved Google Workspace login, admin, Drive and OAuth token activity.
* [GPX Import](documentation/import_mod/gpx_import.md) - Import GPX files as a gpx object with linked geolocation objects.
* [Import Blueprint](misp_modules/modules/import_mod/import_blueprint.py) - Generic blueprint to be copy-pasted to quickly boostrap creation of import module.
* [Joe Sandbox Import](misp_modules/modules/import_mod/joe_import.py) - A module to import data from a Joe Sandbox analysis json report.
* [KML/KMZ Import](documentation/import_mod/kml_import.md) - Import KML documents and KMZ packages with linked Point and gx:Track geolocations.
* [Kubernetes API Audit Logs Import](documentation/import_mod/kubernetes_audit_import.md) - Import Kubernetes API audit events and group stages by cluster and audit ID.
* [Lastline Import](misp_modules/modules/import_mod/lastline_import.py) - Deprecation notice: this module will be deprecated by December 2021, please use vmware_nsx module.  Module to import and parse reports from Lastline analysis links.
* [Microsoft Identity and Audit Logs Import](documentation/import_mod/microsoft_audit_import.md) - Import Entra sign-in and directory audit logs and Microsoft Purview Unified Audit Log exports.
* [MISP JSON Import](misp_modules/modules/import_mod/mispjson.py) - Module to import MISP JSON format for merging MISP events.
* [NMEA 0183 Import](documentation/import_mod/nmea_import.md) - Import NMEA 0183 receiver logs with linked geolocation observations.
* [OCR Import](misp_modules/modules/import_mod/ocr.py) - Optical Character Recognition (OCR) module for MISP.
* [OCSF Event Import](documentation/import_mod/ocsf_import.md) - Import OCSF events and selected observables from a local JSON or JSON Lines export.
* [Okta System Log Import](documentation/import_mod/okta_system_log_import.md) - Import saved Okta System Log events with typed targets and investigation links.
* [OpenIOC Import](misp_modules/modules/import_mod/openiocimport.py) - Import legacy OpenIOC 1.0 and 1.1 files into MISP.
* [OSQuery Results Import](documentation/import_mod/osquery_import.md) - Import osquery snapshots and differential results with host, query/pack and source-indicator provenance.
* [PCAP Import](documentation/import_mod/pcap_import.md) - Import a PCAP or PCAPNG capture, including reassembled files, emails and network indicators.
* [SOCRadar TAXII Feed Import](misp_modules/modules/import_mod/socradar_taxii_feed.py) - Import threat indicators from SOCRadar TAXII 2.1 feed with MITRE ATT&CK, malware family, confidence, and geo tagging. Leave collection_id empty and type 'list' to discover available collections.
* [Suricata EVE Observations Import](documentation/import_mod/suricata_import.md) - Import selected Suricata EVE findings with timestamps, flow/Community IDs, signatures and capture references.
* [TAXII 2.1 Import](misp_modules/modules/import_mod/taxii21.py) - Import content from a TAXII 2.1 server
* [CSV Test Import](misp_modules/modules/import_mod/testimport.py) - Simple CSV import tool with mapable columns
* [ThreadAnalyzer Sandbox Import](misp_modules/modules/import_mod/threatanalyzer_import.py) - Module to import ThreatAnalyzer archive.zip / analysis.json files.
* [Timesketch and Plaso Findings Import](documentation/import_mod/timesketch_import.md) - Import selected or annotated Timesketch/Plaso entries with source references and annotation context.
* [URL Import](misp_modules/modules/import_mod/url_import.py) - Simple URL import tool with Faup
* [Velociraptor Results Import](documentation/import_mod/velociraptor_import.md) - Import Velociraptor JSON, JSONL or CSV results with linked forensic observations and provenance.
* [VMRay API Import](misp_modules/modules/import_mod/vmray_import.py) - Module to import VMRay (VTI) results.
* [VMRay Summary JSON Import](misp_modules/modules/import_mod/vmray_summary_json_import.py) - Import a VMRay Summary JSON report.
* [Volatility 3 Results Import](documentation/import_mod/volatility3_import.md) - Import Volatility 3 process, network, suspicious-memory and YARA results with memory-image provenance.
* [Portable Web Archive Evidence Import](documentation/import_mod/web_archive_import.md) - Import local WARC and WACZ captures with response metadata and package digest verification.
* [Zeek Observations Import](documentation/import_mod/zeek_import.md) - Import selected Zeek records with timestamps, connection/Community IDs and capture provenance.

### Action Modules
* [Cortex XDR IOC Publish](documentation/action_mod/cortex_xdr_ioc_publish.md) - Upload missing Cortex XDR IOC rules from IDS-marked MISP event and object attributes.
* [Cortex XSOAR Incident Create](documentation/action_mod/cortex_xsoar_incident_create.md) - Create a Cortex XSOAR 8 incident with a MISP event reference and selected-data counts.
* [CrowdStrike IOC Publish](documentation/action_mod/crowdstrike_ioc_publish.md) - Create and renew module-owned Falcon custom IOCs from MISP event and object attributes.
* [Doppel Alert and Takedown](documentation/action_mod/doppel_alert_takedown.md) - Create Doppel alerts or explicitly request takedown for an existing alert.
* [Export to Sentinel or Defender](documentation/action_mod/export_sentinel.md) - Export indicators to Microsoft Sentinel or Microsoft Defender. Requires an existing installation of MISP2Sentinel or MISP2Defender.
* [IRC](documentation/action_mod/irc.md) - Send a message to an IRC channel.
* [Matrix](documentation/action_mod/matrix.md) - Send a message to an unencrypted Matrix room.
* [Mattermost](misp_modules/modules/action_mod/mattermost.py) - Simplistic module to send message to a Mattermost channel.
* [n8n Webhook](documentation/action_mod/n8n_webhook.md) - Send selected MISP event attributes to an authenticated n8n Webhook trigger.
* [Nextcloud talk](misp_modules/modules/action_mod/nextcloud_talk.py) - Simplistic module to send a message to a Nextcloud talk conversation.
* [OSQuery Pack Publish](documentation/action_mod/osquery_pack_publish.md) - Publish a MISP query pack to a configured local osquery pack directory.
* [QRadar Reference Set Publish](documentation/action_mod/qradar_reference_set_publish.md) - Publish typed MISP indicators to an existing QRadar reference set and explicit domain.
* [SentinelOne IOC Publish](documentation/action_mod/sentinelone_ioc_publish.md) - Publish MISP event and object indicators to SentinelOne Threat Intelligence with explicit scope.
* [Shuffle Workflow Execute](documentation/action_mod/shuffle_workflow_execute.md) - Start a Shuffle workflow with selected MISP event and object attributes as its JSON execution argument.
* [Signal](documentation/action_mod/signal.md) - Send a message to Signal recipients or a group through signal-cli-rest-api.
* [Slack](misp_modules/modules/action_mod/slack.py) - Simplistic module to send messages to a Slack channel.
* [Test action](misp_modules/modules/action_mod/testaction.py) - This module is merely a test, always returning true. Triggers on event publishing.
* [Tines Case Create](documentation/action_mod/tines_case_create.md) - Create a Tines Cases v2 case with a MISP event reference and selected-data counts.
* [Torq Case Create](documentation/action_mod/torq_case_create.md) - Create a Torq case with a MISP event reference, provenance tags and selected-data counts.
* [Wazuh CDB Publish](documentation/action_mod/wazuh_cdb_publish.md) - Upload MISP event and object indicators to an explicitly named Wazuh CDB source list.

### Gathering Modules
* [BeaconBeagle Gathering](misp_modules/modules/gathering/beaconbeagle_gathering.py) - Gather Cobalt Strike configurations, beacon hosts and C2 infrastructure into a MISP feed ZIP.
* [Offensive Agency](misp_modules/modules/gathering/offensive_agency.py) - Gather Offensive Agency exposure statistics, inventory matches or the full historical host export.
* [WithAName](misp_modules/modules/gathering/withaname.py) - Gather witha.name DDoSia configurations as a deterministic MISP feed.
