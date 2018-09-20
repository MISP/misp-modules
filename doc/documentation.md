# MISP modules documentation

## Expansion Modules

#### asn_history

Query an ASN description history service (https://github.com/CIRCL/ASN-Description-History.git).
- **requirements**:
>asnhistory

-----

#### circl_passivedns

<img src=logos/passivedns.png height=60>

Module to access CIRCL Passive DNS.

-----

#### circl_passivessl

<img src=logos/passivessl.png height=60>

Modules to access CIRCL Passive SSL.

-----

#### countrycode

Module to expand country codes.

-----

#### crowdstrike_falcon

<img src=logos/crowdstrike.png height=60>

Module to query Crowdstrike Falcon.

-----

#### cve

An expansion hover module to expand information about CVE id.

-----

#### dbl_spamhaus

<img src=logos/spamhaus.jpg height=60>

Module to check Spamhaus DBL for a domain name.

-----

#### dns

A simple DNS expansion service to resolve IP address from MISP attributes.

-----

#### domaintools

<img src=logos/domaintools.png height=60>

DomainTools MISP expansion module.

-----

#### eupi

<img src=logos/eupi.png height=60>

A module to query the Phishing Initiative service (https://phishing-initiative.lu).

-----

#### farsight_passivedns

<img src=logos/farsight.png height=60>

Module to access Farsight DNSDB Passive DNS.

-----

#### geoip_country

Module to query a local copy of Maxminds Geolite database.

-----

#### intelmq_eventdb

Module to access intelmqs eventdb.

-----

#### ipasn

Module to query an IP ASN history service (https://github.com/CIRCL/IP-ASN-history.git).

-----

#### iprep

Module to query IPRep data for IP addresses.

-----

#### onyphe

<img src=logos/onyphe.jpg height=60>

Module to process a query on Onyphe.

-----

#### onyphe_full

<img src=logos/onyphe.jpg height=60>

Module to process a full query on Onyphe.

-----

#### otx

<img src=logos/otx.png height=60>

Module to get information from AlienVault OTX.

-----

#### passivetotal

<img src=logos/passivetotal.png height=60>

The PassiveTotal MISP expansion module brings the datasets derived from Internet scanning directly into your MISP instance. This module supports passive DNS, historic SSL, WHOIS, and host attributes. In order to use the module, you must have a valid PassiveTotal account username and API key. Registration is free and can be done by visiting https://www.passivetotal.org/register

-----

#### rbl

Module to check an IPv4 address against known RBLs.
- **requirements**:
>dnspython3

-----

#### reversedns

Simple Reverse DNS expansion service to resolve reverse DNS from MISP attributes.

-----

#### shodan

<img src=logos/shodan.png height=60>

Module to query on Shodan.

-----

#### sourcecache

Module to cache web pages of analysis reports, OSINT sources. The module returns a link of the cached page.

-----

#### threatcrowd

<img src=logos/threatcrowd.png height=60>

Module to get information from ThreatCrowd.

-----

#### threatminer

<img src=logos/threatminer.png height=60>

Module to get information from ThreatMiner.

-----

#### virustotal

<img src=logos/virustotal.png height=60>

Module to get information from virustotal.

-----

#### vmray_submit

<img src=logos/vmray.png height=60>

Module to submit a sample to VMRay.

-----

#### vulndb

<img src=logos/vulndb.png height=60>

Module to query VulnDB (RiskBasedSecurity.com).

-----

#### whois

Module to query a local instance of uwhois (https://github.com/rafiot/uwhoisd).
- **requirements**:
>uwhois

-----

#### wiki

<img src=logos/wikidata.png height=60>

An expansion hover module to extract information from Wikidata to have additional information about particular term for analysis.

-----

#### xforceexchange

<img src=logos/xforce.png height=60>

An expansion module for IBM X-Force Exchange.

-----

#### yara_syntax_validator

<img src=logos/yara.png height=60>

An expansion hover module to perform a syntax check on if yara rules are valid or not.

-----

## Export Modules

#### cef_export

Module to export a MISP event in CEF format.
- **features**:
>The module takes a MISP event in input, to look every attribute. Each attribute matching with some predefined types is then exported in Common Event Format.
>Thus, there is no particular feature concerning MISP Events since any event can be exported. However, 4 configuration parameters recognized by CEF format are required and should be provided by users before exporting data: the device vendor, product and version, as well as the default severity of data.
- **references**:
>https://community.softwaregrp.com/t5/ArcSight-Connectors/ArcSight-Common-Event-Format-CEF-Guide/ta-p/1589306?attachment-id=65537
- **input**:
>MISP Event attributes
- **output**:
>Common Event Format file

-----

#### goamlexport

<img src=logos/goAML.jpg height=60>

This module is used to export MISP events containing transaction objects into GoAML format.
- **requirements**:
>PyMISP, MISP objects
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
- **references**:
>http://goaml.unodc.org/
- **input**:
>MISP objects (transaction, bank-account, person, legal-entity, geolocation), with references, describing financial transactions and their origin and target.
- **output**:
>GoAML format file, describing financial transactions, with their origin and target (bank accounts, persons or entities).

-----

#### liteexport

Lite export of a MISP event.
- **features**:
>This module is simply producing a json MISP event format file, but exporting only Attributes from the Event. Thus, MISP Events exported with this module should have attributes that are not internal references, otherwise the resulting event would be empty.
- **input**:
>MISP Event attributes
- **output**:
>Lite MISP Event

-----

#### pdfexport

Simple export of a MISP event to PDF.
- **requirements**:
>PyMISP, asciidoctor
- **features**:
>The module takes care of the PDF file building, and work with any MISP Event. Except the requirement of asciidoctor, used to create the file, there is no special feature concerning the Event.
- **references**:
>https://acrobat.adobe.com/us/en/acrobat/about-adobe-pdf.html
- **input**:
>MISP Event
- **output**:
>MISP Event in a PDF file.

-----

#### testexport

Skeleton export module.

-----

#### threatStream_misp_export

<img src=logos/threatstream.png height=60>

Module to export a structured CSV file for uploading to threatStream.
- **requirements**:
>csv
- **features**:
>The module takes a MISP event in input, to look every attribute. Each attribute matching with some predefined types is then exported in a CSV format recognized by ThreatStream.
- **references**:
>https://www.anomali.com/platform/threatstream, https://github.com/threatstream
- **input**:
>MISP Event attributes
- **output**:
>ThreatStream CSV format file

-----

#### threat_connect_export

<img src=logos/threatconnect.png height=60>

Module to export a structured CSV file for uploading to ThreatConnect.
- **requirements**:
>csv
- **features**:
>The module takes a MISP event in input, to look every attribute. Each attribute matching with some predefined types is then exported in a CSV format recognized by ThreatConnect.
>Users should then provide, as module configuration, the source of data they export, because it is required by the output format.
- **references**:
>https://www.threatconnect.com
- **input**:
>MISP Event attributes
- **output**:
>ThreatConnect CSV format file

-----

## Import Modules

#### csvimport

Module to import MISP attributes from a csv file.
- **requirements**:
>PyMISP
- **features**:
>In order to parse data from a csv file, a header is required to let the module know which column is matching with known attribute fields / MISP types.
>This header is part of the configuration of the module and should be filled out in MISP plugin settings, each field separated by COMMAS. Fields that do not match with any type known in MISP can be ignored in import, using a space or simply nothing between two separators (example: 'ip-src, , comment, ').
>There is also one type that is confused and can be either a MISP attribute type or an attribute field: 'comment'. In this case, using 'attrComment' specifies that the attribute field 'comment' should be considered, otherwise it will be considered as the MISP attribute type.
>
>For each MISP attribute type, an attribute is created.
>Attribute fields that are imported are the following: value, type, category, to-ids, distribution, comment, tag.
- **references**:
>https://tools.ietf.org/html/rfc4180, https://tools.ietf.org/html/rfc7111
- **input**:
>CSV format file.
- **output**:
>MISP Event attributes

-----

#### cuckooimport

<img src=logos/cuckoo.png height=60>

Module to import Cuckoo JSON.
- **features**:
>The module simply imports MISP Attributes from a Cuckoo JSON format file. There is thus no special feature to make it work.
- **references**:
>https://cuckoosandbox.org/, https://github.com/cuckoosandbox/cuckoo
- **input**:
>Cuckoo JSON file
- **output**:
>MISP Event attributes

-----

#### email_import

Module to import emails in MISP.
- **features**:
>This module can be used to import e-mail text as well as attachments and urls.
>3 configuration parameters are then used to unzip attachments, guess zip attachment passwords, and extract urls: set each one of them to True or False to process or not the respective corresponding actions.
- **input**:
>E-mail file
- **output**:
>MISP Event attributes

-----

#### goamlimport

<img src=logos/goAML.jpg height=60>

Module to import MISP objects about financial transactions from GoAML files.
- **requirements**:
>PyMISP
- **features**:
>Unlike the GoAML export module, there is here no special feature to import data from GoAML external files, since the module will import MISP Objects with their References on its own, as it is required for the export module to rebuild a valid GoAML document.
- **references**:
>http://goaml.unodc.org/
- **input**:
>GoAML format file, describing financial transactions, with their origin and target (bank accounts, persons or entities).
- **output**:
>MISP objects (transaction, bank-account, person, legal-entity, geolocation), with references, describing financial transactions and their origin and target.

-----

#### mispjson

Module to import MISP JSON format for merging MISP events.
- **features**:
>The module simply imports MISP Attributes from an other MISP Event in order to merge events together. There is thus no special feature to make it work.
- **input**:
>MISP Event
- **output**:
>MISP Event attributes

-----

#### ocr

Optical Character Recognition (OCR) module for MISP.
- **features**:
>The module tries to recognize some text from an image and import the result as a freetext attribute, there is then no special feature asked to users to make it work.
- **input**:
>Image
- **output**:
>freetext MISP attribute

-----

#### openiocimport

Module to import OpenIOC packages.
- **requirements**:
>PyMISP
- **features**:
>The module imports MISP Attributes from OpenIOC packages, there is then no special feature for users to make it work.
- **references**:
>https://www.fireeye.com/blog/threat-research/2013/10/openioc-basics.html
- **input**:
>OpenIOC packages
- **output**:
>MISP Event attributes

-----

#### threatanalyzer_import

Module to import ThreatAnalyzer archive.zip / analysis.json files.
- **features**:
>The module imports MISP Attributes from a ThreatAnalyzer format file. This file can be either ZIP, or JSON format.
>There is by the way no special feature for users to make the module work.
- **references**:
>https://www.threattrack.com/malware-analysis.aspx
- **input**:
>ThreatAnalyzer format file
- **output**:
>MISP Event attributes

-----

#### vmray_import

<img src=logos/vmray.png height=60>

Module to import VMRay (VTI) results.
- **requirements**:
>vmray_rest_api
- **features**:
>The module imports MISP Attributes from VMRay format, using the VMRay api.
>Users should then provide as the module configuration the API Key as well as the server url in order to fetch their data to import.
- **references**:
>https://www.vmray.com/
- **input**:
>VMRay format
- **output**:
>MISP Event attributes

-----
