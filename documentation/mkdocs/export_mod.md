
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

<img src=../logos/cisco.png height=60>

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

<img src=../logos/defender_endpoint.png height=60>

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

<img src=../logos/goAML.jpg height=60>

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

<img src=../logos/eql.png height=60>

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

<img src=../logos/nexthink.svg height=60>

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

<img src=../logos/osquery.png height=60>

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

<img src=../logos/threatstream.png height=60>

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

<img src=../logos/threatconnect.png height=60>

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

<img src=../logos/virustotal.png height=60>

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

<img src=../logos/virustotal.png height=60>

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

<img src=../logos/yara.png height=60>

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
