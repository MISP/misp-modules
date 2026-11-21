
#### [ADTimeline Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/adtimeline_import.py)

Import ADTimeline CSV replication metadata with linked-value times, server-scoped counters and source provenance.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/adtimeline_import.py)]

- **features**:
>Imports native semicolon-delimited timeline CSV as unreviewed ad-replication-metadata objects with an exact source attachment. Preserves all columns and raw timestamps. Replication metadata is partial last-change evidence, not actor attribution or confirmed malicious activity. No LDAP access or code execution. Includes its object template. See the usage guide for supported inputs and limits.

- **input**:
>Base64-encoded native timeline_*.csv (UTF-8, or BOM-marked UTF-16).

- **output**:
>Source file and unreviewed AD replication metadata objects.

- **references**:
> - https://github.com/ANSSI-FR/ADTimeline
> - https://github.com/MISP/misp-modules/blob/main/documentation/import_mod/adtimeline_import.md

- **requirements**:
>PyMISP

-----

#### [ANYRUN Sandbox Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/anyrun_sandbox_import.py)

<img src=../logos/anyrun.png height=60>

A module designed to retrieve an analysis report from the ANY.RUN Sandbox by its unique ID and extract results (such as verdict, malware tags, and IOCs), converting them into MISP attributes within your event.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/anyrun_sandbox_import.py)]

- **features**:
>Fetches detailed JSON reports using the ANY.RUN API; parses key elements like verdict, extracted IOCs (hashes, IPs, URLs), malware tags; maps data to MISP attributes and galaxies (e.g., malware family or MITRE ATT&CK Techniques).

- **config**:
>api_key

- **input**:
>ANY.RUN Sandbox analysis UUID.

- **output**:
>Analysis external references, verdict, IOCs (hashes, IPs, URLs), malware tags, MITRE ATT&CK Techniques

- **references**:
>https://any.run

- **requirements**:
> - anyrun-sdk: ANY.RUN API python3 library
> - ANY.RUN Sandbox API-KEY

-----

#### [AWS CloudTrail Audit Logs Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/aws_cloudtrail_import.py)

Import AWS CloudTrail JSON or JSON.gz audit records with source provenance.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/aws_cloudtrail_import.py)]

- **features**:
>Imports native Records envelopes and individual CloudTrail event JSON offline. Maps identity, action, resource, outcome and time to unreviewed MISP objects. Links each record to a SHA-256 source file descriptor. Can attach the exact upload on request. Includes compatible object templates.

- **input**:
>Base64-encoded UTF-8 CloudTrail JSON or gzip-compressed JSON.

- **output**:
>AWS CloudTrail audit event, source file, and linked cloud account, resource and IAM role objects.

- **references**:
> - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html
> - https://github.com/MISP/misp-modules/blob/main/documentation/import_mod/aws_cloudtrail_import.md

- **requirements**:
>PyMISP

-----

#### [Autopsy and Mobile Forensic Selected Results Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/autopsy_import.py)

Import selected browser, download, communication and application artifacts with forensic provenance.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/autopsy_import.py)]

- **features**:
>Accepts Autopsy Export Selected Rows to CSV and a versioned selected-results JSON interchange for mobile parsers. Reuses tsk-web-history/bookmark/cookie/search-query/downloads, tsk-chats and software objects. Preserves selected raw rows, report hashes and case/device/source identifiers in forensic-artifact objects. Explicit row selection omits the full source attachment when rows are excluded. All attributes are unreviewed, non-IDS and non-correlating. Local timestamps need an explicit report offset; paths and URLs are never opened. Commercial native reports require sample fixtures and a named maintainer before an adapter is added. See the [usage guide](https://github.com/MISP/misp-modules/blob/main/documentation/import_mod/autopsy_import.md).

- **config**:
> - format
> - artifact_type
> - rows
> - case_id
> - data_source_id
> - device_id
> - evidence_id
> - report_id
> - tool_version
> - timezone

- **input**:
>Base64 UTF-8 Autopsy selected-row CSV or misp-forensic-selected version 1 JSON.

- **output**:
>Source report, forensic-artifact provenance and linked tsk-* or software observations.

- **references**:
> - https://www.autopsy.com/
> - https://github.com/sleuthkit/autopsy/blob/develop/Core/src/org/sleuthkit/autopsy/directorytree/ExportCSVAction.java

- **requirements**:
>PyMISP

-----

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

Import MISP attributes from base64-encoded UTF-8 CSV contents.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/csvimport.py)]

- **features**:
>In order to parse data from a csv file, a header is required to let the module know which column is matching with known attribute fields / MISP types.
>
>This header either comes from the csv file itself or is part of the configuration of the module and should be filled out in MISP plugin settings, each field separated by COMMAS. Fields that do not match with any type known in MISP or are not MISP attribute fields should be ignored in import, using a space or simply nothing between two separators (example: 'ip-src, , comment, ').
>
>If the csv file already contains a header that does not start by a '#', you should tick the checkbox 'has_header' to avoid importing it and have potential issues. You can also redefine the header even if it is already contained in the file, by following the rules for headers explained earlier. One reason why you would redefine a header is for instance when you want to skip some fields, or some fields are not valid types.
>
>For REST API requests, put the base64-encoded UTF-8 CSV contents in data; file is not a server-side path to read. See the [REST API guide](https://github.com/MISP/misp-modules/blob/main/documentation/import_mod/csvimport.md).

- **input**:
>Base64-encoded UTF-8 CSV contents in the JSON data field.

- **output**:
>MISP Event attributes

- **references**:
> - https://tools.ietf.org/html/rfc4180
> - https://tools.ietf.org/html/rfc7111

- **requirements**:
>PyMISP

-----

#### [Cuckoo Sandbox Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/cuckooimport.py)

<img src=../logos/cuckoo.png height=60>

Module to import Cuckoo and CAPE JSON reports or analysis archives.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/cuckooimport.py)]

- **features**:
>Import a standalone Cuckoo/CAPE JSON report or an analysis archive (ZIP or bzip2 tarball) containing reports/report.json. Without bundled binaries, file metadata is imported without attachments.

- **input**:
>Cuckoo/CAPE JSON report, ZIP archive or bzip2 tarball

- **output**:
>MISP Event attributes

- **references**:
> - https://cuckoosandbox.org/
> - https://github.com/cuckoosandbox/cuckoo
> - https://capev2.readthedocs.io/en/latest/usage/api.html

-----

#### [DMARC Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/dmarc_import.py)

Import DMARC aggregate XML reports, including gzip and ZIP files.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/dmarc_import.py)]

- **features**:
>Upload an aggregate XML report (.xml, .xml.gz, or a ZIP containing exactly one XML file), or paste XML. Creates an annotation object with report metadata, published policy and the original XML attachment. Each aggregate record becomes a linked domain-ip object with its source IP (ip-src), header-from domain, reporting interval and a JSON text attribute preserving counts, disposition, SPF/DKIM results, identifiers and extension fields. Additional identifier and authentication domains are included for correlation. All attributes have to_ids disabled: DMARC observations do not by themselves identify malicious senders. No API key or network access is needed. Input and decompressed XML are limited to 20 MiB each, with at most 10,000 records and 32 XML nesting levels. DTDs, encrypted or multi-file ZIPs, nested archives and forensic/failure reports (RUF/ARF) are not supported. Invalid records reject the entire import.

- **input**:
>DMARC aggregate XML, optionally gzip- or ZIP-compressed

- **output**:
>MISP annotation and domain-ip objects with report context and authentication results

- **references**:
> - https://www.rfc-editor.org/rfc/rfc7489.html
> - https://github.com/MISP/misp-modules/issues/508

- **requirements**:
>PyMISP

-----

#### [Email Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/email_import.py)

Email import module for MISP
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/email_import.py)]

- **features**:
>This module can be used to import e-mail text as well as attachments and urls.
>Configuration parameters are used to unzip attachments, guess zip attachment passwords, extract urls, remove common subject markers, and extract partial inline forwarded emails (extract_forwarded_emails, disabled by default): All switches default to False and accept JSON booleans, 0/1, and case-insensitive yes/no strings. ZIP extraction is limited per request to 100 members, 50 MiB expanded bytes, and 100 password candidates; each member is limited to 20 MiB. Originals are retained and skipped archives are reported.
>Forward extraction supports English From/To/Cc/Bcc/Reply-To/Sent/Date/Subject header blocks in plain text and HTML, including Outlook. Folded header values are supported. Each block needs a sender address, a subject, and a recipient or date. At most 20 partial email objects are linked to the carrier with includes references. Plain text is preferred; HTML is used if no forwards are found in plain text. Reconstructed attributes have to_ids disabled; the original email is retained as evidence. Local or unparseable timestamps are preserved as text in the reconstructed headers. Existing extract_urls and remove_subject_markers settings also apply to forwards. URL objects are shared between the carrier and forwards that contain the same URL. Submitted EML/MSG bytes are preserved separately from converted EML and heuristic forwards. See the [usage guide](https://github.com/MISP/misp-modules/blob/main/documentation/import_mod/email_import.md).

- **config**:
> - unzip_attachments
> - guess_zip_attachment_passwords
> - extract_urls
> - remove_subject_markers
> - extract_forwarded_emails

- **input**:
>E-mail file

- **output**:
>MISP Event attributes

- **references**:
>https://github.com/MISP/mail_to_misp

-----

#### [Hayabusa and Chainsaw Findings Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/evtx_findings_import.py)

Import Hayabusa timelines and Chainsaw hunt results as unreviewed detections with linked Windows event context.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/evtx_findings_import.py)]

- **features**:
>Accepts Hayabusa JSON, JSONL and CSV timelines and Chainsaw hunt JSON/JSONL, including aggregate and cached results. Preserves the original export, rule identity/severity, host, channel, provider, Windows Event ID, record ID, EVTX references and unmapped data. Aggregate event contexts remain separate linked objects. A rule match is unreviewed, not an analyst-confirmed malicious finding. All attributes are non-IDS and non-correlating. Includes compatible object templates; no tool execution, network access or new dependencies. See the [usage guide](https://github.com/MISP/misp-modules/blob/main/documentation/import_mod/evtx_findings_import.md).

- **input**:
>Base64-encoded UTF-8 detection export in data; optional filename and tool/format settings.

- **output**:
>Source file, windows-event-log-detection and windows-event-log-record objects.

- **references**:
> - https://github.com/Yamato-Security/hayabusa/blob/main/config/profiles.yaml
> - https://github.com/WithSecureOpenSource/chainsaw/blob/master/src/cli.rs

- **requirements**:
>PyMISP

-----

#### [File and Media Metadata Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/file_metadata_import.py)

Import metadata from an uploaded file without an external service.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/file_metadata_import.py)]

- **features**:
>Reads documents, images, audio and video with ExifTool. Preserves grouped raw parser values and unverified timestamp and location claims. Correlates selected names, identifiers and software across files. Optional embedded stream scanning and original file attachment. See the [usage guide](https://github.com/MISP/misp-modules/blob/main/documentation/expansion/file_metadata.md).

- **data-source**:
>internal

- **input**:
>An uploaded file or base64 file data.

- **output**:
>A source file object and linked file-metadata object.

- **references**:
> - https://exiftool.org/exiftool_pod.html
> - https://exiftool.org/TagNames/

- **requirements**:
> - PyMISP
> - ExifTool 13.00 or later on PATH
> - Perl Archive::Zip for Office Open XML and OpenDocument metadata

-----

#### [GoAML Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/goamlimport.py)

<img src=../logos/goAML.jpg height=60>

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

<img src=../logos/joesandbox.png height=60>

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

<img src=../logos/lastline.png height=60>

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

#### [Microsoft Identity and Audit Logs Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/microsoft_audit_import.py)

Import Entra sign-in and directory audit logs and Microsoft Purview Unified Audit Log exports.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/microsoft_audit_import.py)]

- **features**:
>Imports Entra sign-in and directory audit JSON and Purview Unified Audit Log JSON or AuditData CSV offline. Maps actions, actors, tenant and session context, results and times to unreviewed MISP objects. Links observations to a SHA-256 source file descriptor and supports attaching the exact upload by request.

- **input**:
>Base64-encoded UTF-8 Entra or Purview JSON, or a Purview CSV containing AuditData.

- **output**:
>Microsoft audit event, source file and optional linked cloud account objects.

- **references**:
> - https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-1.0
> - https://learn.microsoft.com/en-us/graph/api/resources/directoryaudit?view=graph-rest-1.0
> - https://learn.microsoft.com/en-us/purview/audit-log-export-records
> - https://github.com/MISP/misp-modules/blob/main/documentation/import_mod/microsoft_audit_import.md

- **requirements**:
>PyMISP

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

Import legacy OpenIOC 1.0 and 1.1 files into MISP.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/openiocimport.py)]

- **features**:
>A backup import path for legacy .ioc files after removal of the core OpenIOC importer in MISP 3.0. Upload an OpenIOC 1.0 (ioc/definition) or 1.1 (OpenIOC/criteria) XML file through Import from modules, using openiocimport. Common file, network, email, registry, mutex and service fields become MISP attributes; unmapped fields are retained as other attributes. The original XML is attached by default; the existing not save ioc and default tag options are supported. XML DTDs and custom entities are rejected. This extracts observables, rather than evaluating OpenIOC rules: conditions, negation, case sensitivity, item IDs and the AND/OR group path are recorded in attribute comments. All attributes have to_ids=false for review. Correlation is disabled for grouped AND terms, non-exact or negated conditions and unmapped fields, so these are not treated as independent exact indicators. Keep the attachment for the full rule.

- **input**:
>OpenIOC 1.0 or 1.1 XML (.ioc or .xml), including namespace-free legacy files

- **output**:
>MISP Event attributes and the optional original IOC attachment

- **references**:
>https://github.com/mandiant/ioc_writer

- **requirements**:
>PyMISP

-----

#### [Suricata EVE Observations Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/suricata_import.py)

Import selected Suricata EVE findings with timestamps, flow/Community IDs, signatures and capture references.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/suricata_import.py)]

- **features**:
>Accepts native EVE JSON/JSONL, preserving flow/packet/transaction IDs, alert SID/GID/revision/message, severity, action, sensor/capture context and raw protocol records. Reuses network-connection and pcap-metadata with a bundled network-observation template. Event-type/flow-ID selection omits the full attachment when records are excluded. Sensor alerts remain unreviewed observations, not confirmed malicious findings. All attributes are non-IDS and non-correlating. No Suricata execution, capture access or network calls. See the [usage guide](https://github.com/MISP/misp-modules/blob/main/documentation/import_mod/suricata_import.md).

- **input**:
>Base64-encoded UTF-8 EVE JSON/JSONL, optionally selected by event type or flow ID.

- **output**:
>Source file, network-observation, network-connection and optional pcap-metadata objects.

- **references**:
>https://docs.suricata.io/en/latest/output/eve/eve-json-format.html

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

#### [CSV Test Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/testimport.py)

Simple CSV import tool with mapable columns
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/testimport.py)]

- **features**:
>

-----

#### [OSQuery Results Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/osquery_import.py)

<img src=../logos/osquery.png height=60>

Import osquery snapshots and differential results with host, query/pack and source-indicator provenance.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/osquery_import.py)]

- **features**:
>Completes the return path from OSQuery Export and OSQuery Pack Publish. Accepts JSON/JSONL event, batch and snapshot logs, plus explicitly identified ad-hoc snapshots. Preserves host/query/pack identity, execution time, schedule epoch/counter, row action, decorations, raw rows and hunting source references. Empty results remain separate from matches, and removed rows do not delete MISP data. Includes an osquery-result template. No SQL execution, endpoint access or new dependencies. See the [usage guide](https://github.com/MISP/misp-modules/blob/main/documentation/import_mod/osquery_import.md).

- **input**:
>Base64-encoded UTF-8 JSON/JSONL result export; optional collector context and exporter sources map.

- **output**:
>Exact source file and unreviewed osquery-result objects, including explicit empty-result records.

- **references**:
>https://osquery.readthedocs.io/en/stable/deployment/logging/

- **requirements**:
>PyMISP

-----

#### [PCAP Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/pcap_import.py)

Import a PCAP or PCAPNG capture, including reassembled files, emails and network indicators.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/pcap_import.py)]

- **features**:
>Parses captures offline with TShark, without capture privileges or network lookups. Extracts IPv4/IPv6 endpoints, DNS names and answers, HTTP URLs, hosts and user agents, and TLS SNI hostnames. Reassembles HTTP files and SMTP messages; reuses email_import for email objects, attachments and body URLs. Requires complete, unencrypted application traffic for payload extraction; HTTPS yields visible TLS metadata only. Other file-transfer protocols and TLS decryption are not supported. Observed network attributes have to_ids disabled for analyst review. Captures are limited to 50 MiB, exported data and JSON metadata to 100 MiB each. timeout is a positive number of seconds, at most 300 (default 60). Output sizes, including diagnostics, are checked every 50 ms while TShark runs; exceeding a limit kills the process. Bursts can overshoot between checks; these checks are not filesystem quotas. Adds capture hashes and pcap-metadata, capture-scoped TCP/UDP network-connection objects, packet timestamps and observation intervals. Reconstructed content links to streams by exact payload hashes; identical content retains all observed sources. SMTP provenance uses a targeted second pass within the same timeout and combined metadata limit. See the [usage guide](https://github.com/MISP/misp-modules/blob/main/documentation/import_mod/pcap_import.md).

- **config**:
>timeout

- **input**:
>Base64-encoded PCAP or PCAPNG file

- **output**:
>MISP network attributes, pcap-metadata, network-connection, file and email objects with capture/stream provenance

- **references**:
> - https://github.com/MISP/misp-modules/issues/397
> - https://www.wireshark.org/docs/man-pages/tshark.html

- **requirements**:
> - TShark >= 4.0 on the service user's PATH (Debian/Ubuntu: apt install tshark)
> - PyMISP with email and fileobjects extras (included in misp-modules[all])

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

#### [Timesketch and Plaso Findings Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/timesketch_import.py)

Import selected or annotated Timesketch/Plaso entries with source references and annotation context.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/timesketch_import.py)]

- **features**:
>Accepts Timesketch search JSON, JSONL and CSV exports and Plaso psort json_line output. Reuses the timesketch-timeline object, preserving event/sketch/timeline identifiers, annotations, raw entries and microsecond timestamps. Selection can include all supplied entries, explicit selections or annotations. Source annotations remain context, not malicious verdicts. Includes a compatible template and requires no API credentials or tool execution. Complements existing Timesketch playbooks. See the [usage guide](https://github.com/MISP/misp-modules/blob/main/documentation/import_mod/timesketch_import.md).

- **input**:
>Base64-encoded UTF-8 JSON, JSONL or CSV in data; optional filename and selection/source settings.

- **output**:
>Source file and timesketch-timeline objects, with unnormalized times retained and reported.

- **references**:
> - https://timesketch.org/
> - https://plaso.readthedocs.io/

- **requirements**:
>PyMISP

-----

#### [URL Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/url_import.py)

Simple URL import tool with Faup
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/url_import.py)]

- **features**:
>

-----

#### [Velociraptor Results Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/velociraptor_import.py)

Import Velociraptor JSON, JSONL or CSV results with linked forensic observations and provenance.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/velociraptor_import.py)]

- **features**:
>Preserves the original export and every result row, including unmapped fields. Maps Windows.System.Pslist, Windows.System.Services, Windows.Network.NetstatEnriched/Netstat and Windows.Search.FileFinder into process, file, network-socket and windows-service objects. Other artifacts are retained as provenance rows with warnings. All attributes have to_ids disabled. No credentials, network access, VQL execution or additional dependencies are required. Includes the velociraptor-result template for older PyMISP. See the [usage guide](https://github.com/MISP/misp-modules/blob/main/documentation/import_mod/velociraptor_import.md).

- **input**:
>Base64-encoded UTF-8 JSON, JSONL or CSV in data; artifact/context in config or row metadata.

- **output**:
>MISP source file, velociraptor-result and derived observation objects in misp_standard format.

- **references**:
> - https://docs.velociraptor.app/
> - https://github.com/Velocidex/velociraptor/tree/master/artifacts/definitions

- **requirements**:
>PyMISP

-----

#### [VMRay API Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/vmray_import.py)

<img src=../logos/vmray.png height=60>

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

#### [Volatility 3 Results Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/volatility3_import.py)

Import Volatility 3 process, network, suspicious-memory and YARA results with memory-image provenance.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/volatility3_import.py)]

- **features**:
>Accepts native JSON/JSONL from Windows pslist, psscan, pstree, cmdline, netscan, netstat, malfind and vadyarascan, plus layer-wide yarascan. Preserves exact exports, image hashes, plugin/framework versions, offsets, process creation times, renderer hierarchy and unmapped fields. Reuses process and network-socket objects and includes a volatility3-result template. Suspicious memory and YARA matches remain unreviewed. No image access, Volatility execution, network calls or new dependencies. See the [usage guide](https://github.com/MISP/misp-modules/blob/main/documentation/import_mod/volatility3_import.md).

- **input**:
>Base64-encoded native JSON/JSONL in data, with plugin and optional image/version context in config or metadata.

- **output**:
>Source export, optional memory-image file, volatility3-result, process and network-socket objects.

- **references**:
> - https://github.com/volatilityfoundation/volatility3
> - https://volatility3.readthedocs.io/

- **requirements**:
>PyMISP

-----

#### [Portable Web Archive Evidence Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/web_archive_import.py)

Import local WARC and WACZ captures with response metadata and package digest verification.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/web_archive_import.py)]

- **features**:
>Reads WARC 1.0/1.1, gzip-compressed WARC and WACZ. Links HTTP(S) capture records and selected archived response metadata to page-capture objects and the SHA-256 of the original upload. Verifies declared WACZ manifest and resource digests. Original archive attachment is optional. No replay or network access.

- **input**:
>Base64-encoded WARC, WARC.GZ or WACZ file.

- **output**:
>A source file, WARC record metadata and linked page-capture objects.

- **references**:
> - https://specs.webrecorder.net/wacz/1.2.0/
> - https://iipc.github.io/warc-specifications/specifications/warc-format/warc-1.1/
> - https://github.com/MISP/misp-modules/blob/main/documentation/import_mod/web_archive_import.md

- **requirements**:
>PyMISP

-----

#### [Zeek Observations Import](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/zeek_import.py)

Import selected Zeek records with timestamps, connection/Community IDs and capture provenance.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/import_mod/zeek_import.py)]

- **features**:
>Accepts native JSON/JSONL and typed Zeek ASCII logs, including escaped/unset fields. Preserves raw records, stream/sensor context, exact timestamps, UIDs, Community IDs, notices/signatures and capture references. Reuses network-connection and pcap-metadata with a bundled network-observation template. UID selection omits the full source attachment when records are excluded. All observations remain unreviewed and non-IDS. No Zeek execution, capture access or network calls. See the [usage guide](https://github.com/MISP/misp-modules/blob/main/documentation/import_mod/zeek_import.md).

- **input**:
>Base64-encoded UTF-8 Zeek JSON/JSONL or ASCII log; JSON requires explicit stream context.

- **output**:
>Source file, network-observation, network-connection and optional pcap-metadata objects.

- **references**:
>https://docs.zeek.org/en/stable/logs/index.html

- **requirements**:
>PyMISP

-----
