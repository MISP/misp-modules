
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

<img src=../logos/cuckoo.png height=60>

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
