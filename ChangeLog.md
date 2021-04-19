# Changelog


## v2.4.141 (2021-04-19)

### Changes

* [tests] LiveCI set for RBL tests (network connectivity issues in the CI) [Alexandre Dulaunoy]

* [rbl] Added a timeout parameter to change the resolver timeout & lifetime if needed. [chrisr3d]

* [rbl] Small changes on the rbl list and the results handling. [chrisr3d]

* [test] skip some tests if running in the CI (API limitation or specific host issues) [Alexandre Dulaunoy]

* [tests] historical records in threatcrowd. [Alexandre Dulaunoy]

* [test] fixing IP addresses. [Alexandre Dulaunoy]

* [passivetotal] new test IP address. [Alexandre Dulaunoy]

* [farsight] make PEP happy. [Alexandre Dulaunoy]

* [requirements] openpyxl added. [Alexandre Dulaunoy]

* [travis] missing dep. [Alexandre Dulaunoy]

* [test expansion] IPv4 address of CIRCL updated. [Alexandre Dulaunoy]

* [coverage] install. [Alexandre Dulaunoy]

* [pipenv] removed. [Alexandre Dulaunoy]

* [travis] get rid of pipenv. [Alexandre Dulaunoy]

* [Pipfile.lock] updated. [Alexandre Dulaunoy]

* [doc] fix index of mkdocs. [Alexandre Dulaunoy]

* [documentation] updated. [Alexandre Dulaunoy]

* [farsight_passivedns] Making first_time and last_time results human readable. [chrisr3d]

  - We get the datetime format instead of the raw
    timestamp

* Bump deps. [Raphaël Vinot]

* [farsight_passivedns] Making first_time and last_time results human readable. [chrisr3d]

  - We get the datetime format instead of the raw
    timestamp

* [farsight_passivedns] Added input types for more flex queries. [chrisr3d]

  - Standard types still supported as before
    - Name or ip lookup, with optional flex queries
  - New attribute types added will only send flex
    queries to the DNSDB API

* [doc] fix #460 - rh install. [Alexandre Dulaunoy]

* [requirements] fix 463. [Alexandre Dulaunoy]

### Fix

* [tests] Fixed btc_steroids test assertion. [chrisr3d]

* [ocr_enrich] Making Pep8 happy. [chrisr3d]

* [tests] Fixed variable names that have been changed with the latest commit. [chrisr3d]

* [ocr_enrich] Fixed tesseract input format. [chrisr3d]

  - It looks like the `image_to_string` method now
    assumes RGB format and the `imdecode` method
    seems to give BGR format, so we convert the
    image array before

* [tests] Fixed tests for some modules waiting for standard MISP Attribute format as input. [chrisr3d]

* [tests] Fixed hibp test which requires an API key. [chrisr3d]

* [hibp] Fixed config handling to avoir KeyError exceptions. [chrisr3d]

* [test] dns module. [Alexandre Dulaunoy]

* [main] Disable duplicate JSON decoding. [Jakub Onderka]

* [cve_advanced] Some CVEs are not in CWE format but in NVD-CWE-Other. [Alexandre Dulaunoy]

* [farsight_passivedns] Fixed lookup_rdata_name results desclaration. [chrisr3d]

  - Getting generator as a list as it is already the
    case for all the other results, so it avoids
    issues to read the results by accidently looping
    through the generator before it is actually
    needed, which would lose the content of the
    generator
  - Also removed print that was accidently introduced
    with the last commit

* [farsight_passivedns] Excluding last_seen value for now, in order to get the available results. [chrisr3d]

  - With last_seen set we can easily get results
    included in a certain time frame (between first
    seen and last seen), but we do not get the
    latest results. In order to get those ones, we
    skip filtering on the time_last_before value

* [farsight_passivedns] Fixed lookup_rdata_name results desclaration. [chrisr3d]

  - Getting generator as a list as it is already the
    case for all the other results, so it avoids
    issues to read the results by accidently looping
    through the generator before it is actually
    needed, which would lose the content of the
    generator
  - Also removed print that was accidently introduced
    with the last commit

* Making pep8 happy. [chrisr3d]

* [farsight_passivedns] Fixed queries to the API. [chrisr3d]

  - Since flex queries input may be email addresses,
    we nake sure we replace '@' by '.' in the flex
    queries input.
  - We also run the flex queries with the input as
    is first, before runnning them as second time
    with '.' characters escaped: '\\.'

* Google.py module. [Jürgen Löhel]

  The search result does not include always 3 elements. It's better to
  enumerate here.
  The googleapi fails sometimes. Retry it 3 times.

* Google.py module. [Jürgen Löhel]

  Corrects import for gh.com/abenassi/Google-Search-API.

* Consider mail body as UTF-8 encoded. [Jakub Onderka]

### Other

* Merge branch 'main' of github.com:MISP/misp-modules into main. [Alexandre Dulaunoy]

* Fix; [tests] Changes on assertion statements that should fix the passivetotal, rbl & shodan tests. [chrisr3d]

* Merge branch 'main' of github.com:MISP/misp-modules into main. [chrisr3d]

* Merge branch 'main' of github.com:MISP/misp-modules into main. [Alexandre Dulaunoy]

* Merge pull request #435 from JakubOnderka/remove-duplicate-decoding. [Alexandre Dulaunoy]

  fix: [main] Remove duplicate JSON decoding

* Add: [farsight_passivedns] Adding first_seen & last_seen (when available) in passivedns objects. [chrisr3d]

  - The object_relation `time_first` is added as the
    `first_seen` value of the object
  - Same with `time_last` -> `last_seen`

* Merge branch 'main' of github.com:MISP/misp-modules into new_features. [chrisr3d]

* Merge branch 'main' of github.com:MISP/misp-modules into new_features. [chrisr3d]

* Merge branch 'main' of github.com:MISP/misp-modules into new_features. [chrisr3d]

* Merge pull request #484 from GreyNoise-Intelligence/main. [Alexandre Dulaunoy]

  Update to GreyNoise expansion module

* Update community api to released ver. [Brad Chiappetta]

* Fix ver info. [Brad Chiappetta]

* Updates for greynoise community api. [Brad Chiappetta]

* Merge pull request #485 from jgwilson42/patch-1. [Alexandre Dulaunoy]

  Update README.md

* Update README.md. [James Wilson]

  Ensure that the clone of misp-modules is owned by www-data

* Merge pull request #482 from MISP/new_features. [Alexandre Dulaunoy]

  Farsight_passivedns module updated with new input types compatible with flex queries

* Add: [farsight_passivedns] New lookup argument based on the first_seen & last_seen fields. [chrisr3d]

* Merge branch 'main' of github.com:MISP/misp-modules into new_features. [chrisr3d]

* Merge branch 'main' of github.com:MISP/misp-modules into new_features. [chrisr3d]

* Merge pull request #481 from cocaman/main. [Alexandre Dulaunoy]

  Adding ThreatFox enrichment module

* Adding additional tags. [Corsin Camichel]

* First version of ThreatFox enrichment module. [Corsin Camichel]

* Merge pull request #480 from cocaman/patch-1. [Alexandre Dulaunoy]

  updating "hibp" for API version 3

* Updating "hibp" for API version 3. [Corsin Camichel]

* Merge pull request #477 from jloehel/fix/google-module. [Alexandre Dulaunoy]

  Fix/google module

* Merge pull request #476 from digihash/patch-1. [Alexandre Dulaunoy]

  Update README.md

* Update README.md. [Kevin Holvoet]

  Added fix based on https://github.com/MISP/MISP/issues/4045

* Merge pull request #475 from adammchugh/patch-3. [Alexandre Dulaunoy]

  Fixed the censys version

* Fixed the censys version. [adammchugh]

  Unsure how I managed to get the version so wrong, but I have updated it to the current version and confirmed as working.

* Merge pull request #474 from JakubOnderka/patch-4. [Alexandre Dulaunoy]

  fix: Consider mail body as UTF-8 encoded

* Merge pull request #473 from adammchugh/patch-2. [Alexandre Dulaunoy]

  Change to pandas version requirement to address pip install failure

* Included missing dependencies for censys and pyfaup. [adammchugh]

  Added censys dependency
  Added pyfaup dependency

* Change to pandas version requirement to address pip install failure. [adammchugh]

  Updated pandas version to 1.1.5 to allow pip install as defined at https://github.com/MISP/misp-modules to complete successfully.

* Merge pull request #470 from adammchugh/patch-1. [Alexandre Dulaunoy]

  Update assemblyline_submit.py - Add verify SSL option

* Update assemblyline_submit.py. [adammchugh]

* Update assemblyline_query.py. [adammchugh]

* Update assemblyline_submit.py. [adammchugh]

* Merge branch 'main' of github.com:MISP/misp-modules into main. [Alexandre Dulaunoy]

* Update README long hyphen is not standard ASCII hyphen. [Alexandre Dulaunoy]

  Fix #464


## v2.4.137 (2021-01-25)

### Changes

* Bump deps. [Raphaël Vinot]

* Bump requirements. [Raphaël Vinot]

* [pipenv] Enable email extras for PyMISP. [Jakub Onderka]

### Fix

* Bump PyMISP dep to latest. [Raphaël Vinot]

* Use PyMISP from PyPi. [Raphaël Vinot]

* Use pymisp from pypi. [Raphaël Vinot]

* [pipenv] Missing clamd. [Jakub Onderka]

### Other

* Merge pull request #466 from NoDataFound/main. [Alexandre Dulaunoy]

  Corrected VMray rest API import

* Corrected VMray rest API import. [Cory Kennedy]

  When loading misp-modules,  the VMray module ```modules/expansion/vmray_submit.py ``` incorrectly imports the library. VMray's documentation and examples here: https://pypi.org/project/vmray-rest-api/#history also reflect this change as the correct import.

* Merge pull request #457 from trustar/main. [Alexandre Dulaunoy]

  added more explicit error messages for indicators that return no enri…

* Added more explicit error messages for indicators that return no enrichment data. [Jesse Hedden]

* Merge pull request #452 from kuselfu/main. [Alexandre Dulaunoy]

  update vmray_import, add vmray_summary_json_import

* Fix imports and unused variables. [Jens Thom]

* Resolve merge conflict. [Jens Thom]

* Merge remote-tracking branch 'upstream/main' into main. [Jens Thom]

* Merge pull request #451 from JakubOnderka/versions-update. [Alexandre Dulaunoy]

  fix: [pipenv] Missing clamd

* Merge pull request #450 from JakubOnderka/versions-update. [Alexandre Dulaunoy]

  chg: [pipenv] Enable email extras for PyMISP

* Merge pull request #448 from HacknowledgeCH/export_defender_endpoint. [Alexandre Dulaunoy]

  Export defender endpoint

* Fixed error reported by LGTM analysis. [milkmix]

* Added documentation. [milkmix]

* Added missing quotes. [milkmix]

* Added URL support. [milkmix]

* Typo in python src name. [milkmix]

* Initial work on Defender for Endpoint export module. [milkmix]

* * add parser for report version v1 and v2 * add summary JSON import module. [Jens Thom]


## v2.4.134 (2020-11-18)

### New

* [expansion] Added html_to_markdown module. [mokaddem]

  It fetches the HTML from the provided URL, performs a bit of DOM
  clean-up then convert it into markdown

* [clamav] Module for malware scan by ClamAV. [Jakub Onderka]

* [passivedns, passivessl] Add support for ip-src|port and ip-dst|port. [Jakub Onderka]

* Censys Expansion module. [Golbark]

* Expansion module to query MALWAREbazaar API with some hash attribute. [chrisr3d]

### Changes

* [pipenv] Updated lock Pipfile again. [chrisr3d]

* [pipenv] Updated lock Pipfile. [chrisr3d]

* Added socialscan library in Pipfile and updated the lock file. [chrisr3d]

* [documentation] Cleaner documentation directories & auto-generation. [chrisr3d]

  Including:
  - A move of the previous `doc` and `docs` directories to `documentation`
    - `documentation` is now the default directory
    - The documentation previously under `doc` is now in `documentation/website`
    - The mkdocs previously under `docs` is now in `documentation/mkdocs`
  - All single JSON documentation files have been JQed
  - Some small improvements to list fields displaying

* [pipenv] Updated Pipfile. [chrisr3d]

* [documentation] Updated the farsight-passivedns documentation. [chrisr3d]

* [cpe] Added default limit to the results. [chrisr3d]

  - Results returned by CVE-search are sorted by
    cvss score and limited in number to avoid
    potential massive amount of data retuned back
    to MISP.
  - Users can overwrite the default limit with the
    configuration already present as optional, and
    can also set the limit to 0 to get the full list
    of results

* [farsight_passivedns] Now using the dnsdb2 python library. [chrisr3d]

  - Also updated the results parsing to check in
    each returned result for every field if they are
    included, to avoid key errors if any field is
    missing

* [cpe] Support of the new CVE-Search API. [chrisr3d]

* [doc] Updated the farsight_passivedns module documentation. [chrisr3d]

* [farsight_passivedns] More context added to the results. [chrisr3d]

  - References between the passive-dns objects and
    the initial attribute
  - Comment on object attributes mentioning whether
    the results come from an rrset or an rdata
    lookup

* [farsight_passivedns] Rework of the module to return MISP objects. [chrisr3d]

  - All the results are parsed as passive-dns MISP
    objects
  - More love to give to the parsing to add
    references between the passive-dns objects and
    the input attribute, depending on the type of
    the query (rrset or rdata), or the rrtype
    (to be determined)

* [cpe] Changed CVE-Search API default url. [chrisr3d]

* [clamav] Add reference to original attribute. [Jakub Onderka]

* [clamav] TCP port connection must be an integer. [Alexandre Dulaunoy]

* Bump deps. [Raphaël Vinot]

* Updated expansion modules documentation. [chrisr3d]

  - Added documentation for the missing modules
  - Renamed some of the documentation files to match
    with the module names and avoid issues within
    the documentation file (README.md) with the link
    of the miss-spelled module names

* Updated the bgpranking expansion module test. [chrisr3d]

* Updated documentation for the recently updated bgpranking module. [chrisr3d]

* Updated the bgpranking expansion module to return MISP objects. [chrisr3d]

  - The module no longer returns freetext, since the
    result returned to the freetext import as text
    only allowed MISP to parse the same AS number as
    the input attribute.
  - The new result returned with the updated module
    is an asn object describing more precisely the
    AS number, and its ranking for a given day

* Turned the Shodan expansion module into a misp_standard format module. [chrisr3d]

  - As expected with the misp_standard modules, the
    input is a full attribute and the module is able
    to return attributes and objects
  - There was a lot of data that was parsed as regkey
    attributes by the freetext import, the module now
    parses properly the different field of the result
    of the query returned by Shodan

* Updated documentation about the greynoise module. [chrisr3d]

* Updated Greynoise tests following the latest changes on the expansion module. [chrisr3d]

* Making use of the Greynoise v2 API. [chrisr3d]

* Bump deps. [Raphaël Vinot]

* [doc] Added details about faup. [Steve Clement]

* [doc] in case btc expansion fails, give another hint at why it fails. [Steve Clement]

* [travis] Added gtcaca and liblua to faup. [Steve Clement]

* [travis] Added py3.8. [Steve Clement]

* Bump dependencies. [Raphaël Vinot]

  Should fix https://github.com/MISP/MISP/issues/5739

* Quick ransomdncoin test just to make sure the module loads. [chrisr3d]

  - I do not have any api key right now, so the test
    should just reach the error

* Catching missing config issue. [chrisr3d]

### Fix

* [pipenv] Removed duplicated dnsdb2 entry that I missed while merging conflict. [chrisr3d]

* Removed debugging print command. [chrisr3d]

* [tests] Less specific assertion for the rbl module test. [chrisr3d]

* [farsight_passivedns] Fixed pep8 backslash issue. [chrisr3d]

* [farsight_passivedns] Fixed issue with variable name. [chrisr3d]

* [documentation] Added missing cpe module documentation. [chrisr3d]

* [cpe] Fixed typo in vulnerable-configuration object relation fields. [chrisr3d]

* [farsight_passivedns] Fixed typo in the lookup fields. [chrisr3d]

* [farsight_passivedns] Uncommented mandatory field that was commented for tests. [chrisr3d]

* [tests] Small fixes on the expansion tests. [chrisr3d]

* [dnsdb] Avoiding AttributeError with the sys library, probably depending on the python version. [chrisr3d]

* [documentation] Updated links to the scripts, with the default branch no longer being master, but main. [chrisr3d]

* Typo. [chrisr3d]

* Updated Pipfile. [chrisr3d]

* [cpe] Typos and variable name issues fixed + Making the module available in MISP. [chrisr3d]

* [cve-advanced] Using the cpe and weakness attribute types. [chrisr3d]

* [cve_advanced] Avoiding potential MISP object references issues. [chrisr3d]

  - Adding objects as dictionaries in an event may
    cause issues in some cases. It is better to pass
    the MISP object as is, as it is already a valid
    object since the MISPObject class is used

* [virustotal_public] Resolve key error when user enrich hostname. [chrisr3d]

  - Same as #424

* [virustotal] Resolve key error when user enrich hostname. [Jakub Onderka]

* Typo in EMailObject. [Raphaël Vinot]

  Fix #427

* Making pep8 happy. [chrisr3d]

* Fixed pep8. [chrisr3d]

* Fixed pep8 + some copy paste issues introduced with the latest commits. [chrisr3d]

* Avoid issues with the attribute value field name. [chrisr3d]

  - The module setup allows 'value1' as attribute
    value field name, but we want to make sure that
    users passing standard misp format with 'value'
    instead, will not have issues, as well as
    keeping the current setup

* [virustotal] Subdomains is optional in VT response. [Jakub Onderka]

* Fixed list of sigma backends. [chrisr3d]

* Fixed validators dependency issues. [chrisr3d]

  - Possible rollback if we get issues with virustotal

* Removed multiple spaces to comply with pep8. [chrisr3d]

* Making pep8 happy. [chrisr3d]

* Removed trustar_import module name in init to avoid validation issues. [chrisr3d]

  (until it is submitted via PR?)

* [circl_passivessl] Return proper error for IPv6 addresses. [Jakub Onderka]

* [circl_passivessl] Return not found error. [Jakub Onderka]

  If passivessl returns empty response, return Not found error instead of error in log

* [circl_passivedns] Return not found error. [Jakub Onderka]

  If passivedns returns empty response, return Not found error instead of error in log

* [pep] Comply to PEP E261. [Steve Clement]

* [travis] gtcaca has no build directory. [Steve Clement]

* [pip] pyfaup required. [Steve Clement]

* [doc] corrected filenames for 2 docs. [Christophe Vandeplas]

* Making pep8 happy. [chrisr3d]

* Catching errors in the reponse of the query to URLhaus. [chrisr3d]

* Making pep8 happy with indentation. [chrisr3d]

* Making pep8 happy. [chrisr3d]

* Removed unused import. [chrisr3d]

* Making pep8 happy. [chrisr3d]

* Making the module config available so the module works. [chrisr3d]

* [VT] Disable SHA512 query for VT. [Jakub Onderka]

### Other

* Merge branch 'main' of github.com:MISP/misp-modules into chrisr3d_patch. [chrisr3d]

* Merge pull request #429 from MISP/new_module. [Christian Studer]

  New module using socialscan to check the availability of an email address or username on some online platforms

* Merge branch 'main' of github.com:MISP/misp-modules into new_module. [chrisr3d]

* Merge branch 'main' of github.com:MISP/misp-modules into new_module. [chrisr3d]

* Add: Added documentation for the socialscan new module. [chrisr3d]

  - Also quick fix of the message for an invalid
    result or response concerning the queried email
    address or username

* Merge branch 'main' of github.com:MISP/misp-modules into new_module. [chrisr3d]

* Add: New module using socialscan library to check email addresses and usernames linked to accounts on online platforms. [chrisr3d]

* Merge branch 'main' of github.com:MISP/misp-modules into chrisr3d_patch. [chrisr3d]

* Merge branch 'main' of github.com:MISP/misp-modules into chrisr3d_patch. [chrisr3d]

* Merge pull request #445 from chrisr3d/main. [Christian Studer]

  Added missing cpe module documentation

* Merge branch 'main' of github.com:MISP/misp-modules into main. [chrisr3d]

* Add: [farsight-passivedns] Optional feature to submit flex queries. [chrisr3d]

  - The rrset and rdata queries remain the same but
    with the parameter `flex_queries`, users can
    also get the results of the flex rrnames & flex
    rdata regex queries about their domain, hostname
    or ip address
  - Results can thus include passive-dns objects
    containing the `raw_rdata` object_relation added
    with 0a3e948

* Merge branch 'main' of github.com:MISP/misp-modules into chrisr3d_patch. [chrisr3d]

* Merge branch 'main' of github.com:MISP/misp-modules into chrisr3d_patch. [chrisr3d]

* Merge branch 'chrisr3d_patch' of github.com:MISP/misp-modules into main. [chrisr3d]

* Merge branch 'main' of github.com:MISP/misp-modules into main. [chrisr3d]

* Merge branch 'main' of github.com:MISP/misp-modules into chrisr3d_patch. [chrisr3d]

* Merge pull request #443 from trustar/main. [Alexandre Dulaunoy]

  fixed typo causing firstSeen and lastSeen to not be pulled from enric…

* Fixed typo causing firstSeen and lastSeen to not be pulled from enrichment data. [Jesse Hedden]

* Merge pull request #440 from MISP/chrisr3d_patch. [Alexandre Dulaunoy]

  Farsight passivedns module update

* Merge pull request #437 from chrisr3d/main. [Alexandre Dulaunoy]

  New expansion module to get the vulnerabilities related to a CPE

* Merge branch 'main' of github.com:MISP/misp-modules into main. [chrisr3d]

* Merge branch 'main' of github.com:MISP/misp-modules into main. [chrisr3d]

* Merge pull request #436 from MISP/new-html-to-markdown. [Christian Studer]

  new: [expansion] Added html_to_markdown module

* Add: Documentation for the html_to_markdown expansion module. [chrisr3d]

* Add: Added documentation for the cpe module. [chrisr3d]

* Add: First shot of an expansio module to query cve-search with a cpe to get the related vulnerabilities. [chrisr3d]

* Merge pull request #432 from JakubOnderka/clamav. [Alexandre Dulaunoy]

  chg: [clamav] Add reference to original attribute

* Merge pull request #431 from JakubOnderka/clamav. [Alexandre Dulaunoy]

  new: [clamav] Module for malware scan by ClamAV

* Merge branch 'main' of github.com:MISP/misp-modules into main. [Raphaël Vinot]

* Merge pull request #424 from JakubOnderka/vt-subdomains-fix. [Christian Studer]

  fix: [virustotal] Resolve key error when user enrich hostname

* Merge pull request #426 from hildenjohannes/main. [Alexandre Dulaunoy]

  Recorded Future module: Add proxy support and User-Agent header

* Add proxy support and User-Agent header. [johannesh]

* Merge pull request #425 from elhoim/elhoim-patch-1. [Alexandre Dulaunoy]

  Disable correlation for detection-ratio attribute in virustotal.py

* Disable correlation for detection-ratio in virustotal.py. [David André]

* Merge pull request #422 from trustar/feat/EN-5047/MISP-manual-update. [Alexandre Dulaunoy]

  Feat/en 5047/misp manual update

* Merge branch 'main' into feat/EN-5047/MISP-manual-update. [Jesse Hedden]

* Merge pull request #420 from hildenjohannes/main. [Alexandre Dulaunoy]

  Fix typo error introduced in commit: 3b7a5c4dc2541f3b07baee69a7e8b969…

* Fix typo error introduced in commit: 3b7a5c4dc2541f3b07baee69a7e8b9694a1627fc. [johannesh]

* Merge pull request #417 from trustar/feat/EN-4664/trustar-misp. [Alexandre Dulaunoy]

  Feat/en 4664/trustar misp

* Added description to readme. [Jesse Hedden]

* Merge branch 'master' of github.com:trustar/misp-modules into feat/EN-4664/trustar-misp. [Jesse Hedden]

* Removed obsoleted module name. [Jesse Hedden]

* Merge branch 'main' of github.com:MISP/misp-modules into main. [chrisr3d]

* Merge pull request #416 from hildenjohannes/main. [Alexandre Dulaunoy]

  Add Recorded Future module documentation

* Improve wording. [johannesh]

* Add Recorded Future module documentation. [johannesh]

* Add: Specific error message for misp_standard format expansion modules. [chrisr3d]

  - Checking if the input format is respected and
    displaying an error message if it is not

* Merge pull request #415 from hildenjohannes/main. [Alexandre Dulaunoy]

  Add Recorded Future expansion module

* Add Recorded Future expansion module. [johannesh]

* Added comments. [Jesse Hedden]

* Added comments. [Jesse Hedden]

* Added comments. [Jesse Hedden]

* Added error checking. [Jesse Hedden]

* Updating to include metadata and alter type of trustar link generated. [Jesse Hedden]

* Merge pull request #1 from trustar/feat/EN-4664/trustar-misp. [Jesse Hedden]

  Feat/en 4664/trustar misp

* Merge branch 'main' of github.com:MISP/misp-modules into main. [chrisr3d]

* Merge pull request #411 from JakubOnderka/vt-subdomains-fix. [Alexandre Dulaunoy]

  fix: [virustotal] Subdomains is optional in VT response

* Merge remote-tracking branch 'origin' into main. [chrisr3d]

* Add: Trustar python library added to Pipfile. [chrisr3d]

* Merge branch 'trustar-feat/EN-4664/trustar-misp' [chrisr3d]

* Merge branch 'feat/EN-4664/trustar-misp' of https://github.com/trustar/misp-modules into trustar-feat/EN-4664/trustar-misp. [chrisr3d]

* Removed obsolete file. [Jesse Hedden]

* Corrected variable name. [Jesse Hedden]

* Fixed indent. [Jesse Hedden]

* Fixed incorrect attribute name. [Jesse Hedden]

* Fixed metatag; convert summaries generator to list for error handling. [Jesse Hedden]

* Added strip to remove potential whitespace. [Jesse Hedden]

* Removed extra parameter. [Jesse Hedden]

* Added try/except for TruSTAR API errors and additional comments. [Jesse Hedden]

* Added comments and increased page size to max for get_indicator_summaries. [Jesse Hedden]

* Uploaded TruSTAR logo. [Jesse Hedden]

* Updated client metatag and version. [Jesse Hedden]

* Added module documentation. [Jesse Hedden]

* Added client metatag to trustar client. [Jesse Hedden]

* Ready for code review. [Jesse Hedden]

* WIP: initial push. [Jesse Hedden]

* Initial commit. not a working product. need to create a class to manage the MISP event and TruStar client. [Jesse Hedden]

* Merge pull request #381 from MISP/new_module. [Christian Studer]

  New module for MALWAREbazaar

* Merge branch 'main' of github.com:MISP/misp-modules into new_module. [chrisr3d]

* Merge pull request #407 from JakubOnderka/patch-3. [Alexandre Dulaunoy]

  fix: [circl_passivessl] Return proper error for IPv6 addresses

* Merge pull request #406 from JakubOnderka/ip-port. [Alexandre Dulaunoy]

  new: [passivedns, passivessl] Add support for ip-src|port and ip-dst|port

* Merge pull request #405 from JakubOnderka/patch-2. [Alexandre Dulaunoy]

  fix: [circl_passivedns] Return not found error

* Merge pull request #402 from MISP/dependabot/pip/httplib2-0.18.0. [Alexandre Dulaunoy]

  build(deps): bump httplib2 from 0.17.0 to 0.18.0

* Build(deps): bump httplib2 from 0.17.0 to 0.18.0. [dependabot[bot]]

  Bumps [httplib2](https://github.com/httplib2/httplib2) from 0.17.0 to 0.18.0.
  - [Release notes](https://github.com/httplib2/httplib2/releases)
  - [Changelog](https://github.com/httplib2/httplib2/blob/master/CHANGELOG)
  - [Commits](https://github.com/httplib2/httplib2/compare/v0.17.0...v0.18.0)

* Merge branch 'master' of github.com:MISP/misp-modules into new_module. [chrisr3d]

* Merge pull request #395 from SteveClement/master. [Steve Clement]

  chg: [deps] pyfaup seems to be required but not installed

* Merge pull request #393 from vmray-labs/update-vmray-module. [Alexandre Dulaunoy]

  Update vmray_submit module

* Update vmray_submit. [Matthias Meidinger]

  The submit module hat some smaller issues with the reanalyze flag.
  The source for the enrichment object has been changed and the robustness
  of user supplied config parsing improved.

* Merge pull request #388 from Golbark/censys_expansion. [Christophe Vandeplas]

  new: usr: Censys Expansion module

* Fix variable issue in the loop. [Golbark]

* Adding support for more input types, including multi-types. [Golbark]

* Add: Added documentation for the latest new modules. [chrisr3d]

* Merge branch 'master' of github.com:MISP/misp-modules into new_module. [chrisr3d]

* Merge branch 'master' of github.com:MISP/misp-modules. [chrisr3d]

* Merge pull request #380 from JakubOnderka/patch-1. [Christian Studer]

  csvimport: Return error if input is not valid UTF-8

* Csvimport: Return error if input is not valid UTF-8. [Jakub Onderka]

* Merge pull request #379 from cudeso/master. [Alexandre Dulaunoy]

  Cytomic Orion MISP Module

* Documentation for Cytomic Orion. [Koen Van Impe]

* Update __init__ [Koen Van Impe]

* Make Travis (a little bit) happy. [Koen Van Impe]

* Cytomic Orion MISP Module. [Koen Van Impe]

  An expansion module to enrich attributes in MISP and share indicators
  of compromise with Cytomic Orion

* Merge pull request #377 from 0xbennyv/master. [Alexandre Dulaunoy]

  Added SophosLabs Intelix as expansion module

* Removed Unused Import. [bennyv]

* Fixed handler error handling for missing config. [bennyv]

* Fixed formatting in README.md. [bennyv]

* Updated the README.md for SOPHOSLabs Intelix. [bennyv]

* Initial Build of SOPHOSLabs Intelix Product. [bennyv]

* Merge pull request #374 from M0un/projet-m2-oun-gindt. [Christian Studer]

  Rendu projet master2 sécurité par Mathilde OUN et Vincent GINDT // No…

* Rendu projet master2 sécurité par Mathilde OUN et Vincent GINDT // Nouveau module misp de recherche google sur les urls. [Mathilde Oun et Vincent Gindt]

* Merge pull request #373 from seanthegeek/patch-1. [Christian Studer]

  Create missing __init__.py for _ransomcoindb

* Revert change inteded for other patch. [Sean Whalen]

* Install cmake to build faup. [Sean Whalen]

* Create __init__.py. [Sean Whalen]

* Merge pull request #371 from GlennHD/master. [Christian Studer]

  Added GeoIP_City and GeoIP_ASN Database Modules

* Update geoip_asn.py. [GlennHD]

* Update geoip_city.py. [GlennHD]

* Added geoip_asn and geoip_city to load. [GlennHD]

* Added GeoIP_ASN Enrichment module. [GlennHD]

* Added GeoIP_City Enrichment module. [GlennHD]

* Added GeoIP City and GeoIP ASN Info. [GlennHD]

* Merge pull request #370 from JakubOnderka/vt-query-sha512. [Alexandre Dulaunoy]

  fix: [VT] Disable SHA512 query for VT

* Merge pull request #368 from andurin/lastline_verifyssl. [Christian Studer]

  Lastline verify_ssl option

* Lastline verify_ssl option. [Hendrik]

  Helps people with on-prem boxes


## v2.4.121 (2020-02-06)

### Fix

* Making pep8 happy. [chrisr3d]

* [tests] Fixed BGP raking module test. [chrisr3d]

### Other

* Merge pull request #367 from joesecurity/master. [Christian Studer]

  joe: (1) allow users to disable PE object import (2) set 'to_ids' to False

* Joe: (1) allow users to disable PE object import (2) set 'to_ids' to False. [Georg Schölly]

* Merge branch 'master' of github.com:MISP/misp-modules. [chrisr3d]

* Merge pull request #365 from ostefano/analysis. [Alexandre Dulaunoy]

  change: migrate to analysis API when submitting files to Lastline

* Change: migrate to analysis API when submitting tasks to Lastline. [Stefano Ortolani]

* Merge pull request #364 from cudeso/master. [Christian Studer]

  2nd fix for VT Public module

* 2nd fix for VT Public module. [Koen Van Impe]

* Fix error message in Public VT module. [Koen Van Impe]


## v2.4.120 (2020-01-21)

### New

* Updated ipasn and added vt_graph documentation. [chrisr3d]

* Enrichment module for querying APIVoid with domain attributes. [chrisr3d]

### Changes

* Making ipasn module return asn object(s) [chrisr3d]

  - Latest changes on the returned value as string
    broke the freetext parser, because no asn number
    could be parsed when we return the full json
    blob as a freetext attribute
  - Now returning asn object(s) with a reference to
    the initial attribute

* Bumped pipfile.lock with up-to-date libraries and new vt_graph_api library requirement. [chrisr3d]

* Checking attributes category. [chrisr3d]

  - We check the category before adding the
    attribute to the event
  - Checking if the category is correct and if not,
    doing a case insensitive check
  - If the category is not correct after the 2 first
    tests, we simply delete it from the attribute
    and pymisp will give the attribute a default
    category value based on the atttribute type, at
    the creation of the attribute

* Regenerated the modules documentation following the latest changes. [chrisr3d]

* Updated documentation following the latest changes on the passive dns module. [chrisr3d]

* Made circl_passivedns module able to return MISP objects. [chrisr3d]

* Updated documentation following the latest changes on the passive ssl module. [chrisr3d]

* Made circl_passivessl module able to return MISP objects. [chrisr3d]

* Bump dependencies. [Raphaël Vinot]

* Install faup in travis. [Raphaël Vinot]

* Deactive emails tests, need update. [Raphaël Vinot]

* Update email import module, support objects. [Raphaël Vinot]

* Bump dependencies. [Raphaël Vinot]

### Fix

* Fixed ipasn test input format + module version updated. [chrisr3d]

* Updated ipasn test following the latest changes on the module. [chrisr3d]

* Typo. [chrisr3d]

* Fixed vt_graph imports. [chrisr3d]

* Fixed pep8 in the new module and related libraries. [chrisr3d]

* Fixed typo on function import. [chrisr3d]

* [doc] Added APIVoid logo. [chrisr3d]

* Making pep8 happy with whitespace after ':' [chrisr3d]

* [tests] With values, tests are always better ... [chrisr3d]

* [tests] Fixed copy paste issue. [chrisr3d]

* [tests] Fixed error catching in passive dns and ssl modules. [chrisr3d]

* [tests] Avoiding issues with btc addresses. [chrisr3d]

* Making pep8 happy by having spaces around '+' operators. [chrisr3d]

* [tests] Added missing variable. [chrisr3d]

* Making pep8 happy. [chrisr3d]

* Missing dependency in travis. [Raphaël Vinot]

* Properly install pymisp with file object dependencies. [Raphaël Vinot]

* Quick variable name fix. [chrisr3d]

* OTX tests were failing, new entry. [Raphaël Vinot]

* Somewhat broken emails needed some love. [Raphaël Vinot]

* MIssing parameter in skip. [Raphaël Vinot]

* Missing pushd. [Raphaël Vinot]

* Missing sudo. [Raphaël Vinot]

### Other

* Merge pull request #361 from VirusTotal/master. [Christian Studer]

  add vt_graph export module

* Add vt-graph-api to the requirements. [Alvaro Garcia]

* Add vt_graph export module. [Alvaro Garcia]

* Merge pull request #360 from ec4n6/patch-1. [Alexandre Dulaunoy]

  Fix ipasn.py bug

* Update ipasn.py. [Erick Cheng]

* Add: Documentation for the new API Void module. [chrisr3d]

* Add: [tests] Test case for the APIVoid module. [chrisr3d]

* Revert "fix: [tests] Fixed copy paste issue" [chrisr3d]

  This reverts commit fd711475dd84749063f9ff15961453f90c804101.

* Add: Test cases for reworked passive dns and ssl modules. [chrisr3d]

* Merge branch 'master' of github.com:MISP/misp-modules into new_module. [chrisr3d]


## v2.4.119 (2019-12-03)

### Changes

* Bump dependencies. [Raphaël Vinot]

* Use MISPObject in ransomcoindb. [Raphaël Vinot]

* Reintroducing the limit to reduce the number of recursive calls to the API when querying for a domain. [chrisr3d]

### Fix

* Making pep8 happy. [chrisr3d]

* Fixed AssemblyLine input description. [chrisr3d]

* Fixed input types list since domain should not be submitted to AssemblyLine. [chrisr3d]

* Making pep8 happy. [chrisr3d]

* Added missing AssemblyLine logo. [chrisr3d]

* Avoiding KeyError exception when no result is found. [chrisr3d]

### Other

* Merge pull request #356 from ostefano/lastline. [Alexandre Dulaunoy]

  add: Modules to query/import/submit data from/to Lastline

* Add: Modules to query/import/submit data from/to Lastline. [Stefano Ortolani]

* Revert "Merge pull request #341 from StefanKelm/master" [Raphaël Vinot]

  This reverts commit 1df0d9152ed3346a9432393177c89e137bfc0c64, reversing
  changes made to 6042619c6b7fb40fd77b5328f933e67e839e1e83.

  This PR was a fixing a typo in a test case. The typo is in a 3rd party
  service.

* Merge pull request #341 from StefanKelm/master. [Raphaël Vinot]

  Update test_expansions.py

* Update test_expansions.py. [StefanKelm]

  Tiniest of typos

* Merge branch 'aaronkaplan-master' [Raphaël Vinot]

* Oops , use relative import. [aaronkaplan]

* Use a helpful user-agent string. [aaronkaplan]

* Final url fix. [aaronkaplan]

* Revert "fix url" [aaronkaplan]

  This reverts commit 44130e2bf9842c03fb80245b90a873917b56df74.

* Revert "fix url again" [aaronkaplan]

  This reverts commit c5924aee2543b268b296a57096e636261676b63c.

* Fix url again. [aaronkaplan]

* Fix url. [aaronkaplan]

* Mention the ransomcoindb in the README file as a new module. [aaronkaplan]

* Remove pprint. [aaronkaplan]

* Initial version of the ransomcoindb expansion module. [aaronkaplan]

* Merge pull request #352 from aaronkaplan/patch-1. [Alexandre Dulaunoy]

  Update README.md

* Update README.md. [AaronK]

  fixes #351

* Add: Added documentation for the AssemblyLine query module. [chrisr3d]

* Add: Module to query AssemblyLine and parse the results. [chrisr3d]

  - Takes an AssemblyLine submission link to query
    the API and get the full submission report
  - Parses the potentially malicious files and the
    IPs, domains or URLs they are connecting to
  - Possible improvement of the parsing filters in
    order to include more data in the MISP event

* Add: Added documentation and description in readme for the AssemblyLine submit module. [chrisr3d]

* Add: Updated python dependencies to include the assemblyline_client library. [chrisr3d]

* Add: New expansion module to submit samples and urls to AssemblyLine. [chrisr3d]


## v2.4.118 (2019-11-08)

### Changes

* Using EQL module description from blaverick62. [chrisr3d]

* [test expansion] Enhanced results parsing. [chrisr3d]

* [travis] skip E226 as it's more a question of style. [Alexandre Dulaunoy]

* [apiosintds] make flake8 happy. [Alexandre Dulaunoy]

* [Pipfile] apiosintDS added as required by new module. [Alexandre Dulaunoy]

* [env] Pipfile updated. [Alexandre Dulaunoy]

* [pipenv] updated. [Alexandre Dulaunoy]

* Avoids returning empty values + easier results parsing. [chrisr3d]

* Taking into consideration if a user agent is specified in the module configuration. [chrisr3d]

* Updated csv import documentation. [chrisr3d]

### Fix

* Fixed csv file parsing. [chrisr3d]

* Fixed Xforce Exchange authentication + rework. [chrisr3d]

  - Now able to return MISP objects
  - Support of the xforce exchange authentication
    with apikey & apipassword

* Added urlscan & secuirtytrails modules in __init__ list. [chrisr3d]

* Avoiding empty config error on passivetotal module. [chrisr3d]

* More clarity on the exception raised on the securitytrails module. [chrisr3d]

* Better exceptions handling on the passivetotal module. [chrisr3d]

* Fixed results parsing for various module tests. [chrisr3d]

* Fixed variable name. [chrisr3d]

* Bumped Pipfile.lock with the latest libraries versions. [chrisr3d]

* Fixed config parsing and the associated error message. [chrisr3d]

* Fixed config parsing + results parsing. [chrisr3d]

  - Avoiding errors with config field when it is
    empty or the apikey is not set
  - Parsing all the results instead of only the
    first one

* Fixed VT results. [chrisr3d]

* Making urlscan module available in MISP for ip attributes. [chrisr3d]

  - As expected in the the handler function

* Avoiding various modules to fail with uncritical issues. [chrisr3d]

  - Avoiding securitytrails to fail with an unavailable
    feature for free accounts
  - Avoiding urlhaus to fail with input attribute
    fields that are not critical for the query and
    results
  - Avoiding VT modules to fail when a certain
    resource does not exist in the dataset

* Fixed config field parsing for various modules. [chrisr3d]

  - Same as previous commit

* [expansion] Better config field handling for various modules. [chrisr3d]

  - Testing if config is present before trying to
    look whithin the config field
  - The config field should be there when the module
    is called form MISP, but it is not always the
    case when the module is queried from somewhere else

* [test expansion] Using CVE with lighter results. [chrisr3d]

* Avoid issues when some config fields are not set. [chrisr3d]

* Updated pipfile.lock with the correct geoip2 library info. [chrisr3d]

* Fixed requirements for pymisp and geoip python libraries. [chrisr3d]

* Fixed Geoip with the supported python library + fixed Geolite db path management. [chrisr3d]

* Removed unused self param turning the associated functions into static methods. [chrisr3d]

* Updates following the latest CVE-search version. [chrisr3d]

  - Support of the new vulnerable configuration
    field for CPE version > 2.2
  - Support of different 'unknown CWE' message

* Fixed module names with - to avoid errors with python paths. [chrisr3d]

* Fixed tesseract python library issues. [Christian Studer]

  - Avoiding 'tesseract is not installed or it's not in your path' issues

* Using absolute path to open files instead of relative path. [chrisr3d]

* Removed unused import\ [chrisr3d]

* Handling issues when the otx api is queried too often in a short time. [chrisr3d]

* Making pep8 happy. [chrisr3d]

* Avoiding empty values + Fixed empty types error + Fixed filename KeyError. [chrisr3d]

* Fixed ThreatMiner results parsing. [chrisr3d]

* Catching wikidata errors properly + fixed errors parsing. [chrisr3d]

* Grouped two if conditions to avoid issues with variable unassigned if the second condition is not true. [chrisr3d]

* Handling errors and exceptions for expansion modules tests that could fail due to a connection error. [chrisr3d]

* Considering the case of empty results. [chrisr3d]

* Catching results exceptions properly. [chrisr3d]

* Catching exceptions and results properly depending on the cases. [chrisr3d]

* Handling cases where there is no result from the query. [chrisr3d]

* DBL spamhaus test. [chrisr3d]

* Quick typo & dbl spamhaus test fixes. [chrisr3d]

* Fixed pattern parsing + made the module hover only. [chrisr3d]

* Travis tests should be happy now. [chrisr3d]

* Copy paste syntax error. [chrisr3d]

* Fixed greynoise test following the latest changes on the module. [chrisr3d]

* Returning results in text format. [chrisr3d]

  - Makes the hover functionality display the full
    result instead of skipping the records list

* Making pep8 happy. [chrisr3d]

* Avoiding errors with uncommon lines. [chrisr3d]

  - Excluding first from data parsed all lines that
    are comments or empty
  - Skipping lines with failing indexes

* Fixed unassigned variable name. [chrisr3d]

* Removed no longer used variables. [chrisr3d]

* Csv import rework & improvement. [chrisr3d]

  - More efficient parsing
  - Support of multiple csv formats
  - Possibility to customise headers
  - More improvement to come for external csv file

* Making pep8 happy. [chrisr3d]

* [tests] Fixed tests to avoid config issues with the cve module. [chrisr3d]

  - Config currently empty in the module, but being
    updated soon with a pending pull request

### Other

* Add: Updated documentation with the EQL export module. [chrisr3d]

* Merge branch 'master' of github.com:blaverick62/misp-modules. [chrisr3d]

* Added documentation json for new modules. [Braden Laverick]

* Updated README to include EQL modules. [Braden Laverick]

* Add: Xforce Exchange module tests. [chrisr3d]

* Merge pull request #347 from MISP/tests. [Christian Studer]

  More advanced expansion tests

* Merge branch 'master' of github.com:MISP/misp-modules into tests. [chrisr3d]

* Merge branch 'master' of github.com:MISP/misp-modules into tests. [chrisr3d]

* Add: Updated documentation with the latest modules info. [chrisr3d]

* Updated README with new modules and fixed some links. [chrisr3d]

* Add: Added test for vulners module. [chrisr3d]

* Add: Added qrcode module test with its test image. [chrisr3d]

* Merge branch 'master' of github.com:MISP/misp-modules into tests. [chrisr3d]

* Merge pull request #346 from blaverick62/master. [Alexandre Dulaunoy]

  EQL Query Generation Modules

* Removed extraneous comments and unused imports. [Braden Laverick]

* Fixed python links. [Braden Laverick]

* Changed file name to mass eql export. [Braden Laverick]

* Fixed comments. [Braden Laverick]

* Added ors for compound queries. [Braden Laverick]

* Fixed syntax error. [Braden Laverick]

* Changed to single attribute EQL. [Braden Laverick]

* Added EQL enrichment module. [Braden Laverick]

* Fixed string formatting. [Braden Laverick]

* Fixed type error in JSON parsing. [Braden Laverick]

* Attempting to import endgame module. [Braden Laverick]

* Added endgame export to __all__ [Braden Laverick]

* Added EQL export test module. [Braden Laverick]

* Add: [test expansion] Added various tests for modules with api authentication. [chrisr3d]

* Merge branch 'master' of github.com:MISP/misp-modules into tests. [chrisr3d]

* Add: [test expansion] New modules tests. [chrisr3d]

  - Starting testing some modules with api keys
  - Testing new apiosintDS module

* Merge pull request #344 from davidonzo/master. [Alexandre Dulaunoy]

  Added apiosintDS module to query OSINT.digitalside.it services

* Added apiosintDS module to query OSINT.digitalside.it services. [Davide]

* Merge branch 'master' of github.com:MISP/misp-modules. [chrisr3d]

* Merge pull request #345 from 0xmilkmix/fix_geoip2. [Alexandre Dulaunoy]

  updated to geoip2 to support mmdb format

* Updated to geoip2 to support mmdb format. [milkmix]

* Add: cve_advanced module test + functions to test attributes and objects results. [chrisr3d]

* Merge pull request #342 from MISP/tests. [Christian Studer]

  More expansion tests

* Merge branch 'tests' of github.com:MISP/misp-modules into tests. [chrisr3d]

* Add: Tests for all the office, libreoffice, pdf & OCR enrich modules. [chrisr3d]

* Merge branch 'master' of github.com:MISP/misp-modules into tests. [chrisr3d]

* Merge branch 'master' of github.com:MISP/misp-modules into tests. [chrisr3d]

* Add: threatminer module test. [chrisr3d]

* Add: Tests for expansion modules with different input types. [chrisr3d]

* Merge branch 'master' of github.com:MISP/misp-modules. [chrisr3d]

* Merge pull request #339 from MISP/tests. [Christian Studer]

  Expansion modules tests update

* Add: Added tests for the rest of the easily testable expansion modules. [chrisr3d]

  - More tests for more complex modules to come soon

* Merge branch 'master' of github.com:MISP/misp-modules into tests. [chrisr3d]

* Merge branch 'tests' of github.com:MISP/misp-modules. [chrisr3d]

* Add: Tests for sigma queries and syntax validator modules. [chrisr3d]

* Merge branch 'master' of github.com:MISP/misp-modules into tests. [chrisr3d]

* Merge branch 'master' of github.com:MISP/misp-modules into tests. [chrisr3d]

* Merge branch 'master' of github.com:MISP/misp-modules into tests. [chrisr3d]

* Add: More modules tested. [chrisr3d]

* Add: Added tests for some expansion modules without API key required. [chrisr3d]

  - More tests to come

* Merge pull request #338 from MISP/features_csvimport. [Christian Studer]

  Fixed the CSV import module

* Merge pull request #335 from FafnerKeyZee/patch-2. [Christian Studer]

  Travis should not be complaining with the tests after the latest update on "test_cve"

* Adding custom API. [Fafner [_KeyZee_]]

  Adding the possibility to have our own API server.

* Merge branch 'master' of github.com:MISP/misp-modules. [chrisr3d]

* Merge pull request #334 from FafnerKeyZee/patch-1. [Alexandre Dulaunoy]

  Cleaning the error message

* Cleaning the error message. [Fafner [_KeyZee_]]

  The original message can be confusing is the user change to is own API.


## v2.4.116 (2019-09-17)

### Other

* Merge branch 'master' of github.com:MISP/misp-modules. [chrisr3d]

* Merge pull request #329 from 8ear/8ear-add-mkdocs-documentation. [Alexandre Dulaunoy]

  Update mkdocs documentation

* Fixing Install.md. [8ear]

* Fix Install.md. [8ear]

* Change Install documentation. [8ear]

* Merge pull request #328 from 8ear/8ear-add-docker-capabilitites. [Alexandre Dulaunoy]

  Add Docker Capabilitites

* Add .travis.yml command for docker build. [8ear]

* Merge github.com:MISP/misp-modules into 8ear-add-docker-capabilitites. [8ear]

* Disable not required package virtualenv for final stage. [8ear]

* Fix entrypoint bug. [8ear]

* Improve the Dockerfile. [8ear]

* Add Dockerfile, Entrypoint and Healthcheck script. [8ear]

* Update install doc. [8ear]

* Bugfixing for MISP-modules. [8ear]

* Add: New parameter to specify a custom CVE API to query. [chrisr3d]

  - Any API specified here must return the same
    format as the CIRCL CVE search one in order to
    be supported by the parsing functions, and
    ideally provide response to the same kind of
    requests (so the CWE search works as well)


## v2.4.114 (2019-08-30)

### Changes

* [cuckooimport] Handle archives downloaded from both the WebUI and the API. [Pierre-Jean Grenier]

### Fix

* Prevent symlink attacks. [Pierre-Jean Grenier]

* Have I been pwned API changed again. [Raphaël Vinot]

### Other

* Merge pull request #327 from zaphodef/cuckooimport. [Alexandre Dulaunoy]

  fix: prevent symlink attacks

* Merge pull request #326 from zaphodef/cuckooimport. [Alexandre Dulaunoy]

  chg: [cuckooimport] Handle archives downloaded from both the WebUI and the API


## v2.4.113 (2019-08-19)

### New

* Rewrite cuckooimport. [Pierre-Jean Grenier]

### Changes

* Update PyMISP version. [Pierre-Jean Grenier]

### Fix

* Avoiding issues when no CWE id is provided. [chrisr3d]

* Fixed unnecessary dictionary field call. [chrisr3d]

  - No longer necessary to go under 'Event' field
    since PyMISP does not contain it since the
    latest update

### Other

* Merge pull request #322 from zaphodef/cuckooimport. [Alexandre Dulaunoy]

  Rewrite cuckooimport

* Merge branch 'master' of github.com:MISP/misp-modules. [chrisr3d]

* Add: Added initial event to reference it from the vulnerability object created out of it. [chrisr3d]


## v2.4.112 (2019-08-02)

### New

* First version of an advanced CVE parser module. [chrisr3d]

  - Using cve.circl.lu as well as the initial module
  - Going deeper into the CVE parsing
  - More parsing to come with the CWE, CAPEC and so on

### Changes

* [docs] add additional references. [Alexandre Dulaunoy]

* [travis] revert. [Alexandre Dulaunoy]

* [travis] github token. [Alexandre Dulaunoy]

* [travis] mkdocs disabled for the time being. [Alexandre Dulaunoy]

* [doc] Fix #317 - update the link to the latest version of the training. [Alexandre Dulaunoy]

* [doc] README updated to the latest version. [Alexandre Dulaunoy]

* [docs] symbolic link removed. [Alexandre Dulaunoy]

* [docs] add logos symbolic link. [Alexandre Dulaunoy]

* Add print to figure out what's going on on travis. [Raphaël Vinot]

* Bump dependencies. [Raphaël Vinot]

* Updated the module to work with the updated VirusTotal API. [chrisr3d]

  - Parsing functions updated to support the updated
    format of the VirusTotal API responses
  - The module can now return objects
  - /!\ This module requires a high number of
    requests limit rate to work as expected /!\

* Adding references between a domain and their siblings. [chrisr3d]

* Getting domain siblings attributes uuid for further references. [chrisr3d]

### Fix

* Using the attack-pattern object template (copy-paste typo) [chrisr3d]

* Making pep8 happy. [chrisr3d]

* Fixed cvss-score object relation name. [chrisr3d]

* Avoid issues when there is no pe field in a windows file sample analysis. [chrisr3d]

  - For instance: doc file

* Avoid adding file object twice if a KeyError exception comes for some unexpected reasons. [chrisr3d]

* Testing if file & registry activities fields exist before trying to parse it. [chrisr3d]

* Testing if there is some screenshot data before trying to fetch it. [chrisr3d]

* Fixed direction of the relationship between files, PEs and their sections. [chrisr3d]

  - The file object includes a PE, and the PE
    includes sections, not the other way round

* Fixed variable names. [chrisr3d]

* Wrong change in last commit. [Raphaël Vinot]

* Skip tests on haveibeenpwned.com if 403. Make pep8 happy. [Raphaël Vinot]

* Changed the way references added at the end are saved. [chrisr3d]

  - Some references are saved until they are added
    at the end, to make it easier when needed
  - Here we changed the way they are saved, from a
    dictionary with some keys to identify each part
    to the actual dictionary with the keys the
    function add_reference needs, so we can directly
    use this dictionary as is when the references are
    added to the different objects

* Fixed link in documentation. [chrisr3d]

* Avoiding issues with non existing sample types. [chrisr3d]

* Undetected urls are represented in lists. [chrisr3d]

* Changed function name to avoid confusion with the same variable name. [chrisr3d]

* Quick fix on siblings & url parsing. [chrisr3d]

* Typo. [chrisr3d]

* Parsing detected & undetected urls. [chrisr3d]

* Various fixes about typo, variable names, data types and so on. [chrisr3d]

* Making pep8 happy. [chrisr3d]

### Other

* Merge pull request #319 from 8ear/8ear-add-mkdocs-documentation. [Alexandre Dulaunoy]

  Add `make deploy` to Makefile

* Added docker and non-docker make commands. [8ear]

* Add `make deploy` [8ear]

* Merge pull request #318 from chrisr3d/master. [Christian Studer]

  Updated cve_advanced module to parse CWE and CAPEC data related to the CVE

* Merge branch 'master' of github.com:MISP/misp-modules. [chrisr3d]

* Add: Making vulnerability object reference to its related capec & cwe objects. [chrisr3d]

* Add: Parsing CAPEC information related to the CVE. [chrisr3d]

* Add: Parsing CWE related to the CVE. [chrisr3d]

* Merge pull request #316 from 8ear/8ear-add-mkdocs-documentation. [Alexandre Dulaunoy]

  Add web documentation via mkdocs

* Fix Bugs. [8ear]

* Fix Fossa in index.md. [8ear]

* Delete unused file. [8ear]

* Change mkdocs deploy method. [8ear]

* Change index.md. [8ear]

* Merge branch 'master' into 8ear-add-mkdocs-documentation. [Max H]

* Add: Parsing linux samples and their elf data. [chrisr3d]

* Merge branch 'master' of github.com:MISP/misp-modules. [chrisr3d]

* Add: Parsing apk samples and their permissions. [chrisr3d]

* Add: Added virustotal_public to the list of available modules. [chrisr3d]

* Add: TODO comment for the next improvement. [chrisr3d]

* Add: [documentation] Updated README and documentation with the virustotal modules changes. [chrisr3d]

* Add: Parsing communicating samples returned by domain reports. [chrisr3d]

* Add: Parsing downloaded samples as well as the referrer ones. [chrisr3d]

* Add: Object for VirusTotal public API queries. [chrisr3d]

  - Lighter analysis of the report to avoid reaching
    the limit of queries per minute while recursing
    on the different elements

* Add: Updated README file with the new module description. [chrisr3d]

* Change contribute.md. [8ear]

* Update index.md. [8ear]

* Add mkdocs as a great web documentation. [8ear]

* Merge pull request #1 from fossabot/master. [Max H]

  Add license scan report and status

* Add license scan report and status. [fossabot]


## v2.4.110 (2019-07-08)

### New

* [doc] Joe Sandbox added in the list. [Alexandre Dulaunoy]

* Expansion module to query urlhaus API. [chrisr3d]

  - Using the next version of modules, taking a
    MISP attribute as input and able to return
    attributes and objects
  - Work still in process in the core part

### Changes

* [documentation] Making URLhaus visible from the github page. [chrisr3d]

  - Because of the white color, the logo was not
    visible at all

* Moved JoeParser class to make it reachable from expansion & import modules. [chrisr3d]

* [install] REQUIREMENTS file updated. [Alexandre Dulaunoy]

* [install] Pipfile.lock updated. [Alexandre Dulaunoy]

* [requirements] Python API wrapper for the Joe Sandbox API added. [Alexandre Dulaunoy]

* Bump dependencies. [Raphaël Vinot]

* [pep8] try/except # noqa. [Steve Clement]

  Not sure how to make flake happy on this one.

* Updated csvimport to support files from csv export + import MISP objects. [chrisr3d]

### Fix

* Added missing add_attribute function. [chrisr3d]

* [documentation] Fixed json file name. [chrisr3d]

* [documentation] Fixed some description & logo. [chrisr3d]

* Testing if an object is not empty before adding it the the event. [chrisr3d]

* Making travis happy. [chrisr3d]

* Support of the latest version of sigmatools. [chrisr3d]

* We will display galaxies with tags. [chrisr3d]

* Returning tags & galaxies with results. [chrisr3d]

  - Tags may exist with the current version of the
    parser
  - Galaxies are not yet expected from the parser,
    nevertheless the principle is we want to return
    them as well if ever we have some galaxies from
    parsing a JoeSandbox report. Can be removed if
    we never galaxies at all

* Removed duplicate finalize_results function call. [chrisr3d]

* Making pep8 happy + added joe_import module in the init list. [chrisr3d]

* Fixed variable name typo. [chrisr3d]

* Fixed references between domaininfo/ipinfo & their targets. [chrisr3d]

  - Fixed references when no target id is set
  - Fixed domaininfo parsing when no ip is defined

* Some quick fixes. [chrisr3d]

  - Fixed strptime matching because months are
    expressed in abbreviated format
  - Made data loaded while the parsing function is
    called, in case it has to be called multiple
    times at some point

* Making pep8 & travis happy. [chrisr3d]

* Added references between processes and the files they drop. [chrisr3d]

* Avoiding network connection object duplicates. [chrisr3d]

* Avoid creating a signer info object when the pe is not signed. [chrisr3d]

* Avoiding dictionary indexes issues. [chrisr3d]

  - Using tuples as a dictionary indexes is better
    than using generators...

* Avoiding attribute & reference duplicates. [chrisr3d]

* Handling case of multiple processes in behavior field. [chrisr3d]

  - Also starting parsing file activities

* Testing if some fields exist before trying to import them. [chrisr3d]

  - Testing for pe itself, pe versions and pe signature

* Removed test print. [chrisr3d]

* Fixed output format to match with the recent changes on modules. [chrisr3d]

* Making pep8 happy. [chrisr3d]

* Checking not MISP header fields. [chrisr3d]

  - Rejecting fields not recognizable by MISP

* Using pymisp classes & methods to parse the module results. [chrisr3d]

* Clearer user config messages displayed in the import view. [chrisr3d]

* Removed unused library. [chrisr3d]

* Make pep8 happy. [chrisr3d]

* [pep8] More fixes. [Steve Clement]

* [pep8] More pep8 happiness. [Steve Clement]

* [pep8] Fixes. [Steve Clement]

* Fixed standard MISP csv format header. [root]

  - The csv header we can find in data produced from
    MISP restSearch csv format is the one to use to
    recognize a csv file produced by MISP

* Fixed introspection fields for csvimport & goamlimport. [root]

  - Added format field for goaml so the module is
    known as returning MISP attributes & objects
  - Fixed introspection to make the format, user
    config and input source fields visible from
    MISP (format also added at the same time)

* Fixed libraries import that changed with the latest merge. [root]

* Fixed fields parsing to support files from csv export with additional context. [chrisr3d]

* Handling the case of Context included in the csv file exported from MISP. [chrisr3d]

* Fixed changes omissions in handler function. [chrisr3d]

* Fixed object_id variable name typo. [root]

* Making json_decode even happier with full json format. [chrisr3d]

  - Using MISPEvent because it is cleaner & easier
  - Also cleaner implementation globally

* Using to_dict on attributes & objects instead of to_json to make json_decode happy in the core part. [chrisr3d]

### Other

* Add: [documentation] Added some missing documentation for the most recently added modules. [chrisr3d]

* Add: [documentation] Added documentation for Joe Sandbox & URLhaus. [chrisr3d]

* Merge branch 'master' of github.com:MISP/misp-modules. [chrisr3d]

* Merge pull request #309 from Kortho/patch-2. [Steve Clement]

  changed service pointer

* Changed service pointer. [Kortho]

  Changed so the service starts the modules in the venv where they are installed

* Merge pull request #308 from Kortho/patch-1. [Steve Clement]

  Fixed missing dependencies for RHEL install

* Fixed missing dependencies for RHEL install. [Kortho]

  Added dependencies needed for installing the python library pdftotext

* Add: Added screenshot of the behavior of the analyzed sample. [chrisr3d]

* Merge branch 'master' of github.com:MISP/misp-modules. [chrisr3d]

* Merge pull request #307 from ninoseki/fix-missing-links. [Alexandre Dulaunoy]

  Fix missing links in README.md

* Fix missing links in README.md. [Manabu Niseki]

* Merge branch 'master' of github.com:MISP/misp-modules into new_module. [chrisr3d]

* Merge pull request #306 from MISP/new_module. [Alexandre Dulaunoy]

  New modules able to return MISP objects

* Add: Added new modules to the list. [chrisr3d]

* Merge branch 'new_module' of github.com:MISP/misp-modules into new_module. [chrisr3d]

* Merge pull request #305 from joesecurity/new_module. [Alexandre Dulaunoy]

  joesandbox_query.py: improve behavior in unexpected circumstances

* Joesandbox_query.py: improve behavior in unexpected circumstances. [Georg Schölly]

* Add: New expansion module to query Joe Sandbox API with a report link. [chrisr3d]

* Merge branch 'master' of github.com:MISP/misp-modules into new_module. [chrisr3d]

* Merge branch 'joesecurity-joesandbox_submit' [Alexandre Dulaunoy]

* Merge branch 'joesandbox_submit' of https://github.com/joesecurity/misp-modules into joesecurity-joesandbox_submit. [Alexandre Dulaunoy]

* Add expansion for joe sandbox. [Georg Schölly]

* Merge pull request #304 from joesecurity/new_module. [Alexandre Dulaunoy]

  add support for url analyses

* Support url analyses. [Georg Schölly]

* Improve forwards-compatibility. [Georg Schölly]

* Add: Parsing MITRE ATT&CK tactic matrix related to the Joe report. [chrisr3d]

* Add: Parsing domains, urls & ips contacted by processes. [chrisr3d]

* Add: Starting parsing dropped files. [chrisr3d]

* Add: Starting parsing network behavior fields. [chrisr3d]

* Add: Parsing registry activities under processes. [chrisr3d]

* Add: Parsing processes called by the file analyzed in the joe sandbox report. [chrisr3d]

* Add: Parsing some object references at the end of the process. [chrisr3d]

* Add: [new_module] Module to import data from Joe sandbox reports. [chrisr3d]

  - Parsing file, pe and pe-section objects from the
    report file info field
  - Deeper file info parsing to come
  - Other fields parsing to come as well

* Merge branch 'master' of github.com:MISP/misp-modules into new_module. [chrisr3d]

* Merge branch 'master' of github.com:MISP/misp-modules into new_module. [chrisr3d]

* Merge pull request #300 from cudeso/master. [Alexandre Dulaunoy]

  Bugfix for "sources" ; do not include as IDS for "access" registry keys

* Bugfix for "sources" ; do not include as IDS for "access" registry keys. [Koen Van Impe]

  - Bugfix to query "operations" in files, mutex, registry
  - Do not set IDS flag for registry 'access' operations

* Merge branch 'master' of github.com:MISP/misp-modules into new_module. [chrisr3d]

* New VMRay modules (#299) [Steve Clement]

  New VMRay modules

* New VMRay modules. [Koen Van Impe]

  New JSON output format of VMRay
  Prepare for automation (via PyMISP) with workflow taxonomy tags

* Merge pull request #1 from MISP/master. [Koen Van Impe]

  Sync

* Add: Added urlhaus in the expansion modules init list. [root]

* Merge branch 'new_module' of https://github.com/MISP/misp-modules into new_module. [root]

* Merge branch 'features_csvimport' of github.com:MISP/misp-modules into new_module. [chrisr3d]

* Merge branch 'master' of github.com:MISP/misp-modules into features_csvimport. [chrisr3d]

* Merge branch 'features_csvimport' of github.com:MISP/misp-modules into features_csvimport. [chrisr3d]

* Merge branch 'master' of github.com:MISP/misp-modules into features_csvimport. [chrisr3d]

* Merge branch 'master' of github.com:MISP/misp-modules into features_csvimport. [chrisr3d]

* Merge branch 'master' of github.com:MISP/misp-modules into new_module. [chrisr3d]

* Merge branch 'new_module' of github.com:MISP/misp-modules into new_module. [chrisr3d]

* Merge branch 'master' of github.com:MISP/misp-modules into new_module. [chrisr3d]

* Merge branch 'master' of github.com:MISP/misp-modules into new_module. [chrisr3d]

* Merge branch 'master' of https://github.com/MISP/misp-modules into new_module. [root]

* Merge branch 'master' of https://github.com/MISP/misp-modules into new_module. [root]

* Merge branch 'master' of github.com:MISP/misp-modules into new_module. [chrisr3d]


## v2.4.106 (2019-04-27)

### New

* Devel mode. [Raphaël Vinot]

  Fix #293

* Modules for greynoise, haveibeenpwned and macvendors. [Raphaël Vinot]

* Add missing dependency (backscatter) [Raphaël Vinot]

* Add systemd launcher. [Raphaël Vinot]

* Intel471 module. [Raphaël Vinot]

* [btc] Very simple BTC expansion chg: [req] yara-python is preferred. [Steve Clement]

* First version of a yara rule creation expansion module. [chrisr3d]

* Documentation concerning modules explained in markdown file. [chrisr3d]

* Expansion hover module to check spamhaus DBL for a domain name. [chrisr3d]

### Changes

* [doc] install of deps updated. [Alexandre Dulaunoy]

* Bump REQUIREMENTS. [Raphaël Vinot]

* Bump dependencies. [Raphaël Vinot]

* [doc] new MISP expansion modules added for PDF, OCR, DOCX, XLSX, PPTX , ODS and ODT. [Alexandre Dulaunoy]

* [init] cleanup for pep. [Alexandre Dulaunoy]

* [pdf-enrich] updated. [Alexandre Dulaunoy]

* [Pipfile] collection removed. [Alexandre Dulaunoy]

* Bump dependencies. [Raphaël Vinot]

* [doc] Added new dependencies and updated RHEL/CentOS howto. (#295) [Steve Clement]

  chg: [doc] Added new dependencies and updated RHEL/CentOS howto.

* [doc] Added new dependencies and updated RHEL/CentOS howto. [Steve Clement]

* [init] removed trailing whitespace. [Alexandre Dulaunoy]

* [ocr] re module not used - removed. [Alexandre Dulaunoy]

* Bump dependencies, update REQUIREMENTS file. [Raphaël Vinot]

* [doc] cuckoo_submit module added. [Alexandre Dulaunoy]

* Require python3 instead of python 3.6. [Raphaël Vinot]

* [travis] because we all need sudo. [Alexandre Dulaunoy]

* [travis] because everyone need a bar. [Alexandre Dulaunoy]

* [doc] qrcode and Cisco FireSight added. [Alexandre Dulaunoy]

* [qrcode] add requirements. [Alexandre Dulaunoy]

* [qrcode] added to the __init__ [Alexandre Dulaunoy]

* [qrcode] flake8 needs some drugs. [Alexandre Dulaunoy]

* [qrcode] various fixes to make it PEP compliant. [Alexandre Dulaunoy]

* Bump dependencies. [Raphaël Vinot]

  Fix CVE-2019-11324 (urllib3)

* Bump Dependencies. [Raphaël Vinot]

* [doc] Updated README to reflect current virtualenv efforts. TODO: pipenv. [Steve Clement]

* [doc] new modules added. [Alexandre Dulaunoy]

* Bump dependencies. [Raphaël Vinot]

* Bump dependencies. [Raphaël Vinot]

* Bump Requirements. [Raphaël Vinot]

* [doc] asciidoctor requirement removed (new PDF module use reportlab) [Alexandre Dulaunoy]

* Bump dependencies, add update script. [Raphaël Vinot]

* [doc] PDF export. [Alexandre Dulaunoy]

* [pdfexport] make flake8 happy. [Alexandre Dulaunoy]

* [pipenv] fix the temporary issue that python-yara is not officially released. [Alexandre Dulaunoy]

* [requirements] reportlab added. [Alexandre Dulaunoy]

* [pipenv] Pipfile.lock updated. [Alexandre Dulaunoy]

* [requirements] updated. [Alexandre Dulaunoy]

* [PyMISP] dep updated to the latest version. [Alexandre Dulaunoy]

* PyMISP requirement. [Alexandre Dulaunoy]

* [pypi] Made sure url-normalize installs less stric. [Steve Clement]

* [btc_scam_check] fix spacing for making flake 8 happy. [Alexandre Dulaunoy]

* [backscatter.io] blind fix regarding undefined value. [Alexandre Dulaunoy]

* [doc] backscatter.io updated. [Alexandre Dulaunoy]

* [doc] backscatter.io documentation added. [Alexandre Dulaunoy]

* [backscatter.io] remove blank line at the end of the file. [Alexandre Dulaunoy]

* [backscatter.io] Exception handler fixed for recent version of Python. [Alexandre Dulaunoy]

* Bump dependencies. [Raphaël Vinot]

* Use pipenv, update bgpranking/ipasn modules. [Raphaël Vinot]

* [doc] Nexthink module added. [Alexandre Dulaunoy]

* [doc] osquery export module added. [Alexandre Dulaunoy]

* [doc] Nexthink export format added. [Alexandre Dulaunoy]

* [doc] cannot type today. [Alexandre Dulaunoy]

* [intel471] module added. [Alexandre Dulaunoy]

* Regenerated documentation markdown file. [chrisr3d]

* [onyphe] fix #252. [Alexandre Dulaunoy]

* [btc] Removed simple PoC for btc expansion. [Steve Clement]

* [doc] btc module added. [Alexandre Dulaunoy]

* [doc] generated documentation updated. [Alexandre Dulaunoy]

* [doc] btc module added to documentation. [Alexandre Dulaunoy]

* [tools] Added psutil as a dependency to detect misp-modules PID. [Steve Clement]

* [init] Added try/catch in case misp-modules is already running on a port, or port is in use... [Steve Clement]

* Validating yara rules after their creation. [chrisr3d]

* [documentation] osquery logo added. [Alexandre Dulaunoy]

* [documentation] generated. [Alexandre Dulaunoy]

* [docs] Added some missing dependencies and instructions for virtualenv deployment. [Steve Clement]

* [doc] documentation generator updated to include links to source code. [Alexandre Dulaunoy]

* Changed documentation markdown file name. [chrisr3d]

* Structurded data. [chrisr3d]

* Modified the mapping dictionary to support misp-objects updates. [chrisr3d]

* Modified output format. [chrisr3d]

* Add new dependency (oauth2) [Raphaël Vinot]

* Dnspython3 has been superseded by the regular dnspython kit. [Raphaël Vinot]

* Wikidata module added. [Alexandre Dulaunoy]

* SPARQLWrapper added (for wikidata module) [Alexandre Dulaunoy]

### Fix

* Re-enable python 3.6 support. [Raphaël Vinot]

* CTRL+C is working again. [Raphaël Vinot]

  Fix #292

* Make flake8 happy. [Raphaël Vinot]

* [doc] Small typo fix. [Steve Clement]

* Pep8 foobar. [Raphaël Vinot]

* Add the new module sin the list of modules availables. [Raphaël Vinot]

* Typos in variable names. [Raphaël Vinot]

* Remove unused import. [Raphaël Vinot]

* Tornado expects a KILL now. [Raphaël Vinot]

* [exportpdf] update documentation. [Falconieri]

* [exportpdf] custom path parameter. [Falconieri]

* [exportpdf] add parameters. [Falconieri]

* [exportpdf] mising whitespace. [Falconieri]

* [exportpdf] problem on one line. [Falconieri]

* [exportpdf] add configmodule parameter for galaxy. [Falconieri]

* [reportlab] Textual description parameter. [Falconieri]

* [pdfexport]  Bugfix on PyMisp exportpdf call. [Falconieri]

* Systemd service. [Raphaël Vinot]

* Regenerated documentation. [chrisr3d]

* Description fixed. [chrisr3d]

* Pep8 related fixes. [Raphaël Vinot]

* Make flake8 happy. [Raphaël Vinot]

* Change in the imports in other sigma module. [Raphaël Vinot]

* Change in the imports. [Raphaël Vinot]

* Change module name. [Raphaël Vinot]

* Allow redis details to be retrieved from environment variables. [Ruiwen Chua]

* Remove tests on python 3.5. [Raphaël Vinot]

* Make pep8 happy. [Raphaël Vinot]

* Removed not valid input type. [chrisr3d]

* Cleaned up not used variables. [chrisr3d]

* Updated rbl module result format. [chrisr3d]

  - More readable as str than dumped json

* Added Macaddress.io module in the init list. [chrisr3d]

* Typo on input type. [chrisr3d]

* Fixed type of the result in case of exception. [chrisr3d]

  - Set as str since some exception types are not
    jsonable

* Added hostname attribute support as it is intended. [chrisr3d]

* Threatanalyzer_import - bugfix for TA6.1 behavior. [Christophe Vandeplas]

* Displaying documentation items of each module by alphabetic order. [chrisr3d]

  - Also regenerated updated documentation markdown

* Updated yara import error message. [chrisr3d]

  - Better to 'pip install -I -r REQUIREMENTS' to
    have the correct yara-python version working
    for all the modules, than having another one
    failing with yara hash & pe modules

* Specifying a yara-python version that works for hash & pe yara modules. [chrisr3d]

* Making yara query an expansion module for single attributes atm. [chrisr3d]

* Catching errors while parsing additional info in requests. [chrisr3d]

* Reduced logos size. [chrisr3d]

* Typo for separator between each explained module. [chrisr3d]

* Making python 3.5 happy with the exception type ImportError. [chrisr3d]

* Fixed exception type for python 3.5. [chrisr3d]

* Fixed exception type. [chrisr3d]

* Fixed syntax error. [chrisr3d]

* Fixed indentation error. [chrisr3d]

* Fixed 1 variable misuse + cleaned up variable names. [chrisr3d]

  - Fixed use of 'domain' variable instead of 'email'
  - Cleaned up variable names to avoid redefinition
    of built-in variables

* Avoiding adding attributes that are already in the event. [chrisr3d]

* Fixed quick variable issue. [chrisr3d]

* Cleaned up test function not used anymore. [chrisr3d]

* Multiple attributes parsing support. [chrisr3d]

  - Fixing one of my previous changes not processing
    multiple attributes parsing

* Removed print. [chrisr3d]

* Some cleanup and output types fixed. [chrisr3d]

  - hashes types specified in output

* Quick cleanup. [chrisr3d]

* Quick cleanup. [chrisr3d]

* Ta_import - bugfixes. [Christophe Vandeplas]

* [cleanup] Quick clean up on exception type. [chrisr3d]

* [cleanup] Quick clean up on yaml load function. [chrisr3d]

* [cleanup] Quick clean up on exception type. [chrisr3d]

* Put the report location parsing in a try/catch statement as it is an optional field. [chrisr3d]

* Put the stix2-pattern library import in a try statement. [chrisr3d]

  --> Error more easily caught

* Removed STIX related libraries, files, documentation, etc. [chrisr3d]

* Avoid trying to build attributes with not intended fields. [chrisr3d]

  - Previously: if the header field is not an attribute type, then
                it was added as an attribute field.
                PyMISP then used to skip it if needed

  - Now: Those fields are discarded before they are put in an attribute

* Using userConfig to define the header instead of moduleconfig. [chrisr3d]

* Fixed input & output of the module. [chrisr3d]

* Added an object checking. [Christian Studer]

  - Checking if there are objects in the event, and then if there is at least 1 transaction object
  - This prevents the module from crashing, but does not guaranty having a valid GoAML file (depending on objects and their relations)

* Fixed input & output of the module. [chrisr3d]

  Also updated some functions

* Fixed typo of the aml type for country codes. [chrisr3d]

* Typo in references mapping dictionary. [chrisr3d]

* Added an object checking. [chrisr3d]

  - Checking if there are objects in the event, and then
    if there is at least 1 transaction object
  - This prevents the module from crashing, but does not
    guaranty having a valid GoAML file (depending on
    objects and their relations)

* Added the moduleinfo field need to have MISP event in standard format. [chrisr3d]

* Missing cve module test. [Alexandre Dulaunoy]

* Goamlexport added. [Alexandre Dulaunoy]

* Python version in Travis. [Alexandre Dulaunoy]

* Solved reading problems for some files. [chrisr3d]

* Skipping empty lines. [chrisr3d]

* Make travis happy. [Raphaël Vinot]

* OpenIOC importer. [Raphaël Vinot]

* #137 when a CVE is not found, a return message is given. [Alexandre Dulaunoy]

* Use the proper formatting method and not the horrible % one. [Hannah Ward]

* Misp-modules are by default installed in /bin. [Alexandre Dulaunoy]

* Module_config should be set as introspection relies on it. [Alexandre Dulaunoy]

* Types array. [Alexandre Dulaunoy]

* Run the server as "python3 misp-modules" [Raphaël Vinot]

* Stupid off-by-n line... [Alexandre Dulaunoy]

### Other

* Merge branch 'master' of github.com:MISP/misp-modules. [Alexandre Dulaunoy]

* Removed trailing whitespaces. [Sascha Rommelfangen]

* Merge branch 'master' of https://github.com/MISP/misp-modules. [Sascha Rommelfangen]

* Merge branch 'master' of github.com:MISP/misp-modules. [Raphaël Vinot]

* New modules added. [Sascha Rommelfangen]

* New requirements for new modules. [Sascha Rommelfangen]

* Introduction of new modules. [Sascha Rommelfangen]

* Merge remote-tracking branch 'upstream/master' [Steve Clement]

* Merge branch 'master' of https://github.com/MISP/misp-modules. [Sascha Rommelfangen]

* Renamed file. [Sascha Rommelfangen]

* Renamed module. [Sascha Rommelfangen]

* Initial version of OCR expansion module. [Sascha Rommelfangen]

* Merge pull request #291 from Evert0x/submitcuckoo. [Alexandre Dulaunoy]

  Expansion module - File/URL submission to Cuckoo Sandbox

* Generate latest version of documentation. [Ricardo van Zutphen]

* Document Cuckoo expansion module. [Ricardo van Zutphen]

* Use double quotes and provide headers correctly. [Ricardo van Zutphen]

* Update Cuckoo module to support files and URLs. [Ricardo van Zutphen]

* Update __init__.py. [Evert0x]

* Create cuckoo_submit.py. [Evert0x]

* Brackets are difficult... [Sascha Rommelfangen]

* Merge branch 'qr-code-module' of https://github.com/rommelfs/misp-modules into rommelfs-qr-code-module. [Alexandre Dulaunoy]

* Initial version of QR code reader. [Sascha Rommelfangen]

  Module accepts attachments and processes pictures. It tries to identify and analyze an existing QR code.
  Identified values can be inserted into the event.

* Merge branch 'iceone23-patch-1' [Raphaël Vinot]

* Create cisco_firesight_manager_ACL_rule_export.py. [iceone23]

  Cisco Firesight Manager ACL Rule Export module

* Merge pull request #289 from SteveClement/master. [Steve Clement]

  fix: [doc] Small typo fix

* Merge remote-tracking branch 'upstream/master' [Steve Clement]

* Merge pull request #285 from wesinator/patch-1. [Alexandre Dulaunoy]

  Fix command highlighting

* Fix command highlighting. [Ԝеѕ]

* Merge branch 'master' of https://github.com/MISP/misp-modules. [Sascha Rommelfangen]

* Merge pull request #284 from Vincent-CIRCL/master. [Alexandre Dulaunoy]

  fix: [exportpdf] custom path parameter

* Merge pull request #283 from Vincent-CIRCL/master. [Alexandre Dulaunoy]

  fix: [exportpdf] add parameters

* Merge pull request #281 from Vincent-CIRCL/master. [Alexandre Dulaunoy]

  fix: [exportpdf] add configmodule parameter for galaxy

* Merge pull request #282 from cgi1/patch-1. [Alexandre Dulaunoy]

  Adding virtualenv to apt-get install

* Adding virtualenv to apt-get install. [cgi1]

* Merge pull request #279 from Vincent-CIRCL/master. [Alexandre Dulaunoy]

  fix: [reportlab] Textual description parameter

* Chr: Restart the modules after update. [Raphaël Vinot]

* Fixed a bug when checking malformed BTC addresses. [Sascha Rommelfangen]

* Merge remote-tracking branch 'upstream/master' [Steve Clement]

* Merge branch 'master' of github.com:MISP/misp-modules. [Alexandre Dulaunoy]

* Merge pull request #278 from Vincent-CIRCL/master. [Alexandre Dulaunoy]

  chg: [pdfexport] Fix pdf export, by calling new PyMISP tool for Misp Event export

* Fix [exportpdf] update parameters for links generation. [Falconieri]

* Tidy: Remove old dead export code. [Falconieri]

* Test 1 - PDF call. [Falconieri]

* Print values. [Vincent-CIRCL]

* Test update. [Vincent-CIRCL]

* Merge branch 'master' of github.com:MISP/misp-modules. [Alexandre Dulaunoy]

* Merge branch 'master' of github.com:MISP/misp-modules. [Alexandre Dulaunoy]

* Merge pull request #276 from iwitz/patch-1. [Alexandre Dulaunoy]

  Add RHEL installation instructions

* Add: rhel installation instructions. [iwitz]

* Add: [doc] Added backscatter.io logo + regenerated documentation. [chrisr3d]

* Merge branch 'master' of github.com:MISP/misp-modules into new_module. [chrisr3d]

* Merge pull request #274 from 9b/master. [Alexandre Dulaunoy]

  Backscatter.io expansion module

* Use the write var on return. [9b]

* Stubbed module. [9b]

* Add: New module to check if a bitcoin address has been abused. [chrisr3d]

  - Also related update of documentation

* Sometimes server doesn't return expected values. fixed. [Sascha Rommelfangen]

* Merge pull request #266 from MISP/pipenv. [Raphaël Vinot]

  chg: Use pipenv, update bgpranking/ipasn modules, fix imports for sigma

* Merge pull request #259 from ruiwen/fix_redis. [Alexandre Dulaunoy]

  fix: allow redis details to be retrieved from environment variables

* Add: [doc] link documentation to README. [Alexandre Dulaunoy]

* Merge branch 'master' of github.com:MISP/misp-modules. [Alexandre Dulaunoy]

* Merge pull request #258 from HacknowledgeCH/export_nexthink. [Alexandre Dulaunoy]

  Export nexthink

* Added 2 blank lines to comply w/ pep8. [milkmix]

* Removed unused re module. [milkmix]

* Added documentation. [milkmix]

* Added domain attributes support. [milkmix]

* Support for md5 and sha1 hashes. [milkmix]

* First export feature: sha1 attributes nxql query. [milkmix]

* Merge branch 'master' of https://github.com/MISP/misp-modules. [Sascha Rommelfangen]

* Add: Added missing expansion modules in readme. [chrisr3d]

* Add: Completed documentation for expansion modules. [chrisr3d]

* Add: Updated more expansion documentation files. [chrisr3d]

* Add: Added new documentation for hashdd module. [chrisr3d]

* Add: Update to support sha1 & sha256 attributes. [chrisr3d]

* Add: More documentation on expansion modules. [chrisr3d]

* Add: Started filling some expansion modules documentation. [chrisr3d]

* Add: Added yara_query module documentation, update yara_syntax_validator documentation & generated updated documentation markdown. [chrisr3d]

* Merge branch 'master' of github.com:MISP/misp-modules into chrisr3d_patch. [chrisr3d]

* Add: Added test files for yara to test yara library & potentially yara syntax. [chrisr3d]

* Add: Added imphash to input attribute types. [chrisr3d]

* Cosmetic output change. [Sascha Rommelfangen]

* Debug removed. [Sascha Rommelfangen]

* API changes reflected. [Sascha Rommelfangen]

* Merge pull request #253 from MISP/chrisr3d_patch. [Alexandre Dulaunoy]

  Validation of yara rules

* Merge branch 'master' of github.com:MISP/misp-modules into chrisr3d_patch. [chrisr3d]

* Merge pull request #251 from MISP/rommelfs-patch-4. [Raphaël Vinot]

  bug fix regarding leftovers between runs

* Bug fix regarding leftovers between runs. [Sascha Rommelfangen]

* Merge pull request #250 from SteveClement/btc. [Steve Clement]

  chg: [btc] Removed simple PoC for btc expansion.

* Merge pull request #249 from MISP/rommelfs-patch-3. [Steve Clement]

  added btc_steroids

* Added btc_steroids. [Sascha Rommelfangen]

* Merge pull request #248 from rommelfs/master. [Sascha Rommelfangen]

  Pull request for master

* Added btc_steroids to the list. [Sascha Rommelfangen]

* Initial version of a Bitcoin module. [Sascha Rommelfangen]

* Merge pull request #247 from SteveClement/btc. [Alexandre Dulaunoy]

  new: [module] Added very simple BitCoin expansion/hover module

* Merge pull request #245 from chrisr3d/master. [Alexandre Dulaunoy]

  YARA rules from hashes expansion module

* Updated list of modules in readme. [chrisr3d]

* Merge branch 'master' of github.com:MISP/misp-modules. [chrisr3d]

* Add: [documentation] osquery logo. [Alexandre Dulaunoy]

* Merge pull request #241 from 0xmilkmix/doc_osqueryexport. [Alexandre Dulaunoy]

  Added basic documentation for OS query

* Merge branch 'master' into doc_osqueryexport. [Alexandre Dulaunoy]

* Merge pull request #240 from 0xmilkmix/support_osquery_win_named_obj. [Alexandre Dulaunoy]

  super simple support for mutexes through winbaseobj in osquery 3.3

* Merge branch 'master' into support_osquery_win_named_obj. [Alexandre Dulaunoy]

* Merge pull request #242 from 0xmilkmix/module_writting. [Steve Clement]

  chg: [doc] Additional documentation for export module

* Documentation for export module. [milkmix]

* Super simple support for mutexes through winbaseobj in osquery 3.3. [milkmix]

* Added basic documentation. [milkmix]

* Merge pull request #239 from SteveClement/master. [Steve Clement]

  chg: [docs] Added some missing dependencies and instructions for virtualenv deployment

* Merge pull request #237 from 0xmilkmix/export_osquery. [Alexandre Dulaunoy]

  Export osquery

* Merge branch 'master' into export_osquery. [Julien Bachmann]

* Merge pull request #232 from CodeLineFi/master. [Alexandre Dulaunoy]

  macaddres.io module - Date conversion bug fixed

* Merge branch 'master' into master. [Alexandre Dulaunoy]

* Merge pull request #233 from chrisr3d/documentation. [Christian Studer]

  Modules documentation

* Merge branch 'master' of github.com:MISP/misp-modules into documentation. [chrisr3d]

* Updated documentation result file. [chrisr3d]

* Add: Added documentation for expansion modules. [chrisr3d]

* Add: Started adding logos on documentation for each module. [chrisr3d]

* Renamed directory to have consistency in names. [chrisr3d]

* Removed documentation about a module deleted from the repository. [chrisr3d]

* Merging readme. [chrisr3d]

* Merge branch 'master' of github.com:MISP/misp-modules into documentation. [chrisr3d]

* Merge branch 'master' of github.com:MISP/misp-modules into documentation. [chrisr3d]

* Merge branch 'master' of github.com:MISP/misp-modules into documentation. [chrisr3d]

* Merge branch 'master' of github.com:MISP/misp-modules into documentation. [chrisr3d]

* Merge branch 'master' of github.com:MISP/misp-modules into documentation. [chrisr3d]

* Merge branch 'master' of github.com:MISP/misp-modules into documentation. [chrisr3d]

* First try of documentation for import & export modules. [chrisr3d]

  - Providing information about the general purpose of
    the modules, their requirements, how to use them
    (if there are special features), some references
    about the format concerned or the vendors, and their
    input and output.
  - Documentation to be completed by additional fields
    of documentation and / or more detailed descriptions

* Added Documentation explanations on readme file. [chrisr3d]

* CSV import documentation first try. [chrisr3d]

* GoAML modules documentation first try. [chrisr3d]

* Updated README. Added a link to the integration tutorial. [Codelinefi-admin]

* Fixed a bug with wrong dates conversion. [Codelinefi-admin]

* Merge branch 'vulnersCom-master' [Alexandre Dulaunoy]

* Merge branch 'master' of https://github.com/vulnersCom/misp-modules into vulnersCom-master. [Alexandre Dulaunoy]

* Fixed getting of the Vulners AI score. [isox]

* Merge pull request #230 from lctrcl/master. [Alexandre Dulaunoy]

* Merge branch 'master' into master. [lctrcl]

* Merge pull request #229 from lctrcl/master. [Alexandre Dulaunoy]

  New vulners module added

* HotFix: Vulners AI score. [Igor Ivanov]

* Code cleanup and formatting. [Igor Ivanov]

* Added exploit information. [Igor Ivanov]

* Initial Vulners module PoC. [Igor Ivanov]

* Merge pull request #226 from CodeLineFi/master. [Alexandre Dulaunoy]

  New macaddress.io hover module added

* Macaddress.io hover module added. [Codelinefi-admin]

* Merge pull request #223 from chrisr3d/master. [Christian Studer]

* Merge branch 'master' of github.com:MISP/misp-modules. [chrisr3d]

* Merge pull request #222 from chrisr3d/master. [Christian Studer]

  Clean up + fix of some modules

* Merge branch 'master' of github.com:MISP/misp-modules. [chrisr3d]

* Merge pull request #221 from MISP/rommelfs-patch-2. [Alexandre Dulaunoy]

  fixed typo

* Fixed typo. [Sascha Rommelfangen]

  via #220

* Merge branch 'master' of github.com:MISP/misp-modules. [chrisr3d]

* Merge pull request #218 from surbo/patch-1. [Alexandre Dulaunoy]

  Update urlscan.py

* Update urlscan.py. [SuRb0]

  Added hash to the search so you can take advantage of the new file down load function on urlscan.io.  You can use this to pivot on file hashes and find out domains that hosting the same malicious file.

* Merge branch 'master' of github.com:MISP/misp-modules. [chrisr3d]

* Merge pull request #217 from threatsmyth/master. [Alexandre Dulaunoy]

  Add error handling for DNS failures, reduce imports, and simplify attribute comments

* Merge branch 'master' into master. [David J]

* Merge pull request #215 from threatsmyth/master. [Alexandre Dulaunoy]

  Create urlscan.py

* Add error handling for DNS failures, reduce imports, and simplify misp_comments. [David J]

* Create urlscan.py. [David J]

* Merge branch 'master' of github.com:MISP/misp-modules. [chrisr3d]

* Merge pull request #214 from chrisr3d/chrisr3d_patch. [Alexandre Dulaunoy]

  New module to check DBL Spamhaus

* Merge branch 'chrisr3d_patch' of github.com:chrisr3d/misp-modules. [chrisr3d]

* Add: Added DBL spamhaus module documentation and in expansion init file. [chrisr3d]

* Merge branch 'master' of github.com:MISP/misp-modules. [chrisr3d]

* Ta_import - bugfixes for TA 6.1. [Christophe Vandeplas]

* Merge pull request #210 from chrisr3d/master. [Christian Studer]

  Put the report location parsing in a try/catch statement as it is an optional field

* Merge pull request #209 from cvandeplas/master. [Christophe Vandeplas]

  ta_import - support for TheatAnalyzer 6.1

* Ta_import - support for TheatAnalyzer 6.1. [Christophe Vandeplas]

* Securitytrails.com expansion module added. [Alexandre Dulaunoy]

* Merge pull request #208 from sebdraven/dnstrails. [Alexandre Dulaunoy]

  module securitytrails

* Merge branch 'master' into dnstrails. [sebdraven]

* Merge pull request #206 from chrisr3d/master. [Alexandre Dulaunoy]

  Expansion module displaying SIEM signatures from a sigma rule

* Merge branch 'master' into master. [Alexandre Dulaunoy]

* Remove the never release Python code in Travis. [Alexandre Dulaunoy]

* Remove Python 3.4 and Python 3.7 added. [Alexandre Dulaunoy]

* Merge branch 'master' of github.com:MISP/misp-modules. [chrisr3d]

* Merge pull request #202 from SteveClement/master. [Alexandre Dulaunoy]

  Removed test modules from view

* - Removed test modules from view - Moved skeleton expansion module to it's proper place. [Steve Clement]

* Merge pull request #201 from chrisr3d/master. [Alexandre Dulaunoy]

  add: STIX2 pattern syntax validator

* Add: Experimental expansion module to display the SIEM signatures from a sigma rule. [chrisr3d]

* Add: stix2 pattern validator requirements. [chrisr3d]

* Add: STIX2 pattern syntax validator. [chrisr3d]

* Merge pull request #199 from SteveClement/master. [Alexandre Dulaunoy]

  Added (Multipage) PDF support to OCR Module, minor refactor

* - Reverted to <3.6 compatibility. [Steve Clement]

* - Fixed log output. [Steve Clement]

* - Forgot to import sys. [Steve Clement]

* - Added logger functionality for debug sessions. [Steve Clement]

* - content was already a wand.obj. [Steve Clement]

* Merge remote-tracking branch 'upstream/master' [Steve Clement]

* Threatanalyzer_import - order of category tuned. [Christophe Vandeplas]

* Merge branch 'master' of github.com:SteveClement/misp-modules. [Steve Clement]

* Merge branch 'master' into master. [Alexandre Dulaunoy]

* - Some more comments - Removed libmagic, wand can handle it better. [Steve Clement]

* - Set tornado timeout to 300 seconds. [Steve Clement]

* - Quick comment ToDo: Avoid using Magic in future releases. [Steve Clement]

* - added wand requirement - fixed missing return png byte-stream - move module import to handler to catch and  report errorz. [Steve Clement]

* - fixed typo move image back in scope. [Steve Clement]

* - Added initial PDF support, nothing is processed yet - Test to replace PIL with wand. [Steve Clement]

* Change type of status. [Sebdraven]

* Remove print. [Sebdraven]

* Last commit for release. [Sebdraven]

* Add logs. [Sebdraven]

* Add searching_stats. [Sebdraven]

* Add searching_stats. [Sebdraven]

* Correct key. [Sebdraven]

* Correct key. [Sebdraven]

* Correct param. [Sebdraven]

* Add searching domains. [Sebdraven]

* Add searching domains. [Sebdraven]

* Add return. [Sebdraven]

* Add logs. [Sebdraven]

* Add whois expand to test. [Sebdraven]

* Add whois expand to test. [Sebdraven]

* Correct index error. [Sebdraven]

* Error call functions. [Sebdraven]

* Add logs. [Sebdraven]

* Add logs. [Sebdraven]

* Add status_ok to true. [Sebdraven]

* Add logs. [Sebdraven]

* Add logs. [Sebdraven]

* Add logs. [Sebdraven]

* Add logs. [Sebdraven]

* Add logs. [Sebdraven]

* Correct out of bound returns. [Sebdraven]

* Correct key and return of functions. [Sebdraven]

* Add logs. [Sebdraven]

* Add logs. [Sebdraven]

* Correct typo. [Sebdraven]

* Test whois history. [Sebdraven]

* History whois dns. [Sebdraven]

* Correct typo. [Sebdraven]

* Rename misp modules. [Sebdraven]

* Add a test to check if the list is not empty. [Sebdraven]

* Add a test to check if the list is not empty. [Sebdraven]

* Add logs. [Sebdraven]

* Debug whois. [Sebdraven]

* Debug ipv4 or ipv6. [Sebdraven]

* Add debug. [Sebdraven]

* Debug. [Sebdraven]

* Change status. [Sebdraven]

* Change history dns. [Sebdraven]

* Add logs to debug. [Sebdraven]

* Correct call function. [Sebdraven]

* Add history mx and soa. [Sebdraven]

* Add history dns and handler exception. [Sebdraven]

* Add history dns. [Sebdraven]

* Switch type ip. [Sebdraven]

* Refactoring expand_whois. [Sebdraven]

* Correct typo. [Sebdraven]

* Add ipv6 and ipv4. [Sebdraven]

* Change type. [Sebdraven]

* Change type. [Sebdraven]

* Change loop. [Sebdraven]

* Add time sleep in each request. [Sebdraven]

* Control return of records. [Sebdraven]

* Add history ipv4. [Sebdraven]

* Add logs. [Sebdraven]

* Change categories. [Sebdraven]

* Concat results. [Sebdraven]

* Change name keys. [Sebdraven]

* Change return value. [Sebdraven]

* Add logs. [Sebdraven]

* Change errors. [Sebdraven]

* Add logs. [Sebdraven]

* Add expand whois. [Sebdraven]

* Typo. [Sebdraven]

* Add categories and comments. [Sebdraven]

* Add expand subdomains. [Sebdraven]

* Add expand subdomains. [Sebdraven]

* Change categories. [Sebdraven]

* Changes keys. [Sebdraven]

* Add status ! [Sebdraven]

* Add methods. [Sebdraven]

* Add expand domains. [Sebdraven]

* Add link pydnstrain in requirements. [Sebdraven]

* Add new module dnstrails. [Sebdraven]

* Merge pull request #198 from chrisr3d/master. [Alexandre Dulaunoy]

  Sigma syntax validator expansion module + some updates

* Updated README to add sigma & some other missing modules. [chrisr3d]

* Updated the list of modules (removed stiximport) [chrisr3d]

* Add: Sigma syntax validator expansion module. [chrisr3d]

  --> Checks sigma rules syntax
  - Updated the expansion modules list as well
  - Updated the requirements list

* Updated the list of expansion modules. [chrisr3d]

* Corrected typos and unused imports. [milkmix]

* Added support for scheduledtasks. [milkmix]

* Added support for service-displayname, regkey|value. [milkmix]

* Initial implementation supporting regkey. mutexes support waiting osquery table. [milkmix]

* Merge pull request #197 from sebdraven/onyphe_full_module. [Alexandre Dulaunoy]

  Onyphe full module

* Add return handle domains. [Sebdraven]

* Add search. [Sebdraven]

* Add domain to expand. [Sebdraven]

* Correct bugs. [Sebdraven]

* Add domain expansion. [Sebdraven]

* Add comment. [Sebdraven]

* Correct bugs. [Sebdraven]

* Correct comments. [Sebdraven]

* Add threat list expansion. [Sebdraven]

* Change method to concat methods. [Sebdraven]

* Set status after requests. [Sebdraven]

* Set status after requests. [Sebdraven]

* Add logs. [Sebdraven]

* Add logs. [Sebdraven]

* Add logs. [Sebdraven]

* Pep 8. [Sebdraven]

* Correct bug. [Sebdraven]

* Add datascan expansion. [Sebdraven]

* Add reverse infos. [Sebdraven]

* Add reverse infos. [Sebdraven]

* Add reverse infos. [Sebdraven]

* Add reverse infos. [Sebdraven]

* Add forward infos. [Sebdraven]

* Add comment of attributes. [Sebdraven]

* Add comment of attributes. [Sebdraven]

* Error loops. [Sebdraven]

* Error method. [Sebdraven]

* Error type. [Sebdraven]

* Error keys. [Sebdraven]

* Add expansion synscan. [Sebdraven]

* Change key access domains. [Sebdraven]

* Change add in results. [Sebdraven]

* Add logs. [Sebdraven]

* Correct error keys. [Sebdraven]

* Test patries expansion. [Sebdraven]

* Add onyphe full module. [Sebdraven]

* Add onyphe full module and code the stub. [Sebdraven]

* Merge pull request #194 from chrisr3d/master. [Alexandre Dulaunoy]

  Removed STIX1 related requirements to avoid version issues

* Merge branch 'master' of github.com:MISP/misp-modules. [chrisr3d]

* Merge pull request #193 from sebdraven/onyphe_module. [Alexandre Dulaunoy]

  Onyphe module

* Delete vcs.xml. [sebdraven]

* Correct codecov. [Sebdraven]

* Pep 8 compliant. [Sebdraven]

* Correct type of comments. [Sebdraven]

* Correct typo. [Sebdraven]

* Correct typo. [Sebdraven]

* Add domains forward. [Sebdraven]

* Add domains. [Sebdraven]

* Add targeting os. [Sebdraven]

* Add category for AS number. [Sebdraven]

* Change keys. [Sebdraven]

* Change type. [Sebdraven]

* Add category. [Sebdraven]

* Add as number with onyphe. [Sebdraven]

* Add as number with onyphe. [Sebdraven]

* Error indentation. [Sebdraven]

* Correct key in map result. [Sebdraven]

* Correct a bug. [Sebdraven]

* Add pastebin url imports. [Sebdraven]

* Add onyphe module. [Sebdraven]

* Updated requirements to avoid version issues in the MISP packer installation script. [chrisr3d]

* Update countrycode.py. [Andras Iklody]

* Add: mixing modules. [Alexandre Dulaunoy]

* Merge branch 'master' of github.com:MISP/misp-modules. [Alexandre Dulaunoy]

* Merge pull request #190 from chrisr3d/master. [Alexandre Dulaunoy]

  Updated csv import following our recent discussions

* Updated delimiter finder function. [chrisr3d]

* Add: Added user config to specify if there is a header in the csv to import. [chrisr3d]

* Merge branch 'master' of github.com:MISP/misp-modules. [chrisr3d]

* Merge pull request #189 from chrisr3d/master. [Andras Iklody]

  Using userConfig to define the header instead of moduleconfig

* Merge pull request #188 from cvandeplas/master. [Christophe Vandeplas]

  ta import  - noise removal

* Merge branch 'master' into master. [Christophe Vandeplas]

* Merge pull request #187 from cvandeplas/master. [Christophe Vandeplas]

  threatanalyzer_import - minor generic noise removal

* Threatanalyzer_import - minor generic noise removal. [Christophe Vandeplas]

* Ta import - more filter for pollution. [Christophe Vandeplas]

* Threatanalyzer_import - minor generic noise removal. [Christophe Vandeplas]

* Merge pull request #185 from cvandeplas/master. [Christophe Vandeplas]

  threatanalyzer_import - loads sample info + pollution fix

* Threatanalyzer_import - loads sample info + pollution fix. [Christophe Vandeplas]

* Merge pull request #184 from cvandeplas/master. [Christophe Vandeplas]

  threatanalyzer_import - fix regkey issue

* Threatanalyzer_import - fix regkey issue. [Christophe Vandeplas]

* Merge pull request #177 from TheDr1ver/patch-1. [Alexandre Dulaunoy]

  fix missing comma

* Fix missing comma. [Nick Driver]

  fix ip-dst and vulnerability input

* Merge pull request #176 from cudeso/master. [Alexandre Dulaunoy]

  Fix VMRay API access error

* Fix VMRay API access error. [Koen Van Impe]

  hotfix for the "Unable to access VMRay API" error

* Merge remote-tracking branch 'MISP/master' [Koen Van Impe]

* Merge pull request #173 from m3047/master. [Alexandre Dulaunoy]

  Add exception blocks for query errors.

* Add exception blocks for query errors. [Fred Morris]

* Merge pull request #170 from P4rs3R/patch-1. [Alexandre Dulaunoy]

  Improving regex (validating e-mail)

* Improving regex (validating e-mail) [x41\x43]

  Line 48:
  The previous regex ` ^[\w\.\+\-]+\@[\w]+\.[a-z]{2,3}$ ` matched only a small subset of valid e-mail address (e.g.: didn't match domain names longer than 3 chars or user@this-domain.de or user@multiple.level.dom) and needed to be with start (^) and end ($).
  This ` [a-zA-Z0-9!#$%&'*+\/=?^_`{|}~-]+(?:\.[a-zA-Z0-9!#$%&'*+\/=?^_`{|}~-]+)*@(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])? ` is not perfect (e.g: can't match oriental chars), but imho is much more complete.

  Regex tested with several e-mail addresses with Python 3.6.4 and Python 2.7.14 on Linux 4.14.

* Merge pull request #169 from chrisr3d/master. [Alexandre Dulaunoy]

  Updated GoAML import including Object References

* Clarified functions arguments using a class. [chrisr3d]

* Add: Added Object References in the objects imported. [chrisr3d]

* Merge pull request #168 from chrisr3d/goaml. [Alexandre Dulaunoy]

  GoAML import module & GoAML export updates

* Merge branch 'master' of github.com:MISP/misp-modules into goaml. [chrisr3d]

* Merge pull request #167 from chrisr3d/csvimport. [Alexandre Dulaunoy]

  Updated csvimport

* Merge branch 'csvimport' of github.com:chrisr3d/misp-modules into goaml. [chrisr3d]

* Removed print. [chrisr3d]

* Merge branch 'master' of github.com:MISP/misp-modules into csvimport. [chrisr3d]

* Merge pull request #165 from chrisr3d/goaml. [Alexandre Dulaunoy]

  fix: Added an object checking

* Add: added goamlimport. [chrisr3d]

* Fixed some details about the module output. [chrisr3d]

* Converting GoAML into MISPEvent. [chrisr3d]

* Now parsing all the transaction attributes. [chrisr3d]

* Add: Added dictionary to map aml types into MISP types. [chrisr3d]

* Typo. [chrisr3d]

* Merge branch 'master' of github.com:chrisr3d/misp-modules into aml_import. [chrisr3d]

* Merge pull request #164 from chrisr3d/master. [Alexandre Dulaunoy]

  Latest fixes to make GoAML export module work

* Add: Added an example file generated by GoAML export module. [chrisr3d]

* Added GoAML export module in description. [chrisr3d]

* Reading the entire document, to create a big dictionary containing the data, as a beginning. [chrisr3d]

* Add: new expansion module to check hashes against hashdd.com including NSLR dataset. [Alexandre Dulaunoy]

* Merge pull request #163 from chrisr3d/master. [Alexandre Dulaunoy]

  GoAML export

* Typo. [chrisr3d]

* Merge branch 'master' of github.com:MISP/misp-modules. [chrisr3d]

* Quick fix to the invalid hash types offered on all returned hashes, hopefully fixes #162. [Andras Iklody]

* Explicit name. [chrisr3d]

  Avoiding confusion with the coming import module for goaml

* Added "t_to" and "t_from" required fields: funds code & country. [chrisr3d]

* Added a required field & the latest attributes in transaction. [chrisr3d]

* Added report expected information fields. [chrisr3d]

* Simplified ObjectReference dictionary reading. [chrisr3d]

* Merge branch 'master' of github.com:MISP/misp-modules. [chrisr3d]

* Add: YARA syntax validator. [Alexandre Dulaunoy]

* Merge pull request #161 from eCrimeLabs/ecrimelabs_dev. [Alexandre Dulaunoy]

  Added Yara syntax validation expansion module

* Added Yara syntax validation expansion module. [Dennis Rand]

* Added some report information. [chrisr3d]

  Also changed the ObjectReference parser to replace
  all the if conditions by a dictionary reading

* Suporting the recent objects added to misp-objects. [chrisr3d]

  - Matching the aml documents structure
  - Some parts of the document still need to be added

* Wip: added location & signatory information. [chrisr3d]

* Merge branch 'master' of github.com:MISP/misp-modules into test. [chrisr3d]

* Merge pull request #157 from CenturyLinkCIRT/master. [Alexandre Dulaunoy]

  added csvimport to __init__.py

* Added csvimport to __init__.py. [Thomas Gardner]

* Add: CSV import module added. [Alexandre Dulaunoy]

* Outputting xml format. [chrisr3d]

  Also mapping MISP and GoAML types

* First tests for the GoAML export module. [chrisr3d]

* Merge pull request #156 from chrisr3d/master. [Alexandre Dulaunoy]

  CSV import

* Merge branch 'master' of github.com:MISP/misp-modules. [chrisr3d]

* 3.7-alpha removed. [Alexandre Dulaunoy]

* Updated delimiter finder method. [chrisr3d]

* Fixed data treatment & other updates. [chrisr3d]

* Updated delimiter parsing & data reading functions. [chrisr3d]

* First version of csv import module. [chrisr3d]

  - If more than 1 misp type is recognized, for each one an
    attribute is created

  - Needs to have header set by user as parameters of the module atm

  - Review needed to see the feasibility with fields that can create
    confusion and be interpreted both as misp type or attribute field
    (for instance comment is a misp type and an attribute field)

* Merge pull request #154 from cvandeplas/master. [Raphaël Vinot]

  added CrowdStrike Falcon Intel Indicators expansion module

* Added CrowdStrike Falcon Intel Indicators expansion module. [Christophe Vandeplas]

* Add: RBL added. [Alexandre Dulaunoy]

* Merge pull request #150 from chrisr3d/master. [Alexandre Dulaunoy]

  RBL check module

* Merge github.com:MISP/misp-modules. [chrisr3d]

* Merge pull request #149 from cvandeplas/master. [Alexandre Dulaunoy]

  Added ThreatAnalyzer sandbox import

* Added ThreatAnalyzer sandbox import. [Christophe Vandeplas]

  Experimental module - some parts should be migrated to

* Check an IPv4 address against known RBLs. [chrisr3d]

* Fix farsight_passivedns - rdata 404 not found. [Christophe Vandeplas]

* Added ThreatStream and PDF export. [Alexandre Dulaunoy]

* Merge branch 'robertnixon2003-master' + a small fix. [Alexandre Dulaunoy]

* Fix the __init__ import. [Alexandre Dulaunoy]

* Update threatStream_misp_export.py. [Robert Nixon]

* Updated __init__.py. [Robert Nixon]

  Added reference to new ThreatStream export module

* Added threatStream_misp_export.py. [Robert Nixon]

* Merge branch 'cvandeplas-master' [Alexandre Dulaunoy]

* Fixes missing init file in dnsdb library folder. [Christophe Vandeplas]

* New Farsight DNSDB Passive DNS expansion module. [Christophe Vandeplas]

* Merge branch 'master' of github.com:MISP/misp-modules. [Raphaël Vinot]

* Merge pull request #144 from attritionorg/patch-1. [Andras Iklody]

  minor touch-ups on error messages for user friendliness

* Minor touch-ups on error messages for user friendliness. [Jericho]

* Merge pull request #140 from cudeso/master. [Alexandre Dulaunoy]

  VulnDB Queries

* VulnDB Queries. [Koen Van Impe]

  Search on CVE at https://vulndb.cyberriskanalytics.com/
      https://www.riskbasedsecurity.com/
  Get extended CVE info, links + CPE

* Merge remote-tracking branch 'MISP/master' [Koen Van Impe]

* Add quick and dirty pdf export. [Raphaël Vinot]

* Merge pull request #139 from Rafiot/master. [Raphaël Vinot]

  fix: OpenIOC importer

* Merge pull request #135 from DomainTools/domaintools-patch-1. [Raphaël Vinot]

  Added code to allow 3rd party modules

* Added default parameter for new -m flag. [Viktor von Drakk]

* Added code to allow 3rd party modules. [Viktor von Drakk]

  The new '-m pip.module.name' feature allows a pip-installed module to be specified on the command line and then loaded into the available modules without having to copy-paste files into the appropriate directories of this package.

* Broken links fixed. [Alexandre Dulaunoy]

* ThreatConnect export module added. [Alexandre Dulaunoy]

* Merge pull request #133 from CenturyLinkCIRT/master. [Alexandre Dulaunoy]

  ThreatConnect export module

* Added threat_connect_export to export_mod.__init__ [Thomas Gardner]

* Added test files for threat_connect_export. [Thomas Gardner]

* Added threat_connect_export.py. [Thomas Gardner]

* Merge pull request #129 from seamustuohy/utf_hate. [Raphaël Vinot]

  Added support for malformed internationalized email headers

* Added support for malformed internationalized email headers. [seamus tuohy]

  When an emails contains headers that use Unicode without properly crafing
  them to comform to RFC-6323 the email import module would crash.
  (See issue #119 & issue #93)

  To address this I have added additional layers of encoding/decoding to
  any possibly internationalized email headers. This decodes properly
  formed and malformed UTF-8, UTF-16, and UTF-32 headers appropriately.
  When an unknown encoding is encountered it is returned as an 'encoded-word'
  per RFC2047.

  This commit also adds unit-tests that tests properly formed and malformed
  UTF-8, UTF-16, UTF-32, and CJK encoded strings in all header fields; UTF-8,
  UTF-16, and UTF-32 encoded message bodies; and emoji testing for headers
  and attachment file names.

* Merge branch 'master' into utf_hate. [seamus tuohy]

* Added unit tests for UTF emails. [seamus tuohy]

* OTX and ThreatCrowd added. [Alexandre Dulaunoy]

* Merge pull request #130 from chrisdoman/master. [Alexandre Dulaunoy]

  Add AlienVault OTX and ThreatCrowd Expansions

* Add AlienVault OTX and ThreatCrowd Expansions. [Chris Doman]

* Use proper version of PyMISP. [Raphaël Vinot]

* Update travis, fix open ioc import. [Raphaël Vinot]

* Merge pull request #122 from truckydev/master. [Alexandre Dulaunoy]

  Add tags on import with ioc import module

* Replace tab by space. [Tristan METAYER]

* Add a field for user to add tag for this import. [Tristan METAYER]

* Merge pull request #121 from truckydev/master. [Andras Iklody]

  If filename add iocfilename as attachment

* Typo correction. [Tristan METAYER]

* Add user config to not add file as attachement in a box. [Tristan METAYER]

* If filename add iocfilename as attachment. [Tristan METAYER]

* Merge pull request #118 from truckydev/master. [Alexandre Dulaunoy]

  Add indent field for export

* Add indent field for export. [Tristan METAYER]

* Merge pull request #115 from FloatingGhost/master. [Alexandre Dulaunoy]

  fix: Use the proper formatting method and not the horrible % one

* Missing expansion modules added in README. [Alexandre Dulaunoy]

* ThreatMiner added. [Alexandre Dulaunoy]

* Merge pull request #114 from kx499/master. [Alexandre Dulaunoy]

  ThreatMiner Expansion module

* Bug fixes. [kx499]

* Threatminer initial commit. [kx499]

* Cosmetic changes. [Raphaël Vinot]

* Merge pull request #111 from kx499/master. [Raphaël Vinot]

  Handful of changes to VirusTotal module

* Bug fixes, tweaks, and python3 learning curve :) [kx499]

* Initial commit of IPRep module. [kx499]

* Fixed spacing, addressed error handling for public api, added subdomains, and added context comment. [kx499]

* OpenIOC import module added. [Alexandre Dulaunoy]

* Add OpenIOC import module. [Raphaël Vinot]

* Merge pull request #109 from truckydev/master. [Alexandre Dulaunoy]

  add information about offline installation

* Add information about offline installation. [truckydev]

* Merge pull request #106 from truckydev/master. [Alexandre Dulaunoy]

  Lite export of an event

* Exclude internal reference. [Tristan METAYER]

* Add lite Export module. [Tristan METAYER]

* Merge pull request #100 from rmarsollier/master. [Alexandre Dulaunoy]

  Some improvements of virustotal plugin

* Some improvements of virustotal plugin. [rmarsollier]

* Merge pull request #96 from johestephan/master. [Raphaël Vinot]

  XForce Exchange v1 (alpha)

* Passed local run check. [Joerg Stephan]

* V1. [Joerg Stephan]

* Removed urrlib2. [Joerg Stephan]

* Python3 changes. [Joerg Stephan]

* Merged xforce exchange. [Joerg Stephan]

* XForce Exchange v1 (alpha) [Joerg Stephan]

* Merge pull request #56 from RichieB2B/ncsc-nl/mispjson. [Alexandre Dulaunoy]

  Simple import module to import MISP JSON format

* Updated description to reflect merging use case. [Richard van den Berg]

* Simple import module to import MISP JSON format. [Richard van den Berg]

* Merge pull request #92 from seamustuohy/duck_typing_failure. [Alexandre Dulaunoy]

  Email import no longer unzips major compressed text document formats.

* Email import no longer unzips major compressed text document formats. [seamus tuohy]

  Let this commit serve as a warning about the perils of duck typing.
  Word documents (docx,odt,etc) were being uncompressed when they were
  attached to emails. The email importer now checks a list of well known
  extensions and will not attempt to unzip them.

  It is stuck using a list of extensions instead of using file magic because
  many of these formats produce an application/zip mimetype when scanned.

* Merge branch 'master' of github.com:MISP/misp-modules. [Raphaël Vinot]

* Merge pull request #91 from Rafiot/master. [Raphaël Vinot]

  Improve email import module

* Keep zip content as binary. [Raphaël Vinot]

* Fix tests, cleanup. [Raphaël Vinot]

* Improve support of email attachments. [Raphaël Vinot]

  Related to #90

* Merge pull request #89 from Rafiot/fix_87. [Raphaël Vinot]

  Improve VT support.

* Standardised key checking. [Hannah Ward]

* Fixed checking for submission_names in VT JSON. [Hannah Ward]

* Update virustotal.py. [CheYenBzh]

* Merge branch 'master' of github.com:MISP/misp-modules. [Raphaël Vinot]

* Training materials updated + Cuckoo JSON import module was missing. [Alexandre Dulaunoy]

* Improve support of email importer if headers are missing. [Raphaël Vinot]

  Fix #88

* Remove python 3.3 support. [Raphaël Vinot]

* Fix python 3.6 support. [Raphaël Vinot]

* Make PEP8 happy. [Raphaël Vinot]

* Add email_import in the modules loaded by default. [Raphaël Vinot]

* Make PEP8 happy. [Raphaël Vinot]

* Fix failing test (bug in the mail parser?) [Raphaël Vinot]

* Add additional email parsing and tests. [seamus tuohy]

  Added additional attribute parsing and corresponding unit-tests.
  E-mail attachment and url extraction added in this commit. This includes
  unpacking zipfiles and simple password cracking of encrypted zipfiles.

* Fixed basic errors. [seamus tuohy]

* Merged with current master. [seamus tuohy]

* Merge pull request #85 from rmarsollier/master. [Raphaël Vinot]

  add libjpeg-dev as a dep to allow pillow to be installed succesfully

* Add libjpeg-dev as a dep to allow pillow to be installed succesfully. [robin.marsollier@conix.fr]

* GeoIP module added. [Alexandre Dulaunoy]

* Merge pull request #84 from MISP/amuehlem-master. [Raphaël Vinot]

  Fix PR

* Do not crash if the dat file is not available. [Raphaël Vinot]

* Fix path to config file. [Raphaël Vinot]

* Merge branch 'master' of https://github.com/amuehlem/misp-modules into amuehlem-master. [Raphaël Vinot]

* Added empty line to end of config file. [Andreas Muehlemann]

* Removed DEFAULT section from configfile. [Andreas Muehlemann]

* Fixed more typos. [Andreas Muehlemann]

* Fixed typo. [Andreas Muehlemann]

* Changed configparser from python2 to python3. [Andreas Muehlemann]

* Updated missing parenthesis. [Andreas Muehlemann]

* Merge branch 'geoip_country' [Andreas Muehlemann]

* Removed unneeded config option for misp. [Andreas Muehlemann]

* Removed debug message. [Andreas Muehlemann]

* Added config option to geoip_country.py. [Andreas Muehlemann]

* Added pygeoip to the REQUIREMENTS list. [Andreas Muehlemann]

* Updated geoip_country to __init__.py. [Andreas Muehlemann]

* Added geoip_country.py. [Andreas Muehlemann]

* Better error reporting. [Raphaël Vinot]

* Catch exception. [Raphaël Vinot]

* Add reverse lookup. [Raphaël Vinot]

* Refactoring of domaintools expansion module. [Raphaël Vinot]

* Merge branch 'master' of github.com:MISP/misp-modules. [Raphaël Vinot]

* Merge pull request #83 from stoep/master. [Alexandre Dulaunoy]

  Added cuckooimport.py

* Added cuckooimport.py. [Ubuntu]

* DomainTools module added. [Alexandre Dulaunoy]

* Remove domaintools tests. [Raphaël Vinot]

* Add test for domaintools. [Raphaël Vinot]

* Merge pull request #78 from deralexxx/patch-2. [Alexandre Dulaunoy]

  Update README.md

* Update README.md. [Alexander J]

  mentioning import / export modules

* Merge pull request #76 from deralexxx/patch-1. [Alexandre Dulaunoy]

  Update README.md

* Update README.md. [Alexander J]

* Merge pull request #75 from Rafiot/domtools. [Raphaël Vinot]

  Add Domain Tools module

* Update requirements list. [Raphaël Vinot]

* Add domaintools to the import list. [Raphaël Vinot]

* Fix Typo. [Raphaël Vinot]

* Add domain profile and reputation. [Raphaël Vinot]

* Add more comments. [Raphaël Vinot]

* Fix typo. [Raphaël Vinot]

* Remove json.dumps. [Raphaël Vinot]

* Avoid passing None in comments. [Raphaël Vinot]

* Add comments to fields when possible. [Raphaël Vinot]

* Add initial Domain Tools module. [Raphaël Vinot]

* Merge pull request #74 from cudeso/master. [Raphaël Vinot]

  Extra VTI detections

* Merge remote-tracking branch 'MISP/master' [Koen Van Impe]

* Update README.md. [Raphaël Vinot]

* Merge pull request #73 from FloatingGhost/master. [Raphaël Vinot]

  Use SpooledTemp, not NamedTemp file

* Use git for everything we can. [Hannah Ward]

* Ok we'll use the dep from misp-stix-converter. Surely this'll work? [Hannah Ward]

* Use the CIRCL pymisp. Silly @rafiot ;) [Hannah Ward]

* Travis should now use the master branch. [Hannah Ward]

* Maybe it'll take the git repo now? [Hannah Ward]

* Added pymisp to reqs. [Hannah Ward]

* Don't cache anything pls travis. [Hannah Ward]

* Removed unneeded modules. [Hannah Ward]

* Use SpooledTemp, not NamedTemp file. [Hannah Ward]

* VMRay import module added. [Alexandre Dulaunoy]

* Merge pull request #72 from FloatingGhost/master. [Raphaël Vinot]

  Migrated stiximport to use misp-stix-converter

* Moved to misp_stix_converter. [Hannah Ward]

* Merge pull request #70 from cudeso/master. [Raphaël Vinot]

  Submit malware samples

* Extra VTI detections. [Koen Van Impe]

* Submit malware samples. [Koen Van Impe]

  _submit now includes malware samples (zipped content from misp)
  _import checks when no vti_results are returned + bugfix

* Fix STIX import module. [Raphaël Vinot]

* Multiple clanges in the vmray modules. [Raphaël Vinot]

  * Generic fix to load modules requiring a local library
  * Fix python3 support
  * PEP8 related cleanups

* Merge pull request #68 from cudeso/master. [Andras Iklody]

  VMRay Import & Submit module

* VMRay Import & Submit module. [Koen Van Impe]

  * First commit
  * No support for archives (yet) submit

* Merge pull request #59 from rgraf/master. [Alexandre Dulaunoy]

  label replaced by text, which is existing attribute

* Label replaced by text, which is existing attribute. [Roman Graf]

* Adding basic test mockup. [seamus tuohy]

* Adding more steps to module testing. [seamus tuohy]

* Added attachment and url support. [seamus tuohy]

* Added email meta-data import module. [seamus tuohy]

  This email meta-data import module collects basic meta-data from an e-mail
  and populates an event with it. It populates the email subject, source
  addresses, destination addresses, subject, and any attachment file names.
  This commit also contains unit-tests for this module as well as updates to
  the readme. Readme updates are additions aimed to make it easier for
  outsiders to build modules.

* Merge pull request #58 from rgraf/master. [Alexandre Dulaunoy]

  Added expansion for Wikidata.

* Added expansion for Wikidata. Analyst can query Wikidata by label to get additional information for particular term. [Roman Graf]

* Merge pull request #55 from amuehlem/reversedns. [Raphaël Vinot]

  added new module reversedns.py, added reversedns to __init__.py

* Added new module reversedns.py, added reversedns to __init__.py. [Andreas Muehlemann]

* Merge pull request #53 from MISP/Rafiot-patch-1. [Alexandre Dulaunoy]

  Dump host info as text

* Dump host info as text. [Raphaël Vinot]

* Fix typo. [Raphaël Vinot]

* Merge pull request #52 from Rafiot/master. [Alexandre Dulaunoy]

  Add simple Shodan module

* Add simple Shodan module. [Raphaël Vinot]

* Merge pull request #49 from FloatingGhost/master. [Alexandre Dulaunoy]

  Removed useless pickle storage of stiximport

* Removed useless pickle storage of stiximport. [Hannah Ward]

* Create LICENSE. [Alexandre Dulaunoy]

* Update README.md. [Andras Iklody]

* Typo fixed. [Alexandre Dulaunoy]

* CEF export module added. [Alexandre Dulaunoy]

* Cef_export module added. [Alexandre Dulaunoy]

* Merge pull request #47 from FloatingGhost/CEF_Export. [Alexandre Dulaunoy]

  CEF export, fixes in CountryCode, virustotal

* Removed silly subdomain module. [Hannah Ward]

* Added CEF export module. [Hannah Ward]

* Now searches within observable_compositions. [Hannah Ward]

* Removed calls to print. [Hannah Ward]

* Added body.json to gitignore. [Hannah Ward]

* Added virustotal tests. [Hannah Ward]

* CountryCode JSON now is only grabbed once per server run. [Hannah Ward]

* Merge branch 'master' of github.com:MISP/misp-modules. [Raphaël Vinot]

* Merge pull request #46 from Rafiot/master. [Raphaël Vinot]

  Make misp-modules really asynchronous

* Add timeout for the modules, cleanup. [Raphaël Vinot]

* Fix python 3.3 and 3.4. [Raphaël Vinot]

* Make misp-modules really asynchronous. [Raphaël Vinot]

* Improve tornado parallel. [Raphaël Vinot]

* Coroutine decorator added to post handler. [Alexandre Dulaunoy]

* -d option added - enabling debug on queried modules. [Alexandre Dulaunoy]

* New modules added to __init__ [Alexandre Dulaunoy]

* README updated for the new modules. [Alexandre Dulaunoy]

* Merge pull request #45 from FloatingGhost/master. [Alexandre Dulaunoy]

  2 new modules -- VirusTotal and CountryCode

* Modified readme with virustotal/countrycode. [Hannah Ward]

* Added virustotal module. [Hannah Ward]

* Merge branch 'master' of https://github.com/MISP/misp-modules. [Hannah Ward]

* Merge pull request #44 from Rafiot/travis. [Alexandre Dulaunoy]

  Add coverage, update logging

* Add coverage, update logging. [Raphaël Vinot]

* Merge pull request #43 from FloatingGhost/master. [Alexandre Dulaunoy]

  StixImport now uses TemporaryFile rather than a named file in /tmp

* Improved virustotal module. [Hannah Ward]

* Added countrycode, working on virustotal. [Hannah Ward]

* Added lookup by country code. [Hannah Ward]

* Merge branch 'master' of https://github.com/MISP/misp-modules. [Hannah Ward]

* Fix a link to the STIX import module reference. [Alexandre Dulaunoy]

* Stiximport now uses temporary files to store stix data. [Hannah Ward]

  Set max size in config, in bytes

* Merge pull request #42 from MISP/pr/41. [Alexandre Dulaunoy]

  Cleanup on the stix import module

* Merge remote-tracking branch 'origin/master' into pr/41. [Raphaël Vinot]

* Add info about the import modules. [Alexandre Dulaunoy]

* Make PEP8 happy \o/ [Raphaël Vinot]

* Move stiximport.py to misp_modules/modules/import_mod/ [Raphaël Vinot]

* There was a missing comma. [Hannah Ward]

* Merge branch 'master' of https://github.com/MISP/misp-modules. [Hannah Ward]

* Merge branch 'master' of github.com:MISP/misp-modules. [Alexandre Dulaunoy]

* Merge pull request #40 from Rafiot/master. [Alexandre Dulaunoy]

  Remove bin script, use cleaner way. Fix last commit.

* Remove bin script, use cleaner way. Fix last commit. [Raphaël Vinot]

* Merge pull request #39 from Rafiot/master. [Alexandre Dulaunoy]

  Use entry_points instead of scripts in the install.

* Use entry_points instead of scripts. [Raphaël Vinot]

* Pip --upgrade must be always called (to have modules updated) [Alexandre Dulaunoy]

* Added STIX to setup.py. [Hannah Ward]

* Added STIX to reqs. [Hannah Ward]

* Merge branch 'stix_import' [Hannah Ward]

* Added tests, also disregards related_observables. Because they're useless. [Hannah Ward]

* Fixed observables within an indicator not being added. [Hannah Ward]

* Stiximport will now consume campaigns. [Hannah Ward]

* Stiximport will now identify file hashes. [Hannah Ward]

* I can't spell. [Hannah Ward]

* Added STIXImport to readme. [Hannah Ward]

* Threat actors now get imported by stix. [Hannah Ward]

* Added docs to stiximport. [Hannah Ward]

* Added stix import -- works for IPs/Domains. [Hannah Ward]

* Update to the DNS module to support domain|ip. [iglocska]

* Small change to the skeleton export. [iglocska]

* Merge remote-tracking branch 'origin/import-test' [iglocska]

* Added test export module. [Iglocska]

* Merge branch 'master' of github.com:MISP/misp-modules. [Alexandre Dulaunoy]

* Merge pull request #37 from Rafiot/master. [Raphaël Vinot]

  Update documentation.

* Update documentation. [Raphaël Vinot]

  Fix https://github.com/MISP/MISP/issues/1424

* Merge branch 'import-test' of github.com:MISP/misp-modules into import-test. [Alexandre Dulaunoy]

* Merge pull request #36 from Rafiot/import-test. [Alexandre Dulaunoy]

  Pass the server port as integer to the uwhois client

* Pass the server port as integer to the uwhois client. [Raphaël Vinot]

* Merge pull request #35 from Rafiot/import-test. [Alexandre Dulaunoy]

  Add whois module

* Add whois module. [Raphaël Vinot]

* First version of an Optical Character Recognition (OCR) module for MISP. [Alexandre Dulaunoy]

* First version of the import skeleton. [Iglocska]

* Added simple import skeleton. [Iglocska]

* Merge pull request #33 from Rafiot/master. [Raphaël Vinot]

  fix: run the server as "python3 misp-modules"

* Added category to the return format description. [Iglocska]

* Merge pull request #31 from treyka/patch-1. [Alexandre Dulaunoy]

  Refine the installation procedure

* Refine the installation procedure. [Trey Darley]

  Tweak this to make it more inline with the MISP installation docs, start misp-modules at startup via /etc/rc.local

* Install documentation updated. [Alexandre Dulaunoy]

* Merge pull request #28 from Rafiot/pip. [Alexandre Dulaunoy]

  Make it a package

* Also run travis tests on the system-wide instance. [Raphaël Vinot]

* Fix typos in the readme. [Raphaël Vinot]

* Fix travis. [Raphaël Vinot]

* Make sure misp-modules can be launched from anywhere. [Raphaël Vinot]

* Proper testcases. [Raphaël Vinot]

* Make it a package. [Raphaël Vinot]

* Merge pull request #29 from iglocska/master. [Alexandre Dulaunoy]

  Added skeleton structure for new modules

* Added skeleton structure for new modules. [Iglocska]

* Fixed a bug introduced by previous commit if started from the current directory. [Alexandre Dulaunoy]

* Merge pull request #26 from Rafiot/master. [Alexandre Dulaunoy]

  Automatic chdir when the modules are started

* Automatic chdir when the modules are started. [Raphaël Vinot]

* Merge pull request #25 from eu-pi/eupi_expansion_fix. [Alexandre Dulaunoy]

  [EUPI] Fix expansion for empty EUPI response

* [EUPI] Fix expansion for empty EUPI response. [Rogdham]

  Offer no enrichment instead of displaying an error message

* Merge pull request #24 from eu-pi/eupi_hover. [Alexandre Dulaunoy]

  [EUPI] Change module for a simple hover status

* [EUPI] Simplify hover. [Rogdham]

* Merge pull request #23 from Rafiot/master. [Raphaël Vinot]

  [EUPI] Return error message if unknown

* [EUPI] Return error message is unknown. [Raphaël Vinot]

* Merge pull request #22 from Rafiot/master. [Raphaël Vinot]

  [EUPI] Do not return empty results

* [EUPI] Do not return empty results. [Raphaël Vinot]

* ASN History added. [Alexandre Dulaunoy]

* Merge pull request #21 from Rafiot/master. [Raphaël Vinot]

  [ASN description] Fix input type

* [ASN description] Fix input type. [Raphaël Vinot]

* Merge pull request #20 from Rafiot/master. [Raphaël Vinot]

  Add ASN Description expansion module

* Add ASN Description expansion module. [Raphaël Vinot]

* Merge pull request #19 from Rafiot/master. [Raphaël Vinot]

  Fix last commit

* Fix last commit. [Raphaël Vinot]

* Merge pull request #18 from Rafiot/master. [Raphaël Vinot]

  Improve rendering of IP ASN

* Improve rendering of IP ASN. [Raphaël Vinot]

* Merge pull request #17 from Rafiot/master. [Raphaël Vinot]

  Fix again IPASN module

* Fix again IPASN module. [Raphaël Vinot]

* Merge pull request #16 from Rafiot/master. [Raphaël Vinot]

  Fix IPASN module

* Fix IPASN module. [Raphaël Vinot]

* Ipasn module added. [Alexandre Dulaunoy]

* Merge pull request #15 from Rafiot/master. [Alexandre Dulaunoy]

  Add IPASN history module

* Add IPASN history module. [Raphaël Vinot]

* Merge pull request #14 from eu-pi/listen-addr. [Alexandre Dulaunoy]

  Add option to specify listen address

* Add option to specify listen address. [Rogdham]

* EUPI module added. [Alexandre Dulaunoy]

* Merge pull request #13 from Rafiot/master. [Raphaël Vinot]

  Fix eupi module

* Fix eupi module. [Raphaël Vinot]

* Merge pull request #12 from Rafiot/master. [Raphaël Vinot]

  Add EUPI module

* Add redis server. [Raphaël Vinot]

* Add EUPI module. [Raphaël Vinot]

* Skip modules that cannot import. [Alexandre Dulaunoy]

* Skip dot files. [Alexandre Dulaunoy]

* Value is not required. [Alexandre Dulaunoy]

* Cache helper added. [Alexandre Dulaunoy]

  The cache helper is a simple helper to cache data
  in Redis back-end. The format in the cache is the following:
  m:<module name>:sha1(key) -> value. Default expiration is 86400 seconds.

* Skeleton for misp-modules helpers added. [Alexandre Dulaunoy]

  Helpers will support modules with basic functionalities
  like caching or alike.

* Option -p added to specify the TCP port of the misp-modules server. [Alexandre Dulaunoy]

* Intelmq req. removed. [Alexandre Dulaunoy]

* Argparse used for the test mode. [Alexandre Dulaunoy]

* Deleted. [Alexandre Dulaunoy]

* Intelmq is an experimental module (not production ready) [Alexandre Dulaunoy]

* Merge pull request #11 from Rafiot/master. [Raphaël Vinot]

  Fix test mode

* Fix test mode. [Raphaël Vinot]

* Fix install commands. [Raphaël Vinot]

* Add Travis logo. [Raphaël Vinot]

* Merge pull request #10 from Rafiot/travis. [Raphaël Vinot]

  Add basic travis file

* Add basic travis file. [Raphaël Vinot]

* Merge pull request #9 from Rafiot/master. [Alexandre Dulaunoy]

  Please PEP8 on all expansions

* Merge branch 'master' of https://github.com/MISP/misp-modules. [Raphaël Vinot]

* Merge pull request #8 from aaronkaplan/master. [Alexandre Dulaunoy]

  initial example of intelmq connector/enrichtment. Need to change to u…

* Initial example of intelmq connector/enrichtment. Need to change to use the eventDB RESTful API, not the postgresql DB. [aaronkaplan]

* Update README.md. [Raphaël Vinot]

* Dns module test with option added. [Alexandre Dulaunoy]

* New modules added. [Alexandre Dulaunoy]

* Dns MISP module - option to specify nameserver added. [Alexandre Dulaunoy]

* Slides reference added. [Alexandre Dulaunoy]

* Add missing requirements. [Alexandre Dulaunoy]

* Merge pull request #7 from Rafiot/master. [Alexandre Dulaunoy]

  Make loader more flexible

* Make PEP8 happy. [Raphaël Vinot]

* Add CIRCL pssl module. [Raphaël Vinot]

* Make loader more flexible. [Raphaël Vinot]

* First module to test the freetext import functionality. [Alexandre Dulaunoy]

* CIRCL Passive DNS output attributes updated. [Alexandre Dulaunoy]

* PyPDNS requirement added. [Alexandre Dulaunoy]

* CIRCL Passive DNS added. [Alexandre Dulaunoy]

* Tests updated to include CIRCL passive dns. [Alexandre Dulaunoy]

* Test file for passivetotal updated. [Alexandre Dulaunoy]

* Merge pull request #5 from passivetotal/master. [Alexandre Dulaunoy]

  Rewrote the entire PassiveTotal extension

* Rewrote the entire PassiveTotal extension. [Brandon Dixon]

* Return a text attribute for an hover only module. [Alexandre Dulaunoy]

* How to start MISP modules. [Alexandre Dulaunoy]

* 2.4.28 includes misp modules by default. [Alexandre Dulaunoy]

* Types are now described. [Alexandre Dulaunoy]

* Debug removed. [Alexandre Dulaunoy]

* Convert the base64 to ascii. [Iglocska]

* Module-type added as default. [Alexandre Dulaunoy]

* Return base64 value of the archived data. [Alexandre Dulaunoy]

* Merge pull request #2 from iglocska/master. [Alexandre Dulaunoy]

  Some changes to the sourcecache expansion

* Merge branch 'alternate_response' [Iglocska]

* Some changes to the sourcecache expansion. [Iglocska]

  - return attachment or malware sample

* Cve module tests added. [Alexandre Dulaunoy]

* CVE hover expansion module. [Alexandre Dulaunoy]

  An hover module is a module returning a JSON that can be used
  as hover element in the MISP UI.

* Sourcecache module includes the metadata config. [Alexandre Dulaunoy]

* README updated to reflect config parameters changes. [Alexandre Dulaunoy]

* Removed unused attributes. [Alexandre Dulaunoy]

* Sample JSON files reflecting config changes. [Alexandre Dulaunoy]

* Config parameters are now exposed via the meta information. [Alexandre Dulaunoy]

  config uses a specific list of values exposed via the
  introspection of the module. config is now passed as an additional
  dictionary to the request. MISP attributes include only MISP attributes.

* Sourcecache module added. [Alexandre Dulaunoy]

* A minimal caching module added to cache link or url from MISP. [Alexandre Dulaunoy]

* Typo fixed + meta output. [Alexandre Dulaunoy]

* Minimal functions requirements updated + PR request. [Alexandre Dulaunoy]

* Exclude dot files from modules list to be loaded. [Alexandre Dulaunoy]

* Example of module introspection including meta information. [Alexandre Dulaunoy]

* Module meta added to return version, description and author per module. [Alexandre Dulaunoy]

* Authentication notes added. [Alexandre Dulaunoy]

* Passivetotal module added. [Alexandre Dulaunoy]

* First version of a passivetotal MISP expansion module. [Alexandre Dulaunoy]

* Default DNS updated. [Alexandre Dulaunoy]

* Add a note regarding error codes. [Alexandre Dulaunoy]

* Handling of error added. [Alexandre Dulaunoy]

* Merge pull request #1 from Rafiot/master. [Alexandre Dulaunoy]

  Make PEP8 happy.

* Make PEP8 happy. [Raphaël Vinot]

* Output updated (type of module added) [Alexandre Dulaunoy]

* Add a version per default. [Alexandre Dulaunoy]

* Add type per module. [Alexandre Dulaunoy]

* Format updated following Andras updates. [Alexandre Dulaunoy]

* Default var directory added. [Alexandre Dulaunoy]

* Python pip REQUIREMENTS file added. [Alexandre Dulaunoy]

* Merge branch 'master' of https://github.com/MISP/misp-modules. [Iglocska]

* Minimal logging added to the server. [Alexandre Dulaunoy]

* Debug messages removed. [Alexandre Dulaunoy]

* Minimal documentation added. [Alexandre Dulaunoy]

* Curl is now silent. [Alexandre Dulaunoy]

* Changed the output format to include all matching attribute types. [Iglocska]

  - changed the output format to give us a bit more flexibility
    - return an array of results
    - return the valid misp attribute types for each result

* Basic test cases added. [Alexandre Dulaunoy]

* MISP dns expansion module. [Alexandre Dulaunoy]

* First version of a web services to provide ReST API to MISP expansion services. [Alexandre Dulaunoy]


