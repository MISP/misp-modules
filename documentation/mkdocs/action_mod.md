
#### [CrowdStrike IOC Publish](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/action_mod/crowdstrike_ioc_publish.py)

<img src=../logos/crowdstrike.png height=60>

Create and renew module-owned Falcon custom IOCs from MISP event and object attributes.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/action_mod/crowdstrike_ioc_publish.py)]

- **features**:
>Publishes to_ids MD5, SHA-256, domain and IP attributes, including attributes in objects. Requires explicit host-group or global scope. Existing IOCs are updated only when both their source and module ownership tag match; foreign IOCs are left unchanged. Credentials come from server-side CROWDSTRIKE_CLIENT_ID and CROWDSTRIKE_CLIENT_SECRET environment variables. Supports expiration, dry runs and per-indicator outcomes. See the [usage guide](https://github.com/MISP/misp-modules/blob/main/documentation/action_mod/crowdstrike_ioc_publish.md).

- **config**:
>{'params': {'region': {'type': 'string', 'description': 'Falcon region: us1, us2 or eu1', 'value': 'us1'}, 'source': {'type': 'string', 'description': 'Stable ownership namespace, unique to this MISP publisher', 'value': 'misp-modules'}, 'action': {'type': 'string', 'description': 'detect or prevent (prevent is restricted to file hashes)', 'value': 'detect'}, 'severity': {'type': 'string', 'description': 'INFORMATIONAL, LOW, MEDIUM, HIGH or CRITICAL', 'value': 'MEDIUM'}, 'platforms': {'type': 'string', 'description': 'Comma-separated windows, mac and/or linux', 'value': 'windows,mac,linux'}, 'host_groups': {'type': 'string', 'description': 'Comma-separated Falcon host-group IDs (32 hexadecimal characters)'}, 'apply_globally': {'type': 'string', 'description': 'true applies across the tenant; otherwise host_groups is required', 'value': 'false'}, 'expiration_days': {'type': 'string', 'description': 'Days from this publication until expiration (1-365)', 'value': '30'}, 'dry_run': {'type': 'string', 'description': 'true returns planned payloads without authenticating or publishing', 'value': 'false'}}, 'blocking': True, 'support_filters': False, 'expect_misp_core_format': True}

- **input**:
>MISP events in standard, bare or legacy format, supplied in workflow data.

- **output**:
>Publishing summary and per-indicator outcomes; an error signals incomplete publication.

- **references**:
>https://www.falconpy.io/Service-Collections/IOC.html

- **requirements**:
> - crowdstrike-falconpy
> - Falcon IOC Management Read/Write API scopes

-----

#### [Matrix](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/action_mod/matrix.py)

Send a message to an unencrypted Matrix room.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/action_mod/matrix.py)]

- **features**:
>Renders Jinja2 templates using matchingData when present, otherwise data, with a JSON fallback. Sends plain-text m.room.message events using a bot access token. The bot must already be a room member with permission to send messages. End-to-end encrypted rooms and HTML/Markdown formatting are unsupported. See the [usage guide](https://github.com/MISP/misp-modules/blob/main/documentation/action_mod/matrix.md).

- **config**:
>{'params': {'matrix_homeserver': {'type': 'string', 'description': 'The Matrix homeserver base URL, including scheme and optional path prefix', 'value': 'https://matrix.example.org'}, 'bot_access_token': {'type': 'string', 'description': 'Access token for a Matrix bot that has joined the room'}, 'room_id': {'type': 'string', 'description': 'The unencrypted room ID (starting with !), not a room alias'}, 'message_template': {'type': 'large_string', 'description': 'Jinja2 template for the plain-text message; leave empty to send the workflow data as JSON', 'value': 'MISP event: {{ Event.info }}', 'jinja_supported': True}}, 'blocking': False, 'support_filters': True, 'expect_misp_core_format': False}

- **input**:
>Workflow data or matchingData, and an optional Jinja2 message template.

- **output**:
>Boolean success; errors indicate an unsuccessful or unacknowledged send.

- **references**:
>https://spec.matrix.org/latest/client-server-api/#put_matrixclientv3roomsroomidsendeventtypetxnid

- **requirements**:
>requests

-----

#### [Mattermost](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/action_mod/mattermost.py)

Simplistic module to send message to a Mattermost channel.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/action_mod/mattermost.py)]

- **features**:
>

- **config**:
>{'params': {'mattermost_hostname': {'type': 'string', 'description': 'The Mattermost domain or URL', 'value': 'example.mattermost.com'}, 'bot_access_token': {'type': 'string', 'description': 'Access token generated when you created the bot account'}, 'channel_id': {'type': 'string', 'description': 'The channel you added the bot to'}, 'message_template': {'type': 'large_string', 'description': 'The template to be used to generate the message to be posted', 'value': 'The **template** will be rendered using *Jinja2*!', 'jinja_supported': True}}, 'blocking': False, 'support_filters': True, 'expect_misp_core_format': False}

-----

#### [Nextcloud talk](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/action_mod/nextcloud_talk.py)

Simplistic module to send a message to a Nextcloud talk conversation.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/action_mod/nextcloud_talk.py)]

- **features**:
>

- **config**:
>{'params': {'nextcloud_baseurl': {'type': 'string', 'description': 'The Nexctloud domain or URL', 'value': 'https://example.nextcloud.org:443'}, 'nextcloud_app_uuid_login': {'type': 'string', 'description': 'The nextcloud username'}, 'app_access_token': {'type': 'string', 'description': 'The nextcloud application token'}, 'nextcloud_conversation_token': {'type': 'string', 'description': 'The token of the conversation the message should be sent to'}, 'message_template': {'type': 'large_string', 'description': 'The template to be used to generate the message to be posted', 'value': 'The **template** will be rendered using *Jinja2*!', 'jinja_supported': True}}, 'blocking': False, 'support_filters': True, 'expect_misp_core_format': False}

-----

#### [OSQuery Pack Publish](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/action_mod/osquery_pack_publish.py)

<img src=../logos/osquery.png height=60>

Publish a MISP query pack to a configured local osquery pack directory.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/action_mod/osquery_pack_publish.py)]

- **features**:
>Atomically publishes a named pack under OSQUERY_PACK_DIRECTORY. Defaults to dry run; existing packs require explicit overwrite. Reuses the export's platform selectors, IDS filtering and bounded scan paths. Publication does not execute queries or reload osquery. See the [usage guide](https://github.com/MISP/misp-modules/blob/main/documentation/action_mod/osquery_pack_publish.md).

- **config**:
>{'params': {'pack_name': {'type': 'string', 'description': 'Required: pack basename, letters/digits/_/- only'}, 'interval': {'type': 'string', 'description': 'Query interval in seconds', 'value': '3600'}, 'scan_path': {'type': 'string', 'description': 'Absolute osquery file path pattern for file scans'}, 'dry_run': {'type': 'string', 'description': 'Preview without writing files', 'value': 'true'}, 'overwrite': {'type': 'string', 'description': 'Replace the complete named pack with this snapshot', 'value': 'false'}}, 'blocking': True, 'support_filters': False, 'expect_misp_core_format': True}

- **input**:
>Selected MISP events and object attributes in workflow data.

- **output**:
>Publication status, pack content, counts, provenance and content SHA-256.

- **references**:
>https://osquery.readthedocs.io/en/stable/deployment/configuration/#query-packs

- **requirements**:
>OSQUERY_PACK_DIRECTORY on the module server; filesystem pack distribution and config reload

-----

#### [QRadar Reference Set Publish](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/action_mod/qradar_reference_set_publish.py)

Publish typed MISP indicators to an existing QRadar reference set and explicit domain.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/action_mod/qradar_reference_set_publish.py)]

- **features**:
>Adds or refreshes IDS-marked event and object indicators through reference_data_collections/set_entries. Requires an existing reference-set ID and explicit domain ID, validates the target entry type and checks each write acknowledgement. Supports credential-free dry runs and reports partial failures. Set expiry remains controlled by QRadar. Credentials come from the module server environment. See the [usage guide](https://github.com/MISP/misp-modules/blob/main/documentation/action_mod/qradar_reference_set_publish.md).

- **config**:
>{'params': {'reference_set_id': {'type': 'string', 'description': 'Required: existing QRadar reference-set numeric ID'}, 'domain_id': {'type': 'string', 'description': 'Required: numeric domain ID (0 is Default Domain), or SHARED'}, 'indicator_type': {'type': 'string', 'description': 'ipv4, ipv6, domain, url, md5, sha1, sha256 or sha512', 'value': 'ipv4'}, 'source': {'type': 'string', 'description': 'QRadar entry source label', 'value': 'misp-modules'}, 'dry_run': {'type': 'string', 'description': 'true previews entry payloads without network access', 'value': 'false'}}, 'blocking': True, 'support_filters': False, 'expect_misp_core_format': True}

- **input**:
>Selected MISP events and object attributes in workflow data.

- **output**:
>Counts and per-value created, updated, planned or failed outcomes with MISP provenance.

- **references**:
> - https://ibmsecuritydocs.github.io/qradar_api_20.0/20.0--reference_data_collections-set_entries-POST.html
> - https://ibmsecuritydocs.github.io/qradar_api_20.0/20.0--reference_data_collections-sets-id-GET.html

- **requirements**:
> - requests
> - QRadar API 20.0 and an authorized service token with reference-data access

-----

#### [SentinelOne IOC Publish](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/action_mod/sentinelone_ioc_publish.py)

Publish MISP event and object indicators to SentinelOne Threat Intelligence with explicit scope.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/action_mod/sentinelone_ioc_publish.py)]

- **features**:
>Publishes IDS-marked hashes, domains, URLs and IP addresses from supplied events and objects. Requires account or site scope, uses stable external IDs, checks existing records, and supports expiry and dry runs. Existing records are not changed or deleted. Credentials and console URL come from the module server environment. See the [usage guide](https://github.com/MISP/misp-modules/blob/main/documentation/action_mod/sentinelone_ioc_publish.md).

- **config**:
>{'params': {'scope': {'type': 'string', 'description': 'Required: account or site'}, 'scope_id': {'type': 'string', 'description': 'Required: the single SentinelOne account or site ID'}, 'source': {'type': 'string', 'description': 'Stable source namespace, unique to this MISP publisher', 'value': 'misp-modules'}, 'expiration_days': {'type': 'string', 'description': '1-180 days; maximum 30 when publishing IP addresses', 'value': '14'}, 'severity': {'type': 'string', 'description': 'SentinelOne severity score, integer 0-7', 'value': '4'}, 'dry_run': {'type': 'string', 'description': 'true previews payloads without credentials or network access', 'value': 'false'}}, 'blocking': True, 'support_filters': False, 'expect_misp_core_format': True}

- **input**:
>MISP events in standard, bare or legacy format, supplied in workflow data.

- **output**:
>Per-indicator publication outcomes and counts; errors signal incomplete publication.

- **references**:
>https://github.com/Sentinel-One/ai-siem/blob/main/plugins/s1-secops-skills/skills/mgmt-console-api/references/tags/Threat_Intelligence.md

- **requirements**:
> - requests
> - SentinelOne Threat Intelligence.view and Threat Intelligence.manage permissions

-----

#### [Slack](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/action_mod/slack.py)

Simplistic module to send messages to a Slack channel.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/action_mod/slack.py)]

- **features**:
>

- **config**:
>{'params': {'slack_bot_token': {'type': 'string', 'description': 'The Slack bot token generated when you created the bot account'}, 'channel_id': {'type': 'string', 'description': 'The channel ID you want to post messages to'}, 'message_template': {'type': 'large_string', 'description': 'The template to be used to generate the message to be posted', 'value': 'The **template** will be rendered using *Jinja2*!', 'jinja_supported': True}}, 'blocking': False, 'support_filters': True, 'expect_misp_core_format': False}

-----

#### [Test action](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/action_mod/testaction.py)

This module is merely a test, always returning true. Triggers on event publishing.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/action_mod/testaction.py)]

- **features**:
>

- **config**:
>{'params': {'foo': {'type': 'string', 'description': 'blablabla', 'value': 'xyz'}, 'Data extraction path': {'type': 'hash_path', 'description': 'Only post content extracted from this path', 'value': 'Attribute.{n}.AttributeTag.{n}.Tag.name'}}, 'blocking': False, 'support_filters': False, 'expect_misp_core_format': False}

-----

#### [Wazuh CDB Publish](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/action_mod/wazuh_cdb_publish.py)

Upload MISP event and object indicators to an explicitly named Wazuh CDB source list.
[[source code](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/action_mod/wazuh_cdb_publish.py)]

- **features**:
>Uploads one typed, deduplicated list of to_ids indicators using PUT /lists/files/{filename}. Credentials come from the module server environment. Supports a credential-free dry run and explicit overwrite; overwrite replaces the entire list with the supplied snapshot. Checks the Wazuh acknowledgement, refuses empty lists and optionally requests an analysisd reload on the manager or cluster without a full manager restart. See the [usage guide](https://github.com/MISP/misp-modules/blob/main/documentation/action_mod/wazuh_cdb_publish.md).

- **config**:
>{'params': {'filename': {'type': 'string', 'description': 'Required: dedicated list basename, e.g. misp-ipv4'}, 'indicator_type': {'type': 'string', 'description': 'ipv4, ipv6, domain, md5, sha1, sha256 or sha512', 'value': 'ipv4'}, 'overwrite': {'type': 'string', 'description': 'true replaces the complete existing file with this snapshot', 'value': 'false'}, 'dry_run': {'type': 'string', 'description': 'true previews the upload without network access', 'value': 'false'}, 'reload': {'type': 'string', 'description': 'none (upload only), manager (local node) or cluster (all nodes): reload analysisd after upload', 'value': 'none'}}, 'blocking': True, 'support_filters': False, 'expect_misp_core_format': True}

- **input**:
>Selected MISP events and object attributes in workflow data.

- **output**:
>Upload and reload status, selected filename, indicator counts, content SHA-256 and activation notice.

- **references**:
> - https://documentation.wazuh.com/current/user-manual/api/reference.html#tag/Lists
> - https://documentation.wazuh.com/current/user-manual/api/reference.html#tag/Manager
> - https://documentation.wazuh.com/current/user-manual/api/reference.html#tag/Cluster
> - https://documentation.wazuh.com/current/user-manual/ruleset/cdb-list.html

- **requirements**:
> - requests
> - Wazuh server API credentials with lists:update and lists:delete permissions
> - Optional reload: manager:read/manager:restart or cluster:read/cluster:restart permissions

-----
