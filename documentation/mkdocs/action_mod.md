
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
