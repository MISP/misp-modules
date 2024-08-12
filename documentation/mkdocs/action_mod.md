
#### [Mattermost](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/action_mod/mattermost.py)

Simplistic module to send message to a Mattermost channel.
- **features**:
>
- **config**:
>{'params': {'mattermost_hostname': {'type': 'string', 'description': 'The Mattermost domain or URL', 'value': 'example.mattermost.com'}, 'bot_access_token': {'type': 'string', 'description': 'Access token generated when you created the bot account'}, 'channel_id': {'type': 'string', 'description': 'The channel you added the bot to'}, 'message_template': {'type': 'large_string', 'description': 'The template to be used to generate the message to be posted', 'value': 'The **template** will be rendered using *Jinja2*!', 'jinja_supported': True}}, 'blocking': False, 'support_filters': True, 'expect_misp_core_format': False}

-----

#### [Slack](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/action_mod/slack.py)

Simplistic module to send messages to a Slack channel.
- **features**:
>
- **config**:
>{'params': {'slack_bot_token': {'type': 'string', 'description': 'The Slack bot token generated when you created the bot account'}, 'channel_id': {'type': 'string', 'description': 'The channel ID you want to post messages to'}, 'message_template': {'type': 'large_string', 'description': 'The template to be used to generate the message to be posted', 'value': 'The **template** will be rendered using *Jinja2*!', 'jinja_supported': True}}, 'blocking': False, 'support_filters': True, 'expect_misp_core_format': False}

-----

#### [Test action](https://github.com/MISP/misp-modules/tree/main/misp_modules/modules/action_mod/testaction.py)

This module is merely a test, always returning true. Triggers on event publishing.
- **features**:
>
- **config**:
>{'params': {'foo': {'type': 'string', 'description': 'blablabla', 'value': 'xyz'}, 'Data extraction path': {'type': 'hash_path', 'description': 'Only post content extracted from this path', 'value': 'Attribute.{n}.AttributeTag.{n}.Tag.name'}}, 'blocking': False, 'support_filters': False, 'expect_misp_core_format': False}

-----
