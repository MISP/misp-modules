# Matrix action module

Send a plain-text message from a MISP workflow to an **unencrypted** Matrix room.
This action follows the Mattermost module's template and workflow data conventions.
It uses the Matrix Client-Server API through the existing `requests` dependency.

Create a Matrix bot account, obtain its access token, and invite it to the room.
The bot must join the room before running the action and have permission to send
`m.room.message` events. Copy the room ID from your client's room settings; use
the ID starting with `!`, rather than an alias starting with `#`.

Configure these action parameters:

| Parameter | Description |
| --- | --- |
| `matrix_homeserver` | Homeserver base URL, such as `https://matrix.example.org`. Include any reverse proxy path prefix, but omit `/_matrix/client/...`. HTTPS is recommended; explicit HTTP URLs are supported for local deployments. |
| `bot_access_token` | Access token for the bot account. Sent in the Authorization header. |
| `room_id` | Existing unencrypted room ID, for example `!room:example.org`. |
| `message_template` | Optional Jinja2 template. Leave empty to send the selected workflow data as JSON inside triple backticks. |

For example, with event data under `Event`:

```jinja2
MISP event {{ Event.id }}: {{ Event.info }}
{% for attribute in Event.Attribute %}
- {{ attribute.type }}: {{ attribute.value }}
{% endfor %}
```

Templates use `matchingData` when supplied by the workflow, otherwise `data`, as
in the Mattermost action. Workflow filters are supported. Messages are sent as
`m.text`; Markdown, HTML formatting and end-to-end encryption are unsupported.
Triple backticks in the fallback are sent as literal text.

The action sends one `PUT /_matrix/client/v3/rooms/{roomId}/send/m.room.message/{txnId}`
request with a unique transaction ID and a 30-second timeout. Success requires
HTTP 200 and an `event_id` in the response. Failed requests return `data: false`
and an error without exposing the access token or homeserver response body.
Requests are not automatically retried; after a timeout, delivery may be unknown.
The action is nonblocking, like Mattermost.
