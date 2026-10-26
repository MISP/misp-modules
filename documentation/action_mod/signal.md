# Signal action module

Send a plain-text message from a MISP workflow to Signal phone numbers or a group.
The action follows the Mattermost module's template and workflow data conventions.
It uses the existing `requests` dependency with
[signal-cli-rest-api](https://github.com/bbernhard/signal-cli-rest-api).

Run a signal-cli-rest-api service reachable from the module server, and register
or link the sending account there. The account must already belong to any target
group. Use the service's group listing endpoint to obtain the group's `id`, with
the `group.` prefix. Account registration, linking and group management are done
in that service, outside this action.

| Parameter | Description |
| --- | --- |
| `signal_api_url` | Service base URL, such as `http://localhost:8080`. Include any reverse proxy path prefix; omit `/v2/send`. HTTPS URLs are also supported. |
| `sender_number` | Registered or linked account number in international format, such as `+33123456789`. |
| `recipients` | Comma-separated international phone numbers or `group.…` IDs returned by signal-cli-rest-api. |
| `message_template` | Optional Jinja2 template. Empty or omitted sends JSON inside triple backticks. |

For example, use `MISP event {{ Event.id }}: {{ Event.info }}` when the workflow
supplies an `Event` object. Templates use `matchingData` whenever that key is
present, including an empty value; otherwise they use `data`. Workflow filters
are supported. Messages are plain text, so Markdown markers remain literal text.

The action sends `POST /v2/send` with `number`, `recipients` and `message`, using
a 30-second timeout. Success requires HTTP 201 and a positive `timestamp` in the
response. This acknowledges the service's send operation, not recipient delivery.
Errors return `data: false` without exposing phone numbers or the response body.
Requests are not automatically retried; a timeout can leave delivery uncertain.
Like Mattermost, this action is nonblocking.

The API service handles Signal account keys and sees the workflow message in
plain text before Signal encrypts it. Keep access to that service restricted to
trusted clients. This action targets the service's native API and does not
configure authentication for a reverse proxy.
