# IRC action module

Send a plain-text message from a MISP workflow to an IRC channel. The action
follows the Mattermost module's template and workflow data conventions. It uses
Python's standard library, so no extra IRC client dependency is needed.

| Parameter | Description |
| --- | --- |
| `irc_server` | Server hostname, without a URL scheme. |
| `irc_port` | Server port; defaults to `6697`. Set `6667` explicitly for a typical plaintext server. |
| `use_tls` | `true` (default) uses TLS with certificate and hostname verification. `false` selects plaintext. |
| `nickname` | Nickname for the connection; must be available on the server. |
| `channel` | One channel starting with `#` or `&`, such as `#misp`. |
| `server_password` | Optional server password, sent using `PASS`. |
| `channel_key` | Optional channel key, sent with `JOIN`. |
| `message_template` | Optional Jinja2 template. Empty or omitted sends JSON inside triple backticks. |

For example, use `MISP event {{ Event.id }}: {{ Event.info }}` when the workflow
supplies an `Event` object. Templates use `matchingData` whenever that key is
present, including an empty value; otherwise they use `data`. Workflow filters
are supported.

Each invocation connects, registers, joins the channel, sends `PRIVMSG` lines,
and disconnects. The connection answers server `PING` messages. It waits for
registration and its own channel join before sending. Newlines become separate
messages, tabs become spaces, and long lines split at UTF-8 character boundaries
to fit IRC's 512-byte command limit. Empty lines are omitted. Other control
characters, including CTCP framing, are rejected. Markdown markers are literal.

After sending, the action waits for a server `PONG` to a unique token to observe
errors from preceding commands before reporting success. IRC provides no
recipient delivery receipt; a successful result means the server processed the
commands without returning an error. Connection failures, nickname collisions,
channel access errors and send rejections return `data: false` without server
error text or credentials. The operation has a 30-second I/O budget, with no
automatic retries. Like Mattermost, this action is nonblocking.

Choose a channel the account can join and write to. SASL, NickServ authentication
and client certificates are unsupported. Each invocation needs an available
nickname; concurrent runs using the same nickname can collide. Keep templates
concise and account for your IRC network's flood limits when scheduling workflows.
