"""Conservative extraction of partial inline forwards, inspired by mail_to_misp.

These messages are reconstructions of visible text, not original RFC 5322 mails.
Keep the carrier email as the source of evidence.
"""

import re
from email.headerregistry import Address
from email.message import EmailMessage
from email.utils import format_datetime, getaddresses, parsedate_to_datetime
from html.parser import HTMLParser

HEADER = re.compile(r"^\s*(From|To|Cc|Bcc|Reply-To|Sent|Date|Subject)\s*:\s*(.*)$", re.IGNORECASE)
# Remove quoting while preserving indentation used by folded header values.
QUOTE = re.compile(r"^[ \t]*(?:>[ \t]?)+")
MAX_FORWARDS = 20


class ForwardHTMLParser(HTMLParser):
    """Preserve visual header lines and HTTP links without fetching any content."""

    def __init__(self):
        super().__init__()
        self.parts = []
        self.hidden = 0
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag in ("head", "script", "style"):
            self.hidden += 1
        if self.hidden:
            return
        if tag in ("br", "hr", "div", "p", "tr", "blockquote"):
            self.parts.append("\n")
        attrs = dict(attrs)
        if tag == "a":
            self.links.append(attrs.get("href") or "")
        source = attrs.get("src") or ""
        if tag == "img" and source.lower().startswith(("http://", "https://")):
            self.parts.append(" " + source + " ")

    def handle_endtag(self, tag):
        if tag in ("head", "script", "style"):
            self.hidden = max(0, self.hidden - 1)
            return
        if self.hidden:
            return
        if tag == "a" and self.links:
            link = self.links.pop()
            if link.lower().startswith(("http://", "https://")):
                self.parts.append(" " + link + " ")
        if tag in ("div", "p", "tr", "blockquote"):
            self.parts.append("\n")

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)


def _header_block(lines, start):
    headers = {}
    end = start
    previous = None
    after_blank = False
    # Real forwarded headers form a short block, not scattered body keywords.
    for index in range(start, min(start + 40, len(lines))):
        line = lines[index]
        if not line.strip():
            after_blank = True
            continue
        match = HEADER.match(line)
        if not match:
            if previous is not None and line.startswith((" ", "\t")) and not after_blank:
                headers[previous] += " " + line.strip()
                end = index + 1
                continue
            break
        name, value = match.groups()
        name = name.lower()
        if name in headers:
            break
        headers[name] = value.strip()
        previous = name
        after_blank = False
        end = index + 1
    if not headers.get("subject") or not (headers.get("to") or headers.get("sent") or headers.get("date")):
        return None
    if not any("@" in address for _, address in getaddresses([headers.get("from", "")])):
        return None
    return headers, end


def _reconstruct(headers, body):
    message = EmailMessage()
    for name, value in headers.items():
        if name in ("date", "sent"):
            # Outlook's localized dates and times without a zone are only claims.
            # Preserve them without inventing a UTC send-date.
            try:
                date = parsedate_to_datetime(value)
            except (ValueError, TypeError, OverflowError):
                date = None
            if date is not None and date.tzinfo is not None and "Date" not in message:
                message["Date"] = format_datetime(date)
            else:
                message[f"X-Forwarded-{name}"] = value
        elif name in ("from", "to", "cc", "bcc", "reply-to") and "@" not in value:
            # A display name is not an email address (e.g. 'To: Other Name').
            message[name] = str(Address(display_name=value))
        else:
            message[name] = value
    message.set_content(body)
    return message


def _extract(text):
    lines = [QUOTE.sub("", line) for line in text.replace("\r\n", "\n").splitlines()]
    blocks = []
    index = 0
    while index < len(lines) and len(blocks) < MAX_FORWARDS:
        match = HEADER.match(lines[index])
        if match and match[1].lower() == "from":
            block = _header_block(lines, index)
            if block:
                headers, end = block
                blocks.append((index, end, headers))
                index = end
                continue
        index += 1
    messages = []
    for position, (_, end, headers) in enumerate(blocks):
        next_start = blocks[position + 1][0] if position + 1 < len(blocks) else len(lines)
        messages.append(_reconstruct(headers, "\n".join(lines[end:next_start]).strip()))
    return messages


def inline_forwarded_messages(message):
    """Prefer plain text, fall back to HTML; never parse both MIME alternatives.

    Require From (with an address), Subject, and To or Sent/Date in one block.
    English header labels are supported, with or without a forwarding delimiter.
    """
    for subtype in ("plain", "html"):
        part = message.get_body(preferencelist=(subtype,))
        if part is None:
            continue
        payload = part.get_payload(decode=True)
        if not payload:
            continue
        try:
            text = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        except LookupError:
            text = payload.decode("utf-8", errors="replace")
        if subtype == "html":
            parser = ForwardHTMLParser()
            parser.feed(text)
            text = "".join(parser.parts)
        messages = _extract(text)
        if messages:
            return messages
    return []
