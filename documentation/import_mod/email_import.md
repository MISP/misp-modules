# Email Import

Imports EML and Outlook MSG messages as email, file and optional URL objects.
The module works locally; it does not fetch URLs or write ZIP member paths to disk.

## Configuration

All five switches default to false:

| Setting | Action when enabled |
| --- | --- |
| unzip_attachments | Extract supported ZIP attachments within the limits below. |
| guess_zip_attachment_passwords | Try candidate passwords for encrypted ZIPs; requires unzip_attachments. |
| extract_urls | Extract URLs from carrier and reconstructed-forward bodies. |
| remove_subject_markers | Clean reply/forward prefixes from subject attributes. |
| extract_forwarded_emails | Reconstruct up to 20 partial inline-forward email objects. |

Values can be JSON true/false, integers 1/0, or strings true/false, yes/no,
y/n, t/f and 1/0. String matching ignores case and surrounding whitespace.
Missing, null and empty values disable the option. Unsupported values and
non-object configurations return a configuration error without import results.
In particular, the string "false" disables extraction just as JSON false does.

Example module request:

    {
      "module": "email_import",
      "data": "<base64-encoded original message>",
      "config": {
        "unzip_attachments": true,
        "guess_zip_attachment_passwords": false,
        "extract_urls": true
      }
    }

## Extraction limits

ZIP limits are fixed in the module and shared across all attachments in one
request. They cannot be increased through request configuration.

| Resource | Limit |
| --- | --- |
| ZIP entries selected for extraction, including directories | 100 per request |
| Expanded bytes from one member | 20 MiB |
| Cumulative expanded ZIP bytes, including password retries | 50 MiB per request |
| Candidate password trials across encrypted archives | 100 per request |
| Password candidate size | 256 UTF-8 bytes |
| Subject/body text considered for candidates | 64 Ki characters |

The module checks declared member sizes and counts before extraction, then
reads in chunks of at most 64 KiB while enforcing actual expanded-byte limits.
One lookahead byte may be read to detect an overflow. A read that raises an
error is conservatively charged for the requested chunk; successful bytes and
failed attempts do not get a fresh budget on retries or later attachments.
Passwords are deduplicated in a stable order, beginning with common malware
passwords and then quoted phrases and words in the subject/body.

Only stored and deflated ZIP members are extracted. Python's ZIP reader can
expand BZIP2/LZMA data without an output bound inside an individual read, so
those methods are retained as original archives with a warning. Office and
OpenDocument containers remain intact, including uppercase extensions.
Nested ZIPs are kept as extracted file objects and are not recursively expanded.

An archive's file objects are added only after every member has been read
successfully. Limits, corrupt data, unsupported compression, disabled password
guessing and unsuccessful guesses leave the original attachment intact.
Warnings appear in the API response and in the original file object's comment.
Other attachments and the carrier email remain available. Every original
attachment is retained even when extraction succeeds; derived files have an
extraction comment and are linked to the carrier. Duplicate ZIP names are read
as distinct directory entries.

These are ZIP extraction limits, not input-message or general MIME parser quotas.

## Original evidence and reconstructed content

The carrier has an attachment containing the exact submitted bytes, including
line endings, byte-order marks and trailing whitespace. It is labeled
Original email.eml or Original email.msg, and has to_ids disabled.

For MSG input, a separate Converted email.eml attachment contains the converted
message and explicitly states that it is reconstructed. Original MSG data is
taken from the submitted input, rather than from PyMISP's conversion buffers.
Subject cleanup changes the subject attribute, not the preserved message bytes.

Inline-forward objects are labeled as heuristic reconstructions and have
to_ids disabled. They do not carry an original-message attachment; the
carrier's preserved message remains their evidence. Existing conservative
forward-header recognition and URL-object sharing remain in effect.
