# Farsight DNSDB Passive DNS

The module returns DNSDB results as `passive-dns` objects. SOA records also
produce `dns-soa-email` attributes linked to those objects. The complete SOA
record remains in the object's `rdata` attribute.

For unescaped mailbox names, the bundled Public Suffix List is used to infer
the email domain, including multi-label and private suffixes. For example:

| SOA mailbox | Inferred email |
| --- | --- |
| `foo.bar.tld.` | `foo@bar.tld` |
| `foo.bar.hello.tld` | `foo.bar@hello.tld` |
| `first.last.example.co.uk.` | `first.last@example.co.uk` |
| `first\.last.mail.example.com.` | `first.last@mail.example.com` |

This inference is a heuristic: an unescaped name can also represent a mailbox
on a subdomain. Explicitly escaped dots in the first DNS label are respected,
so those names use the DNS label boundary instead. Unknown suffixes use the
Public Suffix List's wildcard rule; names without a registrable-domain prefix
fall back to the first DNS label as the local part.

Derived email attributes have `to_ids` disabled and a comment describing the
heuristic. Malformed SOA records and absent mailboxes are retained as raw data
without creating an email attribute. No additional network lookup is required
for email conversion.
