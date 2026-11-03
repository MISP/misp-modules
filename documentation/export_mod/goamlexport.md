# GoAML export report metadata

The exporter requires at least one MISP `transaction` object and references to
its origin and target objects. Configure report metadata separately from the
accounts and persons involved in those transactions.

| Configuration key | Meaning and default |
| --- | --- |
| `rentity_id` | Required positive numeric reporting entity ID assigned by the receiving Financial Intelligence Unit (FIU). This is not a MISP organisation ID, event ID, account number, or transaction party ID. |
| `submission_code` | Submission code accepted by the receiving FIU. Defaults to `E`, preserving existing exports. Supply only the code, without a description. |
| `submission_date` | Date and time of the submission. Defaults to the current UTC time when generating the export. An optional ISO 8601 date-time override supports historical exports, for example `2026-10-28T12:00:00Z`. |
| `currency_code_local` | Three-letter local currency code for the report's `amount_local` values, for example `EUR`. Lowercase input is normalized to uppercase. Configure this explicitly for the reporting jurisdiction. If omitted, the exporter retains a compatibility fallback only when bank-account objects supply exactly one distinct currency. Missing or conflicting currencies return an error. |
| `report_code` | Report type accepted by the FIU, for example `STR` (Suspicious Transaction Report) or `CTR` (Cash Transaction Report). An explicit value overrides account attributes. Supply only the code, without a description. |

Codes accepted by a receiving FIU can vary; these settings do not validate against
that FIU's code lists. Optional settings that are absent, null, empty, or whitespace
use their defaults or inference rules. A supplied invalid value returns an error
instead of silently falling back.

If `report_code` is omitted, the exporter reads bank-account `report-code`
attributes, taking the first whitespace-delimited token of values such as
`STR Suspicious Transaction Report`. It preserves the existing selection rule:
`STR` takes precedence; otherwise the most frequent report code wins, with the
first encountered code winning a tie. If no code is available, configure
`report_code` explicitly. Report codes and account currencies are collected
independently, so one missing attribute does not suppress the other.

Example `config` in a module request:

```json
{
  "rentity_id": "2510",
  "submission_code": "E",
  "currency_code_local": "EUR",
  "report_code": "STR"
}
```

Leave `submission_date` unset for normal exports. Set it explicitly only when a
fixed submission date is intended. The override accepts `YYYY-MM-DDTHH:MM:SS`,
optionally followed by fractional seconds (up to six digits) and `Z` or a numeric
timezone offset, for example `2026-10-28T14:00:00+02:00`. Prefer including a timezone.

Transaction `amount` values must already be denominated in `currency_code_local`:
they are written as `amount_local` without conversion. An account's `currency-code`
describes the account, and can differ from the reporting currency. Configuring the
report currency does not change account currencies or transaction amounts.

## Migration and validation

Existing requests with a valid `rentity_id` and an unambiguous account currency
continue to work. Two behavior changes are intentional:

- The default submission date is the export time in UTC, rather than the MISP
  event's last-modified timestamp. Pass `submission_date` to reproduce a historical
  submission date.
- Mixed account currencies require `currency_code_local`, instead of silently
  choosing the most common account currency.

Reports without bank-account objects can set `report_code` and
`currency_code_local` explicitly. Existing requirements for transaction party
references still apply. Validate the complete XML against the receiving FIU's
GoAML schema and code lists before submission; these metadata checks do not
provide full document schema validation.
