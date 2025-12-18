# Mapping DSL Reference

This document describes the declarative Domain-Specific Language (DSL) used to define how ReversingLabs API responses are transformed into MISP objects, attributes, tags, and relationships.

> 🔬 **Interactive Visualizer**: Open [mapping-visualizer.html](mapping-visualizer.html) for an interactive D3.js visualization of the DSL structure.

---

## Table of Contents

1. [Overview](#overview)
2. [File Structure](#file-structure)
3. [Object Definitions](#object-definitions)
4. [Event-Level Attributes](#event-level-attributes)
5. [Attribute Mappings](#attribute-mappings)
6. [Handlers](#handlers)
7. [Tags](#tags)
8. [Relationships](#relationships)
9. [Nested Objects](#nested-objects)
10. [Foreach Iteration](#foreach-iteration)
11. [Nested Fetch](#nested-fetch)
12. [Complete Examples](#complete-examples)
13. [API Response Examples](#api-response-examples)

---

## Overview

The mapping DSL is a JSON-based configuration that defines:

- **What data to extract** from ReversingLabs API responses
- **How to transform it** into MISP objects and attributes
- **What relationships** to create between objects
- **What tags** to apply to events/objects

The mappings file is located at `mappings/rl_mappings.json`.

---

## File Structure

```json
{
  "#COMMENT": "Top-level comment (stripped at compile time)",
  "create": {
    "file": {
      "obj:fetch": ["/api/samples/v2/list/details/", "/api/samples/v3/{hash}/classification/"],
      /* file IOC type mappings */
    },
    "domain": {
      "obj:fetch": ["/api/network-threat-intel/domain/{domain}/"],
      /* domain IOC type mappings */
    },
    "ip": {
      "obj:fetch": ["/api/network-threat-intel/ip/{ip}/report/"],
      /* IP IOC type mappings */
    },
    "url": {
      "obj:fetch": ["/api/network-threat-intel/url/"],
      /* URL IOC type mappings */
    }
  }
}
```

### Top-Level Keys

| Key | Description |
|-----|-------------|
| `#COMMENT` | Development comment, stripped during compilation |
| `create` | Contains mapping definitions for each IOC type (legacy: `_enrich`) |

### IOC-Level Keys

| Key | Description |
|-----|-------------|
| `obj:fetch` | Array = top-level endpoint fallback list; Dict = nested fetch call |

---

## Object Definitions

Objects are defined as JSON objects within the IOC type section. Each object definition can contain:

- **Object directives** (`obj:*`) - metadata about the MISP object
- **Attribute mappings** - field definitions that become MISP attributes
- **Tag definitions** - fields prefixed with namespace that become tags
- **Nested objects** - child object definitions

### Object Directives

| Directive | Description | Example |
|-----------|-------------|---------|
| `obj:type` | MISP object type to create | `"obj:type": "file"` |
| `obj:comment` | Comment attached to the MISP object | `"obj:comment": "Analysis results"` |
| `obj:analysed-with->` | Create "analysed-with" relationship to listed children | `"obj:analysed-with->": ["report"]` |
| `obj:related-to->` | Create "related-to" relationship to listed children | `"obj:related-to->": ["dns-record"]` |
| `obj:contains->` | Create "contains" relationship to listed children | `"obj:contains->": ["domain-ip"]` |
| `obj:handler` | Invoke a handler to dynamically create child objects | `"obj:handler": "{{#iterate_dns ...}}"` |

### Basic Object Example

```json
{
  "file": {
    "obj:type": "file",
    "obj:comment": "File object from ReversingLabs analysis",
    "md5": "{{#ref sample_summary.md5 | md5}}",
    "sha256": "{{#ref sample_summary.sha256 | sha256}}",
    "filename": "{{#ref sample_summary.identification_name | file_name}}"
  }
}
```

This creates a MISP `file` object with three attributes: `md5`, `sha256`, and `filename`.

---

## Event-Level Attributes

In addition to creating MISP objects, you can create **event-level attributes** - standalone attributes that appear directly on the MISP event, not inside any object.

### Two Ways to Create Event-Level Attributes

#### 1. Top-Level String Values

At the IOC mapping level, string values become event-level attributes:

```json
{
  "file": {
    "sha256": "{{#ref sample_summary.sha256}}",    
    "file": {
      "obj:type": "file",
      "md5": "{{#ref sample_summary.md5}}"
    }
  }
}
```

- `"file": { ... }` is a dict → creates a `file` **object**
- `"sha256": "{{#ref ...}}"` is a string → creates an **event-level attribute**

#### 2. `!` Prefix - Promote Object Attribute

Prefix an object attribute with `!` to create **both** the object attribute AND an event-level attribute:

```json
{
  "file": {
    "obj:type": "file",
    "!md5": "{{#ref sample_summary.md5}}",
    "!sha256": "{{#ref sample_summary.sha256}}",
    "filename": "{{#ref sample_summary.identification_name}}"
  }
}
```

This creates:
- **1 file object** with 3 attributes (`md5`, `sha256`, `filename`)
- **2 event-level attributes** (`md5`, `sha256`) for quick correlation

### When to Use Each Approach

| Approach | Use When |
|----------|----------|
| Top-level string | Attribute name differs between object and event (e.g., object has `host`, event needs `domain`) |
| `!` prefix | Same attribute appears in both object and event (no duplication in mappings) |

### Syntax Comparison

**Old way (duplicate definitions):**
```json
{
  "file": {
    "sha256": "{{#ref sample_summary.sha256}}",
    "file": {
      "obj:type": "file",
      "sha256": "{{#ref sample_summary.sha256}}"
    }
  }
}
```

**New way (! prefix):**
```json
{
  "file": {
    "file": {
      "obj:type": "file",
      "!sha256": "{{#ref sample_summary.sha256}}"
    }
  }
}
```

Both produce identical MISP output.

### Mixed Usage Example

When object and event attribute names differ, use both approaches:

```json
{
  "url": {
    "domain": "{{#ref domain | domain}}",
    
    "url-object": {
      "obj:type": "url",
      "!url": "{{#ref requested_url | url}}",
      "host": "{{#ref domain}}"
    }
  }
}
```

This creates:
- Event-level `domain` attribute (from top-level string)
- Event-level `url` attribute (from `!url`)  
- URL object with `url` and `host` attributes

### Features

Event-level attributes automatically include:
- **UUID**: Required by MISP to persist attributes (auto-generated)
- **All handlers**: `{{#ref path}}`, `{{#build_link type}}`, `{{#summary}}`, etc.
- **Comments**: `{{#Comment Description}}` inline comments
- **Automatic type inference**: The attribute name determines the MISP type (e.g., `sha256` → type `sha256`)
- **Automatic category**: Categories are inferred from type (e.g., `sha256` → "Payload delivery")
- **IDS flag**: Indicator types (`sha256`, `domain`, `ip-dst`, etc.) automatically get `to_ids: true`
- **Correlation enabled**: `disable_correlation: false` by default

### Complete Example

```json
{
  "_enrich": {
    "file": {
      "#COMMENT": "File object with promoted hashes for correlation",
      "file": {
        "obj:type": "file",
        "obj:comment": "File with hash identifiers",
        "!md5": "{{#ref sample_summary.md5}}",
        "!sha1": "{{#ref sample_summary.sha1}}",
        "!sha256": "{{#ref sample_summary.sha256}}",
        "filename": "{{#ref sample_summary.identification_name}}"
      }
    }
  }
}
```

This produces:
- **3 event-level attributes**: `md5`, `sha1`, and `sha256` (from `!` prefix)
- **1 file object**: with 4 attributes inside it (md5, sha1, sha256, filename)

### Disabling Event-Level Attributes

To disable an event-level attribute, prefix the key with `# ` (hash + space):

```json
{
  "# sha256": "{{#ref sample_summary.sha256}}"
}
```

---

## Attribute Mappings

Attribute mappings define how to extract values from the API response and create MISP attributes.

### Syntax

```
"<attribute_name>": "<value_expression>"
```

The value expression can be:

1. **Handler invocation**: `{{#handler_name args}}`
2. **Static value**: `"literal text"`
3. **Type coercion**: `(int) path`

### Handler: `#ref` - Path Reference

The most common handler extracts a value from the API response using a dot-notation path.

**Syntax:**
```
{{#ref <path>}}
{{#ref <path> | <fallback_type>}}
{{#ref <path1> | <path2> | <path3>}}   // Fallback paths
```

**Path Syntax:**

| Syntax | Description | Example |
|--------|-------------|---------|
| `field` | Access a field | `sha256` |
| `parent.child` | Nested field access | `sample_summary.sha256` |
| `array[0]` | First array element | `top_threats[0]` |
| `array[N]` | Nth array element (0-indexed) | `dns_records[2]` |
| `array[0].field` | Field from array element | `top_threats[0].threat_name` |

**Examples:**

```json
{
  // Simple path
  "sha256": "{{#ref sample_summary.sha256}}",
  
  // Path with MISP type hint - uses (type) suffix
  "md5": "{{#ref sample_summary.md5 (md5)}}",
  
  // Fallback paths - tries each until one has a value
  "filename": "{{#ref sample_summary.identification_name | sample_summary.file_name}}",
  
  // Fallback paths with type hint
  "ip-dst": "{{#ref requested_ip | fallback_ip (ip-dst)}}",
  
  // Type coercion - converts to integer (prefix syntax)
  "port": "{{#ref (int) port}}",
  
  // Array index - get first element
  "primary-threat": "{{#ref top_threats[0].threat_name}}",
  
  // Array index with fallback path
  "threat-name": "{{#ref top_threats[0].threat_name | classification_reason}}"
}
```
 
### Numeric-index suffix on attribute keys

You can append a `#N` suffix to an attribute **key** to declare multiple attributes of the same name in the mappings. The runtime strips the `#N` suffix when creating attributes, allowing you to define several attributes of the same MISP type without name collisions in JSON.

Examples:

```json
{
  "text#0": "{{#ref sample_summary.file_type}} {{#Comment File type (primary)}}",
  "text#1": "{{#ref sample_summary.file_subtype}} {{#Comment File subtype (secondary)}}"
}
```

Both keys above create attributes of type `text` in the MISP object; the `"#0"` and `"#1"` suffixes are removed at runtime.

> **Note:** The legacy `[N]` syntax (e.g., `text[0]`) is still supported but `#N` is preferred as it's visually distinct from the `[]` array mode suffix.


### Migration note

If you maintain existing mappings that create multiple attributes of the same name, prefer switching to the `#N` suffix form (for example, `text#0`, `text#1`) to make the intent explicit and JSON-valid. Example migration:

Before:

```json
"text": "{{#ref sample_summary.file_type}} - {{#ref sample_summary.threat_name}}"
```

After:

```json
"text#0": "{{#ref sample_summary.file_type}} {{#Comment File type}}",
"text#1": "{{#ref sample_summary.threat_name}} {{#Comment Threat name}}"
```

Using `#N` suffixes avoids needing to encode arrays of attribute names in JSON and keeps each attribute mapping explicit.


### Inline Comments

Add documentation to attributes with `{{#Comment ...}}`:

```json
{
  "sha256": "{{#ref sample_summary.sha256 | sha256}} {{#Comment SHA256 hash (primary identifier)}}"
}
```

The comment text becomes the MISP attribute's `comment` field.

### Type Coercion

Force type conversion with `(type)` prefix:

```json
{
  "port": "{{#ref (int) port}}",
  "size-in-bytes": "{{#ref (int) sample_summary.file_size}}"
}
```

Supported types: `int`, `float`, `str`, `bool`

---

## Handlers

Handlers are functions that process API data in custom ways. They're invoked with `{{#handler_name arguments}}`.

### `#ref` - Extract Value from Path

Extracts a value from the API response.

#### Quoted-literal fallbacks

You may supply multiple fallback tokens separated by `|`. Tokens that are enclosed in matching single or double quotes are treated as literal values (not JSON paths). Resolution rules:

- Tokens are evaluated left-to-right.
- If a token is a quoted literal (e.g. `'LOCAL'` or "UNKNOWN"), that literal is returned immediately.
- Otherwise the token is treated as a JSON path and resolved against the API response.
- Only missing values or null/empty (whitespace-only) strings cause the resolver to try the next fallback; values of `0`, `False`, or non-empty strings are returned as-is.

Examples:

```
{{#ref data_source | sample_summary.data_source | 'LOCAL'}}
```

This will try `data_source` (root), then `sample_summary.data_source`, and finally return the literal `LOCAL` if none of the paths provide a non-empty value.

### `#if` - Block conditional

Use `{{#if CONDITION}}...{{#else}}...{{/if}}` to select between two blocks of DSL. Semantics:

- `CONDITION` is resolved using the same fallback rules as `{{#ref}}` (quoted-literal tokens are literals; unquoted tokens are JSON paths).
- The condition's truthiness follows Python semantics: empty or whitespace-only strings are falsey, `None` is falsey, `0` and `False` are falsey; non-empty strings and non-zero numbers are truthy.
- If the condition is truthy, the content between `{{#if ...}}` and `{{#else}}` (or `{{/if}}` if no else) is used; otherwise the `{{#else}}` block is used if present.
- The selected block may contain nested `{{#ref}}` calls and will be resolved normally. Final rendered strings are trimmed; empty trimmed results suppress attribute/tag creation.

Example:

```
"rl:example": "{{#if data_source | sample_summary.data_source}} {{#ref data_source | sample_summary.data_source | 'LOCAL'}} {{#else}} Not Found {{/if}}",
```

In this example the condition checks `data_source` (root) then `sample_summary.data_source`; if truthy it emits the resolved data source (falling back to `'LOCAL'`), otherwise emits `Not Found`.

#### Quoted-literal fallbacks

You can provide literal fallback values when using `{{#ref ...}}` by supplying a quoted token as one of the fallback alternatives. Only properly paired single or double quotes denote a literal string; unquoted tokens are always interpreted as JSON paths to resolve.

Rules:
- Syntax: `{{#ref path1 | path2 | "LITERAL"}}` or `{{#ref path1 | 'LITERAL'}}` (paired quotes required).
- Evaluation order: tokens are tried left→right. For each token:
  - If the token is a paired quoted string, the unquoted literal is returned immediately.
  - Otherwise the token is resolved as a JSON path; if the path exists and is not `null`, its value is returned.
  - If the path is missing or `null`, evaluation continues to the next token.
- Only `null` / missing triggers fallback; empty string (`""`), `0`, and `false` are valid values and will stop fallback.

Example:

```json
{
  "!data_source": "{{#ref data_source | sample_summary.data_source | \"LOCAL\"}}"
}
```

This attempts to resolve `data_source` at the root, then `sample_summary.data_source`, and finally returns the literal string `LOCAL` if both paths are absent or `null`.


```json
"domain": "{{#ref requested_domain | domain}}"
```

**Arguments:**
- `path` - Dot-notation path (e.g., `sample_summary.sha256`)
- `| fallback` - Alternative fallback path (tries in order until one has a value)
- `(type)` - MISP type hint suffix (e.g., `(ip-dst)`, `(domain)`, `(sha256)`)

---

### `#summary` - Generate Unified Summary

Generates a human-readable summary appropriate for the IOC type.

```json
"summary": "{{#summary}}"
```

**No arguments.** Automatically detects IOC type and generates summary.

**Output examples:**

For file:
```
Classification: MALICIOUS (Trojan.Generic)
Risk Score: 8/10 | Threat Level: 5
File Type: PE32 executable | Size: 245760 bytes
```

For domain:
```
Domain: example.com
First Seen: 2024-01-15 | Last Seen: 2024-06-20
Associated Threats: Trojan.X, Malware.Y
```

---

### `#build_link` - Generate Portal Link

Creates a link to the ReversingLabs analysis portal.

```json
"link": "{{#build_link file}}"
"link": "{{#build_link domain}}"
"link": "{{#build_link ip}}"
"link": "{{#build_link url}}"
```

**Arguments:**
- IOC type: `file`, `domain`, `ip`, `url`

**Output examples:**
```
https://a1000.reversinglabs.com/abc123def456...  (for file SHA256)
https://a1000.reversinglabs.com/domain/example.com/analysis/domain/
https://a1000.reversinglabs.com/ip/192.168.1.1/analysis/ip/
```

---

### `#list_items` - Extract List Field Values

Extracts a specific field from each item in a list and joins with commas.

```json
"text": "{{#list_items top_threats threat_name}}"
```

**Arguments:**
- `path` - Path to the list in API response
- `field` - Field name to extract from each item

**Given API data:**
```json
{
  "top_threats": [
    {"threat_name": "Trojan.Generic", "count": 5},
    {"threat_name": "Ransomware.Lock", "count": 3}
  ]
}
```

**Output:** `"Trojan.Generic, Ransomware.Lock"`

---

### `#foreach` - Iterate Over Arrays (Block Directive)

Iterates over an array and creates tags, attributes, or aggregated values from a template. This is a block directive that replaces both `#tags_from` and `#list_items` with a more flexible, composable syntax.

**Syntax:**
```
{{#foreach <array_path>}}<template>{{/foreach}}
{{#foreach <array_path> <limit>}}<template>{{/foreach}}                   // with limit
{{#foreach <array_path>[field=val1,val2]}}<template>{{/foreach}}          // with filter
{{#foreach <array_path>[field=val1,val2] <limit>}}<template>{{/foreach}}  // with filter and limit
```

**Parameters:**
- `array_path` - Path to the array in the API response
- `limit` - (Optional) Maximum number of iterations (default: 50)
- `[field=val1,val2]` - (Optional) Filter to only include items where field matches one of the values

**Two Modes Based on Key:**

| Key Pattern | Mode | Output |
|-------------|------|--------|
| `key[]` | **Multiple** | Creates separate tag/attribute per item |
| `key` (no `[]`) | **Aggregate** | Concatenates all resolved values (separator controlled in template) |

**Key naming:**
- `namespace:key[]` - Creates multiple **tags** (one per item)
- `attribute[]` - Creates multiple **attributes** (one per item)
- `namespace:key` or `attribute` (no `[]`) - Creates single **aggregated** value

**Examples:**

```json
{
  // MULTIPLE MODE: Create separate tag for each threat name
  "rl:threat[]": "{{#foreach top_threats}}{{#ref threat_name}}{{/foreach}}",
  // → rl:threat="Trojan.Generic", rl:threat="Ransomware.Lock"
  
  // AGGREGATE MODE: Concatenate threat names (separator in template)
  "text#0": "{{#foreach top_threats}}{{#ref threat_name}}, {{/foreach}}",
  // → text = "Trojan.Generic, Ransomware.Lock, Adware.Minor, "
  
  // AGGREGATE with template formatting
  "text#1": "{{#foreach top_threats}}[{{#ref risk_score}}] {{#ref threat_name}} | {{/foreach}}",
  // → text = "[8] Trojan.Generic | [9] Ransomware.Lock | [3] Adware.Minor | "
  
  // With explicit limit (only first 10 items)
  "rl:threat[]": "{{#foreach top_threats 10}}{{#ref threat_name}}{{/foreach}}",
  
  // With filter - only high-risk threats
  "rl:high-risk[]": "{{#foreach top_threats[risk_score=8,9,10]}}{{#ref threat_name}}{{/foreach}}",
  
  // With filter AND limit
  "rl:ip[]": "{{#foreach dns_records[type=A,AAAA] 5}}{{#ref value}}{{/foreach}}",
  
  // Create multiple attributes
  "comment[]": "{{#foreach top_threats}}Threat: {{#ref threat_name}}{{/foreach}}"
}
```

**Given API data:**
```json
{
  "top_threats": [
    {"threat_name": "Trojan.Generic", "threat_family": "Trojan", "risk_score": 8},
    {"threat_name": "Ransomware.Lock", "threat_family": "Ransomware", "risk_score": 9},
    {"threat_name": "Adware.Minor", "threat_family": "Adware", "risk_score": 3}
  ]
}
```

**Multiple mode output for `rl:threat:[]`:**
```
rl:threat="Trojan.Generic"
rl:threat="Ransomware.Lock"
rl:threat="Adware.Minor"
```

**Aggregate mode output for `text#0`:**
```
"Trojan.Generic, Ransomware.Lock, Adware.Minor, "
```

> **Note:** The trailing separator is included. If you need to strip it, handle in post-processing or use a conditional in your template.

**Behavior:**
- Iterates over each item in the array (limited to 50 items by default)
- Resolves `{{#ref field}}` relative to the current item
- Skips items where template resolves to empty/null (no output for that item)
- Supports nested `{{#if}}` conditionals inside the template
- Filter syntax `[field=val1,val2]` only includes items where field matches one of the values
- In aggregate mode, values are concatenated directly (you control the separator in your template)

---

### `#list_items` - Extract List Field Values (Legacy)

> **Note:** Consider using `{{#foreach}}` in aggregate mode for new mappings. `#list_items` is retained for backward compatibility.

Extracts a specific field from each item in a list and joins with commas.

```json
"text": "{{#list_items top_threats threat_name}}"
```

---

### `#tags_from` - Create Tags from List (Legacy)

> **Note:** Consider using `{{#foreach}}` for new mappings. `#tags_from` is retained for backward compatibility.

Creates multiple tags from list items. Does not create an attribute.

```json
"rl:threat_name:": "{{#tags_from top_threats threat_name threat}}"
"rl:threat_family:": "{{#tags_from top_threats threat_family malware-family}}"
```

**Arguments:**
- `path` - Path to list in API response
- `field` - Field to extract from each item
- `tagkey` - (Optional) Tag key name, defaults to "threat"

**Given API data:**
```json
{
  "top_threats": [
    {"threat_name": "Trojan.Generic", "threat_family": "Trojan"},
    {"threat_name": "Ransomware.Lock", "threat_family": "Ransomware"}
  ]
}
```

**Created tags:**
```
rl:threat="Trojan.Generic"
rl:threat="Ransomware.Lock"
rl:malware-family="Trojan"
rl:malware-family="Ransomware"
```

---

### `#dns_records` - Filter DNS Records

Filters DNS records by type and extracts values.

```json
"a-record": "{{#dns_records A last_dns_records}}",
"aaaa-record": "{{#dns_records AAAA last_dns_records}}",
"mx-record": "{{#dns_records MX last_dns_records}}"
```

**Arguments:**
- `TYPE` - DNS record type (A, AAAA, CNAME, MX, NS, TXT, SOA, SRV, PTR)
- `path` - Path to DNS records array

**Given API data:**
```json
{
  "last_dns_records": [
    {"type": "A", "value": "93.184.216.34"},
    {"type": "A", "value": "93.184.216.35"},
    {"type": "MX", "value": "mail.example.com"}
  ]
}
```

**Output for `{{#dns_records A last_dns_records}}`:**
```
"93.184.216.34, 93.184.216.35"
```

---

### `#iterate_dns` - Create Child Objects from DNS

Iterates over DNS records and creates child MISP objects for each.

```json
"domain-ip": {
  "obj:handler": "{{#iterate_dns last_dns_records A,AAAA,NS,CNAME,MX,TXT}}"
}
```

**Arguments:**
- `path` - Path to DNS records array
- `types` - Comma-separated DNS record types to process

**Behavior:**
- For A/AAAA records: Creates `domain-ip` or `ip-port` objects with `ip` attribute
- For NS/CNAME/MX/PTR: Creates objects with `hostname` attribute
- For TXT (SPF): Parses SPF records to extract IPs and domains
- Deduplicates values
- Limits to `MAX_DNS_CHILDREN` (default 25) to prevent explosion

---

### `#extract_iocs` - Extract IOCs from Text

Extracts IP addresses and domains from text fields using regex.

```json
"domain-ip": {
  "obj:handler": "{{#extract_iocs some_text_field ip,domain}}"
}
```

**Arguments:**
- `path` - Path to text field or array
- `types` - Comma-separated: `ip`, `domain`

---

## Tags

Tags are created from attribute mappings that use a namespace prefix.

### Tag Syntax

```json
{
  "rl:classification": "{{#ref classification}}",
  "rl:riskscore": "{{#ref riskscore}}"
}
```

**Field naming conventions:**

| Pattern | Behavior |
|---------|----------|
| `namespace:key` | Creates single tag `namespace:key="value"` |
| `namespace:key[]` | Creates multiple tags (with `#foreach` directive) |
| `namespace:key:` | Creates multiple tags (legacy `#tags_from` handler) |

### Examples

```json
{
  // Single value tag
  "rl:classification": "{{#ref sample_summary.classification}}",
  
  // Multiple tags from list using foreach (recommended)
  "rl:threat[]": "{{#foreach top_threats}}{{#ref threat_name}}{{/foreach}}",
  
  // Multiple tags from list using legacy tags_from
  "rl:threat_name:": "{{#tags_from top_threats threat_name threat}}"
}
```

**Given API data:**
```json
{
  "sample_summary": {
    "classification": "MALICIOUS"
  },
  "top_threats": [
    {"threat_name": "Trojan.X"},
    {"threat_name": "Malware.Y"}
  ]
}
```

**Created tags:**
```
rl:classification="MALICIOUS"
rl:threat="Trojan.X"
rl:threat="Malware.Y"
```

---

## Relationships

MISP objects can reference each other via relationships. These are defined using `obj:<relationship>->` directives.

### Relationship Types

| Directive | Relationship | Use Case |
|-----------|--------------|----------|
| `obj:analysed-with->` | analysed-with | Link IOC to analysis report |
| `obj:related-to->` | related-to | General relationship |
| `obj:contains->` | contains | Parent contains child |

Note: these three are common examples but not a hard limit — you may declare any relationship
name using the `obj:<relationship>->` directive. The handler will create object references
using the relationship string you provide (e.g. `obj:observed-with->`, `obj:derived-from->`).
When creating references the mapping value can be a single type name, a list, or `"*"`
to target all nested children.

### Syntax

```json
{
  "file": {
    "obj:type": "file",
    "obj:analysed-with->": ["report"],
    "sha256": "{{#ref sample_summary.sha256}}",
    
    "report": {
      "obj:type": "report",
      "title": "Analysis Report"
    }
  }
}
```

This creates:
1. A `file` object
2. A `report` object (nested)
3. An `analysed-with` reference from `file` → `report`

### Multiple Targets

```json
{
  "obj:related-to->": ["report", "dns-record"],
  "obj:contains->": ["domain-ip", "ip-port"]
}
```

### Wildcard Target

```json
{
  "obj:contains->": "*"
}
```

Links to all nested child objects.

---

## Nested Objects

Objects can be nested to create hierarchies. The nesting defines the structure, and relationship directives define how objects link.

### Basic Nesting

```json
{
  "domain-ip": {
    "obj:type": "domain-ip",
    "obj:analysed-with->": ["report"],
    "domain": "{{#ref requested_domain}}",
    
    "report": {
      "obj:type": "report",
      "obj:related-to->": ["dns-record"],
      "title": "Domain Report",
      
      "dns-record": {
        "obj:type": "dns-record",
        "queried-domain": "{{#ref requested_domain}}",
        "a-record": "{{#dns_records A last_dns_records}}"
      }
    }
  }
}
```

**Creates this object hierarchy:**

```
domain-ip
  └── analysed-with ──→ report
                          └── related-to ──→ dns-record
```

### Dynamic Children with Handlers

```json
{
  "dns-record": {
    "obj:type": "dns-record",
    "queried-domain": "{{#ref requested_domain}}",
    
    "domain-ip": {
      "obj:handler": "{{#iterate_dns last_dns_records A,AAAA,NS,CNAME,MX,TXT}}"
    }
  }
}
```

The `iterate_dns` handler creates multiple `domain-ip` child objects—one for each DNS record matching the specified types.

---

## Foreach Iteration

Create multiple objects from array data using **foreach iteration**. This is a declarative alternative to handlers like `iterate_dns`.

### Syntax

Use the `obj:path` directive to specify the source data path. The `[]` suffix supports optional limit:

```json
// Basic iteration (default limit: 1000, effective: 25 for objects)
"child-name[]": {
  "obj:type": "object-type",
  "obj:path": "array_path",
  "attr": "{{#ref field}}"
}

// With explicit limit
"child-name[100]": {
  "obj:type": "object-type",
  "obj:path": "array_path",
  "attr": "{{#ref field}}"
}

// With filter
"child-name[]": {
  "obj:type": "object-type",
  "obj:path": "array_path[field=val1,val2]",
  "attr": "{{#ref field}}"
}

// With filter AND limit
"child-name[50]": {
  "obj:type": "object-type",
  "obj:path": "array_path[field=val1,val2]",
  "attr": "{{#ref field}}"
}
```

**Key suffix patterns:**

| Pattern | Meaning |
|---------|---------|
| `key[]` | Iterate with default limit (25 for objects) |
| `key[100]` | Iterate with explicit limit of 100 |
| `key[filter]` | Iterate with filter (default limit) |
| `key[50]` + `obj:path` with filter | Limit on key, filter in obj:path |

**Auto-detection behavior:**
- If the path points to an **array** → iterates over each item, creating multiple objects
- If the path points to a **single object** → uses it directly, creating one object

The `[]` on the key name is optional but recommended as a visual indicator that multiple objects may be created.

### Basic Foreach

Create one object per array item using `obj:path`:

```json
{
  "dns-record": {
    "obj:type": "dns-record",
    "queried-domain": "{{#ref requested_domain}}",
    
    "dns-ips[]": {
      "obj:type": "ip-port",
      "obj:path": "last_dns_records[]",
      "obj:comment": "IP from DNS record",
      "ip": "{{#ref value | ip}}"
    }
  }
}
```

For each item in `last_dns_records`, creates an `ip-port` object. Inside the template, `{{#ref value}}` refers to the current item's `value` field.

### Filtered Foreach

Only process items matching a condition:

```json
{
  "dns-record": {
    "obj:type": "dns-record",
    
    "#COMMENT": "Create IP objects only from A and AAAA records",
    "dns-ips[]": {
      "obj:type": "ip-port",
      "obj:path": "last_dns_records[type=A,AAAA]",
      "ip": "{{#ref value | ip}}"
    },
    
    "#COMMENT": "Create domain objects from NS, CNAME, MX records",
    "dns-hostnames[]": {
      "obj:type": "domain-ip",
      "obj:path": "last_dns_records[type=NS,CNAME,MX]",
      "hostname": "{{#ref value | hostname}}"
    }
  }
}
```

### Filter Syntax

| Syntax | Meaning |
|--------|---------|
| `array[]` | All items |
| `array[field=value]` | Items where `field == value` |
| `array[field=a,b,c]` | Items where `field` is `a`, `b`, or `c` (OR) |
| `array[f1=a;f2=b]` | Items where `f1` is `a` AND `f2` is `b` |
| `array[f1=a,b;f2=c]` | Combined: `f1` in (`a`,`b`) AND `f2` is `c` |

### Context Inside Foreach

Inside a foreach template, paths are relative to the current array item:

```json
{
  "threats[]": {
    "obj:type": "malware",
    "obj:path": "top_threats[]",
    "name": "{{#ref threat_name}}",
    "family": "{{#ref threat_family}}",
    "confidence": "{{#ref confidence}}"
  }
}
```

If API returns:
```json
{
  "top_threats": [
    {"threat_name": "Trojan.Generic", "threat_family": "Trojan", "confidence": 95},
    {"threat_name": "Ransom.WannaCry", "threat_family": "Ransomware", "confidence": 87}
  ]
}
```

Creates 2 `malware` objects with their respective values.

---

## Nested Fetch

Fetch additional data from a separate API endpoint and create objects from it using `obj:fetch`.

### Syntax

```json
{
  "obj:fetch": {
    "obj:uri": "/api/path/{placeholder}/",
    "object_name[]": {
      "obj:type": "object-type",
      "attr": "{{#ref field}}"
    }
  }
}
```

### Example: Extracted Files

```json
{
  "file": {
    "obj:type": "file",
    "!sha256": "{{#ref sample_summary.sha256}}",
    
    "obj:contains->": ["extracted-files"],
    "obj:fetch": {
      "obj:uri": "/api/samples/{sha256}/extracted-files/",
      "extracted-files[]": {
        "obj:type": "file",
        "obj:comment": "File extracted from parent sample",
        "filename": "{{#ref filename}}",
        "md5": "{{#ref sample.md5}}",
        "sha256": "{{#ref sample.sha256}}"
      }
    }
  }
}
```

This:
1. Creates the parent `file` object
2. Fetches data from `/api/samples/{sha256}/extracted-files/` (substituting the actual sha256)
3. Creates a `file` object for each extracted file
4. Creates "contains" relationships from parent to each extracted file

### Placeholders

The `uri` supports placeholders that are replaced with values from the current data context. Any key from the parent object's data can be used as a placeholder:

```json
"obj:uri": "/api/samples/{sha256}/extracted-files/"
"obj:uri": "/api/network/{domain}/subdomains/"
"obj:uri": "/api/custom/{my_custom_field}/data/"
```

**Built-in fallbacks** (use original IOC value if not found in data):
- `{hash}` - Falls back to original value for file IOCs
- `{domain}` - Falls back to original value for domain IOCs  
- `{ip}` - Falls back to original value for IP IOCs
- `{url}` - Falls back to original value for URL IOCs
- `{value}` - Always the original IOC value

**Data context keys** are sourced from:
1. Top-level fields in the current object's data
2. Nested `sample_summary` fields (for file enrichment)

### Multiple Fetches

To fetch from multiple endpoints in the same object, use numeric-index suffixes (`obj:fetch[0]`, `obj:fetch[1]`, …) — JSON does not allow duplicate keys:

```json
{
  "file": {
    "obj:type": "file",
    "!sha256": "{{#ref sample_summary.sha256}}",
    
    "obj:contains->": "*",
    
    "obj:fetch[0]": {
      "obj:uri": "/api/samples/{sha256}/extracted-files/",
      "extracted-files[]": {
        "obj:type": "file",
        "obj:comment": "File extracted from parent",
        "sha256": "{{#ref sample.sha256}}"
      }
    },
    
    "obj:fetch[1]": {
      "obj:uri": "/api/samples/{sha256}/downloaded-files/",
      "downloaded-files[]": {
        "obj:type": "file",
        "obj:comment": "File downloaded during analysis",
        "sha256": "{{#ref sample.sha256}}"
      }
    }
  }
}
```

Each `obj:fetch[N]` is fetched sequentially (not in parallel); both sets of child objects receive "contains" relationships from the parent (`"obj:contains->": "*"`).

### Timeout and Error Handling

Nested fetch calls are designed to fail gracefully — a failing fetch **will not** crash the entire enrichment. Instead:

1. **Default timeout**: 30 seconds per request
2. **Retries**: 3 automatic retries with exponential backoff (via the shared session)
3. **Error tag**: On failure, an `rl:fetch-error` tag is added to the event for visibility

**Custom timeout** — use `obj:timeout` to override the default (in seconds):

```json
"obj:fetch": {
  "obj:uri": "/api/samples/{sha256}/extracted-files/",
  "obj:timeout": 60,
  "extracted-files[]": { ... }
}
```

**Error tag examples**:

| Scenario | Tag Value |
|----------|-----------|
| Request timed out | `rl:fetch-error="extracted-files: timeout after 30s"` |
| Connection failed | `rl:fetch-error="extracted-files: connection error"` |
| HTTP 404 | `rl:fetch-error="extracted-files: HTTP 404"` |
| Invalid JSON | `rl:fetch-error="extracted-files: invalid JSON response"` |

The parent object and other fetches continue processing normally even if one fails.

### Response Unwrapping

The nested endpoint handler automatically unwraps common response formats:

| Response Format | Unwrapped To |
|-----------------|--------------|
| `{"results": [...]}` | The array |
| `{"extracted_files": [...]}` | The array |
| `{"downloaded_files": [...]}` | The array |
| `[...]` (direct array) | Used as-is |

---

## Complete Examples

### File Enrichment

```json
{
  "file": {
    "file": {
      "obj:type": "file",
      "obj:comment": "File object with hash identifiers from ReversingLabs analysis",
      
      "md5": "{{#ref sample_summary.md5 | md5}} {{#Comment MD5 hash of the analyzed file}}",
      "sha1": "{{#ref sample_summary.sha1 | sha1}} {{#Comment SHA1 hash of the analyzed file}}",
      "sha256": "{{#ref sample_summary.sha256 | sha256}} {{#Comment SHA256 hash (primary identifier)}}",
      "filename": "{{#ref sample_summary.identification_name | file_name}} {{#Comment Original or identified filename}}",
      "size-in-bytes": "{{#ref sample_summary.file_size | file_size}} {{#Comment File size in bytes}}",
      "mimetype": "{{#ref sample_summary.file_type | file_type}} {{#Comment Detected file type}}",
      "text": "{{#ref sample_summary.classification | threat_name}} {{#Comment Threat classification name}}",
      "entropy": "{{#ref sample_summary.entropy | entropy}} {{#Comment File entropy value}}",
      
      "rl:classification": "{{#ref sample_summary.classification}}",
      "rl:riskscore": "{{#ref sample_summary.riskscore}}",
      "rl:threat_level": "{{#ref sample_summary.threat_level}}",
      
      "obj:analysed-with->": ["report"],
      
      "report": {
        "obj:type": "report",
        "obj:comment": "ReversingLabs file analysis report",
        "link": "{{#build_link file}}",
        "title": "ReversingLabs File Analysis",
        "type": "threat-intelligence",
        "summary": "{{#summary}}"
      }
    }
  }
}
```

### Domain Enrichment (with Nested Foreach)

```json
{
  "domain": {
    "domain-ip": {
      "obj:type": "domain-ip",
      "obj:comment": "Domain with threat intelligence and DNS resolution data",
      
      "domain": "{{#ref requested_domain | domain}}",
      "first-seen": "{{#ref first_seen}}",
      "last-seen": "{{#ref last_seen}}",
      "text": "{{#list_items top_threats threat_name}}",
      
      "rl:threat_name:": "{{#tags_from top_threats threat_name threat}}",
      "rl:threat_family:": "{{#tags_from top_threats threat_family malware-family}}",
      
      "obj:analysed-with->": ["report"],
      
      "report": {
        "obj:type": "report",
        "obj:comment": "ReversingLabs domain report",
        "title": "ReversingLabs Domain Report",
        "type": "threat-intelligence",
        "summary": "{{#summary}}",
        "link": "{{#build_link domain}}",
        
        "obj:related-to->": ["dns-record"],
        
        "dns-record": {
          "obj:type": "dns-record",
          "obj:comment": "DNS resolution records for the domain",
          "queried-domain": "{{#ref requested_domain | domain}}",
          "a-record": "{{#dns_records A last_dns_records}}",
          "aaaa-record": "{{#dns_records AAAA last_dns_records}}",
          "cname-record": "{{#dns_records CNAME last_dns_records}}",
          "mx-record": "{{#dns_records MX last_dns_records}}",
          "ns-record": "{{#dns_records NS last_dns_records}}",
          "txt-record": "{{#dns_records TXT last_dns_records}}",
          
          "obj:contains->": "*",
          
          "#COMMENT": "Create IP objects from A and AAAA records",
          "dns-ips[]": {
            "obj:type": "ip-port",
            "obj:path": "last_dns_records[type=A,AAAA]",
            "obj:comment": "IP address resolved from DNS record",
            "ip": "{{#ref value | ip}}"
          },
          
          "#COMMENT": "Create domain objects from NS, CNAME, MX records",
          "dns-hostnames[]": {
            "obj:type": "domain-ip",
            "obj:path": "last_dns_records[type=NS,CNAME,MX]",
            "obj:comment": "Domain resolved from DNS record",
            "hostname": "{{#ref value | hostname}}"
          }
        }
      }
    }
  }
}
```

This example demonstrates:

1. **`child-name[]` convention** - The `[]` suffix on keys like `dns-ips[]` visually indicates foreach iteration
2. **`obj:path` directive** - Specifies the source array and optional filter
3. **Filtered iteration** - `[type=A,AAAA]` creates `ip-port` objects only from A/AAAA records
4. **Wildcard relationship** - `"obj:contains->": "*"` creates relationships to all dynamically-created child objects
4. **Context-relative paths** - Inside foreach templates, `{{#ref value}}` references the current array item's `value` field
5. **Logical child names** - Keys like `dns-ips` and `dns-hostnames` are descriptive labels, not data paths

---

## API Response Examples

### File Analysis Response

```json
{
  "sample_summary": {
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "md5": "d41d8cd98f00b204e9800998ecf8427e",
    "identification_name": "suspicious.exe",
    "file_size": 245760,
    "file_type": "PE32 executable",
    "classification": "MALICIOUS",
    "classification_source": "TitaniumCloud",
    "classification_reason": "Trojan.Generic",
    "riskscore": 8,
    "threat_level": 5,
    "trust_factor": 2,
    "entropy": 7.234,
    "extracted_file_count": 12
  }
}
```

**Resulting MISP objects:**

1. **file** object:
   - `md5`: d41d8cd98f00b204e9800998ecf8427e
   - `sha1`: da39a3ee5e6b4b0d3255bfef95601890afd80709
   - `sha256`: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
   - `filename`: suspicious.exe
   - `size-in-bytes`: 245760
   - `mimetype`: PE32 executable
   - `text`: MALICIOUS
   - `entropy`: 7.234

2. **report** object:
   - `link`: https://a1000.reversinglabs.com/e3b0c44298fc...
   - `title`: ReversingLabs File Analysis
   - `type`: threat-intelligence
   - `summary`: Classification: MALICIOUS...

3. **Tags:**
   - `rl:classification="MALICIOUS"`
   - `rl:riskscore="8"`
   - `rl:threat_level="5"`

4. **Relationships:**
   - file → analysed-with → report

---

### Domain Analysis Response

```json
{
  "requested_domain": "malicious-example.com",
  "first_seen": "2024-01-15T10:30:00Z",
  "last_seen": "2024-06-20T14:22:00Z",
  "top_threats": [
    {"threat_name": "Trojan.Downloader", "threat_family": "Trojan", "count": 45},
    {"threat_name": "Ransomware.Crypto", "threat_family": "Ransomware", "count": 12}
  ],
  "last_dns_records": [
    {"type": "A", "value": "93.184.216.34"},
    {"type": "A", "value": "93.184.216.35"},
    {"type": "MX", "value": "mail.malicious-example.com"},
    {"type": "NS", "value": "ns1.malicious-example.com"},
    {"type": "TXT", "value": "v=spf1 ip4:192.168.1.1 include:spf.example.com -all"}
  ]
}
```

**Resulting MISP objects:**

1. **domain-ip** object:
   - `domain`: malicious-example.com
   - `first-seen`: 2024-01-15T10:30:00Z
   - `last-seen`: 2024-06-20T14:22:00Z
   - `text`: Trojan.Downloader, Ransomware.Crypto

2. **report** object:
   - `title`: ReversingLabs Domain Report
   - `summary`: Domain: malicious-example.com...
   - `link`: https://a1000.reversinglabs.com/domain/malicious-example.com/...

3. **dns-record** object:
   - `queried-domain`: malicious-example.com
   - `a-record`: 93.184.216.34, 93.184.216.35
   - `mx-record`: mail.malicious-example.com
   - `ns-record`: ns1.malicious-example.com
   - `txt-record`: v=spf1 ip4:192.168.1.1 include:spf.example.com -all

4. **domain-ip** child objects (from `iterate_dns`):
   - domain-ip with `ip`: 93.184.216.34
   - domain-ip with `ip`: 93.184.216.35
   - domain-ip with `hostname`: mail.malicious-example.com
   - domain-ip with `hostname`: ns1.malicious-example.com
   - domain-ip with `ip`: 192.168.1.1 (from SPF)
   - domain-ip with `hostname`: spf.example.com (from SPF)

5. **Tags:**
   - `rl:threat="Trojan.Downloader"`
   - `rl:threat="Ransomware.Crypto"`
   - `rl:malware-family="Trojan"`
   - `rl:malware-family="Ransomware"`

6. **Relationships:**
   - domain-ip → analysed-with → report
   - report → related-to → dns-record
   - dns-record → contains → domain-ip (for each child)

---

## Quick Reference

### Handler Cheat Sheet

| Handler | Purpose | Example |
|---------|---------|---------|
| `#ref` | Extract value from path | `{{#ref sample_summary.sha256}}` |
| `#summary` | Generate IOC summary | `{{#summary}}` |
| `#build_link` | Create portal URL | `{{#build_link file}}` |
| `#list_items` | Join list field values | `{{#list_items top_threats threat_name}}` |
| `#tags_from` | Create tags from list | `{{#tags_from top_threats threat_name threat}}` |
| `#dns_records` | Filter DNS by type | `{{#dns_records A last_dns_records}}` |
| `#iterate_dns` | Create children from DNS | `{{#iterate_dns records A,AAAA}}` |
| `#extract_iocs` | Extract IOCs from text | `{{#extract_iocs text_field ip,domain}}` |

### Object Directive Cheat Sheet

| Directive | Purpose |
|-----------|---------|
| `obj:type` | MISP object type |
| `obj:comment` | Object description |
| `obj:fetch` | Array = top-level endpoints; Dict = nested fetch |
| `obj:path` | Foreach iteration path with optional filter |
| `obj:analysed-with->` | Create analysed-with relationship |
| `obj:related-to->` | Create related-to relationship |
| `obj:contains->` | Create contains relationship |
| `obj:handler` | Invoke handler for dynamic children |
| `obj:timeout` | Timeout for obj:fetch in seconds |

### DSL Syntax Cheat Sheet

| Syntax | Meaning |
|--------|---------|
| `{{#handler args}}` | Invoke handler |
| `path.field` | Dot-notation path access |
| `path[0]` | Array index access (0-indexed) |
| `path[0].field` | Field from array element |
| `path1 \| path2` | Fallback paths (tried in order) |
| `path (type)` | MISP type hint (e.g., `(ip-dst)`, `(sha256)`) |
| `(int) path` | Type coercion prefix |
| `{{#Comment text}}` | Inline comment |
| `attr#N` | Key uniqueness suffix (stripped at runtime) |
| `namespace:key` | Tag field |
| `namespace:key[]` | Multi-tag field (foreach array mode) |
| `namespace:key:` | Multi-tag field (legacy `#tags_from`) |
| `!attr_name` | Promote to event-level attribute |
| `# attr_name` | Disabled attribute (skipped) |
| `obj:path: "array[]"` | Foreach: iterate all items |
| `obj:path: "array[field=val]"` | Foreach: filter by field value |
