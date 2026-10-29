# DomainTools module support and coverage

The bundled `domaintools` expansion and hover module uses the DomainTools Python API client with a username and API key. Its source carries a warning that the module does not appear to be actively maintained.

## Existing lookups

Domain attributes use parsed WHOIS, domain profile, reputation and reverse-IP services. Registrant email, name and phone attributes use reverse WHOIS. IP attributes use host-domain lookup. Results are mapped to MISP attributes such as domains, WHOIS fields and explanatory text.

An existing module is not evidence that every service remains available under a current subscription. Confirm the API endpoints, account entitlements and Python client compatibility before deploying it. The current module does not implement Iris Investigate or Iris Enrich.

## Provider supported integration

DomainTools maintains a separate MISP integration at https://github.com/DomainTools/domaintools_misp. Evaluate its supported services and deployment instructions when choosing a maintained integration. The bundled module and that integration have separate installation and configuration requirements; this guide does not migrate credentials or replace either installation.

## Future maintenance

A functional update should select the required DomainTools service, document supported account entitlements, preserve current configuration where possible, and supply sanitized response fixtures and mapping tests for the selected API. New API coverage should have its own explicit module name when its authentication or output contract differs materially from the legacy module.
