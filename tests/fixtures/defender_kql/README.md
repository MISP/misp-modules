# Independent KQL validation

`schemas.json` captures column names and types from the eight linked Microsoft Learn Advanced Hunting table pages on 2026-11-15. The snapshot is independent of the exporter's field mapping. Normal Python regression tests check selected mappings against it.

`Validator.csproj` pins Microsoft's `Microsoft.Azure.Kusto.Language` package at 12.4.1. `Program.cs` registers the captured schemas and runs `KustoCode.ParseAndAnalyze` on generated queries, failing on syntax, binding or type errors. `generate_queries.py` covers individual and mixed indicator types, optional tables, exact/subdomain host matching, escaped URL literals, IPv4/IPv6, absolute time ranges and single-indicator batches.

From the repository root, with .NET SDK 8 installed:

```sh
PYTHONPATH=. python tests/fixtures/defender_kql/generate_queries.py > /tmp/defender-queries.kql
dotnet run --project tests/fixtures/defender_kql/Validator.csproj -- tests/fixtures/defender_kql/schemas.json /tmp/defender-queries.kql
```

Alternatively run the validator in `mcr.microsoft.com/dotnet/sdk:8.0` with the repository and query file mounted. NuGet restore needs network access. No Defender credentials or live query execution are involved. The analyzer validates against this schema snapshot, not a live tenant; table availability, service behavior, regex/URL evaluation, performance and telemetry matching require validation in the target tenant.

To refresh the snapshot, obtain each table's column-name/type rows from its `source` URL. Keep the snapshot independent of `TABLE_FIELDS` rather than deriving it from the implementation.
