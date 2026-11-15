using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using Kusto.Language;
using Kusto.Language.Symbols;

var schemas = JsonDocument.Parse(File.ReadAllText(args.Length > 0 ? args[0] : "schemas.json"));
var tables = schemas.RootElement.EnumerateObject().Select(table => new TableSymbol(table.Name,
    table.Value.GetProperty("columns").EnumerateObject().Select(column => new ColumnSymbol(column.Name,
        column.Value.GetString() switch {
            "string" => ScalarTypes.String,
            "datetime" => ScalarTypes.DateTime,
            "long" => ScalarTypes.Long,
            "int" => ScalarTypes.Int,
            "bool" or "boolean" => ScalarTypes.Bool,
            "real" or "double" => ScalarTypes.Real,
            "dynamic" => ScalarTypes.Dynamic,
            _ => throw new InvalidDataException($"Unknown schema type for {table.Name}.{column.Name}")
        }))));
var globals = GlobalState.Default.WithDatabase(new DatabaseSymbol("Defender", tables));

// Negative control: this file hash column does not exist on network events.
if (!KustoCode.ParseAndAnalyze("DeviceNetworkEvents | where MD5 == 'a'", globals)
    .GetDiagnostics().Any(d => d.Severity.ToString() == "Error")) {
    throw new InvalidOperationException("Analyzer failed the unknown-column negative control.");
}

var failed = 0;
var count = 0;
foreach (var query in File.ReadLines(args.Length > 1 ? args[1] : "queries.kql")) {
    count++;
    var diagnostics = KustoCode.ParseAndAnalyze(query, globals).GetDiagnostics();
    foreach (var diagnostic in diagnostics.Where(d => d.Severity.ToString() == "Error")) {
        Console.WriteLine($"Query {count}: {diagnostic.Code} at {diagnostic.Start}: {diagnostic.Message}");
        failed++;
    }
}
Console.WriteLine($"Analyzed {count} queries; {failed} errors.");
Environment.ExitCode = failed == 0 ? 0 : 1;
