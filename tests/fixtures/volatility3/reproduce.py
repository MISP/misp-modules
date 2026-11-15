"""Render synthetic plugin-shaped TreeGrids with Volatility 3 2.28.2.

Requires that version only for fixture reproduction, never for the importer.
The plugin run() column lists are read from the installed upstream package.
No memory image is analyzed and no plugin generator is executed.
"""

import ast
import contextlib
import datetime
import hashlib
import io
import json
from pathlib import Path

import volatility3
from volatility3.cli.text_renderer import JsonLinesRenderer, JsonRenderer
from volatility3.framework import constants, contexts, renderers
from volatility3.framework.layers.physical import BufferDataLayer
from volatility3.framework.renderers import format_hints

PLUGINS = {
    "pslist": "windows.pslist.PsList",
    "psscan": "windows.psscan.PsScan",
    "pstree": "windows.pstree.PsTree",
    "cmdline": "windows.cmdline.CmdLine",
    "netscan": "windows.netscan.NetScan",
    "netstat": "windows.netstat.NetStat",
    "malfind": "windows.malware.malfind.Malfind",
    "vadyarascan": "windows.vadyarascan.VadYaraScan",
    "yarascan": "yarascan.YaraScan",
}


def main():
    assert constants.PACKAGE_VERSION == "2.28.2", constants.PACKAGE_VERSION
    root = Path(volatility3.__file__).parent / "framework/plugins"
    directory = Path(__file__).parent
    context = contexts.Context()
    buffer = b"MZ\x90\x00synthetic match"
    context.layers.add_layer(BufferDataLayer(context, "fixture", "synthetic", buffer))
    data = renderers.LayerData(context, "synthetic", 0, len(buffer), no_surrounding=True)
    created = datetime.datetime(2026, 10, 10, 12, 0, 0, 123456, datetime.timezone.utc)
    manifest = {}
    for name, plugin in PLUGINS.items():
        path = root / (plugin.rsplit(".", 1)[0].replace(".", "/") + ".py")
        source = ast.parse(path.read_text())
        run = next(n for n in ast.walk(source) if isinstance(n, ast.FunctionDef) and n.name == "run")
        grid = next(
            n
            for n in ast.walk(run)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "TreeGrid"
        )
        columns = eval(
            compile(ast.Expression(grid.args[0]), str(path), "eval"),
            {
                "datetime": datetime,
                "renderers": renderers,
                "format_hints": format_hints,
                "offsettype": "(P)" if name == "psscan" else "(V)",
            },
        )
        versions = [
            n.value
            for n in ast.walk(source)
            if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "_version" for t in n.targets)
        ]
        metadata = {
            "plugin": plugin,
            "volatility_version": constants.PACKAGE_VERSION,
            "image_name": "synthetic.raw",
            "image_sha256": hashlib.sha256(buffer).hexdigest(),
        }
        if versions:
            metadata["plugin_version"] = ".".join(map(str, ast.literal_eval(versions[0])))
        if name == "yarascan":
            metadata["layer_name"] = "synthetic"
        rows = []
        for i in range(2):
            values = {
                "PID": 4 if i == 0 else 100,
                "PPID": 0 if i == 0 else 4,
                "ImageFileName": "System" if i == 0 else "cmd.exe",
                "Process": "System" if i == 0 else "cmd.exe",
                "Owner": "System" if i == 0 else "cmd.exe",
                "CreateTime": created + datetime.timedelta(seconds=i),
                "ExitTime": renderers.NotAvailableValue(),
                "Created": created,
                "Offset(V)": format_hints.Hex(0xFFFF800000001000 + i * 4096),
                "Offset(P)": format_hints.Hex(0x12345000 + i * 4096),
                "Offset": format_hints.Hex(0x1234 + i),
                "Args": '"C:\\Windows\\System32\\cmd.exe" /c echo example',
                "Cmd": "cmd.exe /c echo example",
                "Path": "C:\\Windows\\System32\\cmd.exe",
                "Threads": 3,
                "Handles": renderers.UnreadableValue(),
                "SessionId": 1,
                "Wow64": False,
                "Audit": "C:\\Windows\\System32\\cmd.exe",
                "File output": "Disabled",
                "Proto": "TCPv4" if i == 0 else "UDPv6",
                "LocalAddr": "10.0.0.5" if i == 0 else "::",
                "LocalPort": 49152 if i == 0 else 53,
                "ForeignAddr": "203.0.113.5" if i == 0 else "*",
                "ForeignPort": 443 if i == 0 else 0,
                "State": "ESTABLISHED" if i == 0 else renderers.NotApplicableValue(),
                "Start VPN": format_hints.Hex(0x1000),
                "End VPN": format_hints.Hex(0x1FFF),
                "Protection": "PAGE_EXECUTE_READWRITE",
                "Tag": "VadS",
                "CommitCharge": 1,
                "PrivateMemory": 1,
                "Notes": "Synthetic suspicious region",
                "Hexdump": data,
                "Disasm": renderers.NotAvailableValue(),
                "Rule": "ExampleRule",
                "Component": "$example",
                "Value": data,
            }
            rows.append(
                (
                    i if name == "pstree" else 0,
                    tuple(values.get(column, renderers.NotAvailableValue()) for column, _ in columns),
                )
            )
        for extension, renderer in [("json", JsonRenderer), ("jsonl", JsonLinesRenderer)]:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                renderer().render(renderers.TreeGrid(columns, iter(rows)))
            filename = name + "." + extension
            (directory / filename).write_text(output.getvalue())
            manifest[filename] = metadata
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
