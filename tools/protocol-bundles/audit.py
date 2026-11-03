"""Compatibility calls into Rust symbol ownership rules until the builder migration."""

import json
from pathlib import Path
import sys

from provenance import _request
from symbol_tool import compiler_debug_metadata, inspect

GDB_SCRIPT = "__rustc_debug_gdb_scripts_section__"
INPUT_RUNTIME = {"DW.ref.rust_eh_personality", GDB_SCRIPT}


def _audit(operation, **values):
    return _request(dict(operation=operation, working_directory=str(Path.cwd()), **values),
                    command="audit-symbols")


def definitions(path, globals_only=True):
    arguments = ["-g", path] if globals_only else [path]
    return _audit("parse_definitions", text=inspect(arguments), darwin=sys.platform == "darwin")


def suffix(version):
    return "".join(c if c.isascii() and c.isalnum() else "_" for c in version)


def owner(name, graph, version, path=None, value=None):
    return _audit("owner", name=name, graph=graph, version=version,
                  path=str(path) if path is not None else None, value=value)


def private_local_inputs(graphs):
    sets, inventories = _audit("private_local", graphs=graphs)
    return list(map(set, sets)), inventories


def audit_inputs(graphs, output):
    result = _audit("inputs", graphs=graphs)
    (output / "input-ownership.json").write_text(json.dumps(result["inventory"], sort_keys=True) + "\n")
    return list(map(set, result["sets"])), result["versions"]


def audit_final(executable, graphs, sets, versions, output, common, kind="proof", node=None):
    result = _audit("final", executable=str(executable), graphs=graphs, sets=list(map(sorted, sets)),
                    versions=versions, common=common, kind=kind, node=node or {})
    if result["local_inventory"] is not None:
        (output / "input-local-ownership.json").write_text(json.dumps(result["local_inventory"], sort_keys=True) + "\n")
    (output / "final-ownership.json").write_text(json.dumps(result["attributed"], sort_keys=True) + "\n")
    return result["result"]
