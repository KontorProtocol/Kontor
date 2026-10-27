"""Attribute every link-visible input definition before the linker can coalesce it."""

import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

INPUT_RUNTIME = {"DW.ref.rust_eh_personality"}
FINAL_RUNTIME = INPUT_RUNTIME | {
    "rust_eh_personality", "main", "_start", "__TMC_END__", "__bss_end__",
    "__bss_start", "__bss_start__", "__dso_handle", "__end__", "__bss_end__",
    "_bss_end__", "_edata", "_end", "_fini", "_init", "__aarch64_cpu_features",
    "__aarch64_have_lse_atomics", "__init_cpu_features", "__pthread_atfork",
    "__udivti3", "__umodti3",
}
RUST = re.compile(r"(?:_ZN.+17h[0-9a-f]{16}E|_R[A-Z].+)(?:\.llvm\.\d+)?$")
ANONYMOUS = re.compile(r"anon\.[0-9a-f]+\.\d+(?:\.llvm\.\d+)?$")
ALLOCATOR = re.compile(r"__(?:rg|rust)_(?:alloc|dealloc|realloc|alloc_zeroed|alloc_error_handler)(?:$|[^a-z_])")


def definitions(path, globals_only=True):
    command = ["nm", "-g", str(path)] if globals_only else ["nm", str(path)]
    result = subprocess.run(command, text=True, capture_output=True, check=True)
    symbols = {}
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) != 3 or not re.fullmatch(r"[0-9a-fA-F]+", fields[0]):
            continue
        address, kind, name = fields
        if kind.upper() == "U":
            continue
        if sys.platform == "darwin":
            name = name.removeprefix("_")
        symbols[name] = {"address": address, "kind": kind}
    return symbols


def suffix(version):
    return "".join(c if c.isascii() and c.isalnum() else "_" for c in version)


def owner(name, graph, version):
    if name in INPUT_RUNTIME:
        return "common compiler runtime"
    if ALLOCATOR.search(name):
        raise RuntimeError(f"bundle defines process allocator: {name}")
    if RUST.fullmatch(name) or ANONYMOUS.fullmatch(name):
        return graph["graph"]
    if name.startswith("wasmtime_") and name.endswith("_" + suffix(version)):
        return graph["graph"]
    if name.startswith(graph["namespace"] + "_"):
        return graph["graph"]
    raise RuntimeError(f"unowned native input definition in {graph['graph']}: {name}")


def audit_inputs(graphs, output):
    versions = [next(p["version"] for p in graph["packages"] if p["name"] == "wasmtime") for graph in graphs]
    if len(set(versions)) != len(graphs) or len({suffix(v) for v in versions}) != len(graphs):
        raise RuntimeError("independent Wasmtime graphs must have unique versions and native prefixes")
    inventories = []
    sets = []
    for graph, version in zip(graphs, versions, strict=True):
        paths = {Path(a["path"]) for a in graph["artifacts"]}
        paths.update(Path(item["path"]) for item in graph["native_artifacts"])
        all_names = set()
        inventory = []
        for path in sorted(paths):
            symbols = definitions(path)
            for name in symbols:
                owner(name, graph, version)
            all_names.update(symbols)
            inventory.append({"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                              "definitions": symbols})
        sets.append(all_names)
        inventories.append({"graph": graph["graph"], "inputs": inventory})
    for index, names in enumerate(sets):
        for previous in range(index):
            collisions = (names & sets[previous]) - INPUT_RUNTIME
            if collisions:
                raise RuntimeError(f"cross-graph definitions would coalesce: {sorted(collisions)[:100]}")
    (output / "input-ownership.json").write_text(json.dumps(inventories, sort_keys=True) + "\n")
    return sets, versions


def audit_final(executable, graphs, sets, versions, output, common):
    symbols = definitions(executable)
    attributed = {}
    for name, value in symbols.items():
        matches = [graph["graph"] for graph, names in zip(graphs, sets, strict=True) if name in names]
        if name in FINAL_RUNTIME or (sys.platform == "darwin" and name == "_mh_execute_header"):
            attribution = "common compiler/linker runtime"
        elif len(matches) == 1:
            attribution = matches[0]
        elif not matches and name in common:
            attribution = {"common_inputs": common[name]}
        else:
            raise RuntimeError(f"ambiguous or unowned final definition: {name}: {matches}")
        attributed[name] = dict(value, owner=attribution)
    helpers = ["wasmtime_libunwind_" + suffix(version) for version in versions]
    if any(name not in symbols for name in helpers):
        raise RuntimeError("missing graph-private Wasmtime native helper")
    if len({symbols[name]["address"] for name in helpers}) != len(helpers):
        raise RuntimeError("Wasmtime graph-private helpers alias one address")
    crypto = []
    for graph in graphs:
        crypto.extend(graph["namespace"] + "_" + name for name in (
            "blst_keygen", "rustsecp256k1_v0_10_0_ecdsa_sign_recoverable",
            "rustsecp256k1_v0_10_0_default_illegal_callback_fn",
            "ring_core_0_17_14__CRYPTO_memcmp",
        ))
    local_symbols = definitions(executable, globals_only=False)
    if not set(crypto) <= local_symbols.keys():
        raise RuntimeError("a required native crypto definition disappeared at final link")
    if len({local_symbols[name]["address"] for name in crypto}) != len(crypto):
        raise RuntimeError("independent native crypto helpers alias one address")
    (output / "final-ownership.json").write_text(json.dumps(attributed, sort_keys=True) + "\n")
    return {"wasmtime": {name: attributed[name] for name in helpers},
            "crypto": {name: local_symbols[name] for name in crypto}}
