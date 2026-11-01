"""Attribute every link-visible input definition before the linker can coalesce it."""

import hashlib
import json
from pathlib import Path
import re
import sys

from symbol_tool import archive_member, archive_members, inspect, object_records, section_bytes

GDB_SCRIPT = "__rustc_debug_gdb_scripts_section__"
GDB_PAYLOAD = b"\x01gdb_load_rust_pretty_printers.py\x00"
INPUT_RUNTIME = {"DW.ref.rust_eh_personality", GDB_SCRIPT}
FINAL_RUNTIME = INPUT_RUNTIME | {
    "rust_eh_personality", "main", "_start", "__TMC_END__", "__bss_end__",
    "__bss_start", "__bss_start__", "__dso_handle", "__end__",
    "_bss_end__", "_edata", "_end", "_fini", "_init", "__aarch64_cpu_features",
    "__aarch64_have_lse_atomics", "__init_cpu_features", "__pthread_atfork",
    "__udivti3", "__umodti3",
}
RUST = re.compile(r"(?:_ZN.+17h[0-9a-f]{16}E|_R[A-Z].+)(?:\.llvm\.\d+)?$")
ANONYMOUS = re.compile(r"anon\.[0-9a-f]+\.\d+(?:\.llvm\.\d+)?$")
ALLOCATOR = re.compile(r"__(?:rg|rust)_(?:alloc|dealloc|realloc|alloc_zeroed|alloc_error_handler)(?:$|[^a-z_])")


def compiler_debug_metadata(path, linked=False):
    if sys.platform != "linux":
        raise RuntimeError("compiler GDB metadata requires an audited ELF object")
    found = 0
    for record in object_records(path):
        sections = {item["Section"]["Index"]: item["Section"] for item in record.get("Sections", [])}
        for item in record.get("Symbols", []):
            symbol = item["Symbol"]
            if symbol["Name"]["Name"] != GDB_SCRIPT:
                continue
            found += 1
            section = sections.get(symbol["Section"]["Value"])
            if (symbol["Binding"]["Name"] != "Weak" or symbol["Type"]["Name"] != "Object"
                    or symbol["Size"] != len(GDB_PAYLOAD) or symbol["Other"]["Value"] != 0
                    or section is None or section["Name"]["Name"] != ".debug_gdb_scripts"
                    or section["Type"]["Name"] != "SHT_PROGBITS"
                    or section["Flags"]["Value"] != 0x32
                    or section["AddressAlignment"] != 1 or section["EntrySize"] != 1):
                raise RuntimeError(f"invalid compiler GDB metadata definition: {record['FileSummary']['File']}")
            offset = symbol["Value"] - section["Address"]
            if (offset < 0 or offset + len(GDB_PAYLOAD) > section["Size"]
                    or (not linked and (offset != 0 or section["Size"] != len(GDB_PAYLOAD)))
                    or section_bytes(path, record, section)[offset:offset + len(GDB_PAYLOAD)] != GDB_PAYLOAD):
                raise RuntimeError(f"invalid compiler GDB metadata payload: {record['FileSummary']['File']}")
    if not found:
        raise RuntimeError(f"compiler GDB metadata definition missing: {path}")
    return found


def definitions(path, globals_only=True):
    arguments = ["-g", path] if globals_only else [path]
    output = inspect(arguments)
    symbols = {}
    for line in output.splitlines():
        fields = line.split()
        if not fields or line.endswith(":"):
            continue
        if len(fields) == 2 and fields[0] in ("U", "w", "v"):
            continue
        if len(fields) != 3 or not re.fullmatch(r"[0-9a-fA-F]+|-+", fields[0]):
            raise RuntimeError(f"unknown defined-symbol output: {line}")
        address, kind, name = fields
        if kind.upper() == "U":
            continue
        if sys.platform == "darwin":
            name = name.removeprefix("_")
        # Bitcode definitions have no address until link, but still own their names.
        symbols[name] = {"address": None if address.startswith("-") else address, "kind": kind}
    return symbols


def suffix(version):
    return "".join(c if c.isascii() and c.isalnum() else "_" for c in version)


def owner(name, graph, version, path=None, value=None):
    if name == GDB_SCRIPT:
        if path is None or value is None or value["kind"] != "V":
            raise RuntimeError(f"unverified compiler GDB metadata definition: {name}")
        compiler_debug_metadata(path)
        return "common compiler debug metadata"
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


def verify_psm_archive_copies(graph):
    rlibs = [Path(item["path"]) for item in graph["artifacts"]
             if re.fullmatch(r"libpsm-[0-9a-f]{16}\.rlib", Path(item["path"]).name)]
    archives = [Path(item["path"]) for item in graph["native_artifacts"]
                if Path(item["path"]).name == "libpsm_s.a"]
    if not rlibs and not archives:
        return
    if len(rlibs) != 1 or len(archives) != 1:
        raise RuntimeError(f"expected one psm rlib and native archive in {graph['graph']}")
    members = archive_members(archives[0])
    if len(members) != 1 or not members[0].endswith(".o"):
        raise RuntimeError(f"unexpected psm native archive members: {archives[0]}")
    if archive_members(rlibs[0]).count(members[0]) != 1:
        raise RuntimeError(f"psm native object missing from rlib: {rlibs[0]}")
    if archive_member(rlibs[0], members[0]) != archive_member(archives[0], members[0]):
        raise RuntimeError(f"psm native archive copies differ in {graph['graph']}")


def private_local_inputs(graphs):
    inventories = []
    sets = []
    for graph in graphs:
        prefix = graph["namespace"] + "_"
        expected = {}
        for item in graph["artifacts"] + graph["native_artifacts"]:
            path = Path(item["path"])
            if path in expected and expected[path] != item.get("sha256"):
                raise RuntimeError(f"conflicting staged graph input hashes: {path}")
            expected[path] = item.get("sha256")
        graph_names = set()
        graph_inputs = []
        for path in sorted(expected):
            actual_hash = hashlib.sha256(path.read_bytes()).hexdigest()
            if expected[path] != actual_hash:
                raise RuntimeError(f"staged graph input changed before local ownership audit: {path}")
            global_names = definitions(path)
            local = {name: value for name, value in definitions(path, globals_only=False).items()
                     if name.startswith(prefix) and name not in global_names}
            graph_names.update(local)
            graph_inputs.append({"path": str(path), "sha256": actual_hash,
                                 "definitions": local})
        sets.append(graph_names)
        inventories.append({"graph": graph["graph"], "inputs": graph_inputs})
    return sets, inventories


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
            for name, value in symbols.items():
                owner(name, graph, version, path, value)
            all_names.update(symbols)
            inventory.append({"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                              "definitions": symbols})
        verify_psm_archive_copies(graph)
        sets.append(all_names)
        inventories.append({"graph": graph["graph"], "inputs": inventory})
    for index, names in enumerate(sets):
        for previous in range(index):
            collisions = (names & sets[previous]) - INPUT_RUNTIME
            if collisions:
                raise RuntimeError(f"cross-graph definitions would coalesce: {sorted(collisions)[:100]}")
    (output / "input-ownership.json").write_text(json.dumps(inventories, sort_keys=True) + "\n")
    return sets, versions


def audit_final(executable, graphs, sets, versions, output, common, kind="proof", node=None):
    if kind not in ("proof", "executor"):
        raise RuntimeError(f"unknown final audit kind: {kind}")
    node = node or {}
    if kind == "proof" and node:
        raise RuntimeError("proof final audit has unexpected node inputs")
    symbols = definitions(executable)
    attributed = {}
    for name, value in symbols.items():
        if value["address"] is None:
            raise RuntimeError(f"final definition has no linked address: {name}")
        matches = [graph["graph"] for graph, names in zip(graphs, sets, strict=True) if name in names]
        if name == GDB_SCRIPT:
            if not matches and name not in common:
                raise RuntimeError("unowned final compiler GDB metadata")
            compiler_debug_metadata(executable, linked=True)
            attribution = "common compiler debug metadata"
        elif name in FINAL_RUNTIME or (sys.platform == "darwin" and name == "_mh_execute_header"):
            attribution = "common compiler/linker runtime"
        elif len(matches) == 1:
            attribution = matches[0]
        elif not matches and name in common:
            attribution = {"common_inputs": common[name]}
        elif kind == "executor" and not matches and name in node:
            attribution = {"node_inputs": node[name]}
        else:
            raise RuntimeError(f"ambiguous or unowned final definition: {name}: {matches}")
        attributed[name] = dict(value, owner=attribution)
    helpers = ["wasmtime_libunwind_" + suffix(version) for version in versions]
    crypto = []
    for graph in graphs:
        crypto.extend(graph["namespace"] + "_" + name for name in (
            "blst_keygen", "rustsecp256k1_v0_10_0_ecdsa_sign_recoverable",
            "rustsecp256k1_v0_10_0_default_illegal_callback_fn",
            "ring_core_0_17_14__CRYPTO_memcmp",
        ))
    local_symbols = definitions(executable, globals_only=False)
    if kind == "proof":
        if any(name not in symbols for name in helpers):
            raise RuntimeError("missing graph-private Wasmtime native helper")
        if len({symbols[name]["address"] for name in helpers}) != len(helpers):
            raise RuntimeError("Wasmtime graph-private helpers alias one address")
        if not set(crypto) <= local_symbols.keys():
            raise RuntimeError("a required native crypto definition disappeared at final link")
        if len({local_symbols[name]["address"] for name in crypto}) != len(crypto):
            raise RuntimeError("independent native crypto helpers alias one address")
        observed_native = {name: local_symbols[name] for name in crypto}
    else:
        local_sets, local_inventory = private_local_inputs(graphs)
        (output / "input-local-ownership.json").write_text(
            json.dumps(local_inventory, sort_keys=True) + "\n")
        observed_native = {}
        graph_addresses = []
        for graph, names, private_locals in zip(graphs, sets, local_sets, strict=True):
            prefix = graph["namespace"] + "_"
            observed = {name: value for name, value in local_symbols.items()
                        if name.startswith(prefix)}
            global_final = observed.keys() & symbols.keys()
            unowned_global = global_final - names
            unowned_local = (observed.keys() - global_final) - names - private_locals
            if unowned_global or unowned_local:
                raise RuntimeError(
                    f"unowned graph-private final definition: {sorted(unowned_global | unowned_local)[:100]}")
            if any(value["address"] is None for value in observed.values()):
                raise RuntimeError(f"graph-private final definition has no linked address: {graph['graph']}")
            observed_native.update(observed)
            for name, value in observed.items():
                attributed.setdefault(name, dict(value, owner=graph["graph"]))
            graph_addresses.append({value["address"] for value in observed.values()})
        for index, addresses in enumerate(graph_addresses):
            for previous in range(index):
                if addresses & graph_addresses[previous]:
                    raise RuntimeError("independent graph-private native definitions alias one address")
        for name, names, graph in zip(helpers, sets, graphs, strict=True):
            if name in local_symbols:
                if name not in names or local_symbols[name]["address"] is None:
                    raise RuntimeError(f"unowned graph-private Wasmtime native helper: {name}")
                attributed.setdefault(name, dict(local_symbols[name], owner=graph["graph"]))
        present_helpers = [name for name in helpers if name in local_symbols]
        if len({local_symbols[name]["address"] for name in present_helpers}) != len(present_helpers):
            raise RuntimeError("Wasmtime graph-private helpers alias one address")
    (output / "final-ownership.json").write_text(json.dumps(attributed, sort_keys=True) + "\n")
    if kind == "proof":
        return {"wasmtime": {name: attributed[name] for name in helpers},
                "crypto": observed_native}
    return {"wasmtime": {name: attributed[name] for name in helpers if name in local_symbols},
            "crypto": {name: observed_native[name] for name in crypto if name in observed_native},
            "native": observed_native}
