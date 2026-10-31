"""Attribute every link-visible input definition before the linker can coalesce it."""

import hashlib
import json
from pathlib import Path
import re
import sys

from symbol_tool import archive_member_bytes, inspect, object_records, section_bytes

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
PSM_ABI = {"rust_psm_on_stack", "rust_psm_replace_stack",
           "rust_psm_stack_direction", "rust_psm_stack_pointer"}
WIT_ABI = {"cabi_realloc_wit_bindgen_0_63_0"}


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


def package_artifact(graph, path, package, version, native=False):
    if not any(item["name"] == package and item["version"] == version for item in graph["packages"]):
        return False
    field = "native_artifacts" if native else "artifacts"
    item = next((item for item in graph[field] if item["path"] == str(path)), None)
    if item is None or "source_path" not in item:
        return False
    source = Path(item["source_path"])
    if native:
        return (path.name == "libpsm_s.a" and path.parent.parent.name == "native"
                and source.name == "libpsm_s.a" and source.parent.name == "out"
                and re.fullmatch(r"psm-[0-9a-f]{16}", source.parent.parent.name) is not None)
    crate = package.replace("-", "_")
    return (re.fullmatch(rf"lib{crate}-[0-9a-f]{{16}}\.rlib", path.name) is not None
            and source.name == path.name and source.parent.name == "deps")


def graph_abi_function(path, name, section_name):
    found = 0
    digest = None
    for record in object_records(path):
        sections = {item["Section"]["Index"]: item["Section"] for item in record.get("Sections", [])}
        for item in record.get("Symbols", []):
            symbol = item["Symbol"]
            if symbol["Name"]["Name"] != name or symbol["Section"]["Name"] == "Undefined":
                continue
            found += 1
            section = sections.get(symbol["Section"]["Value"])
            if (symbol["Binding"]["Name"] != "Global" or symbol["Type"]["Name"] != "Function"
                    or symbol["Size"] <= 0 or section is None
                    or section["Name"]["Name"] != section_name
                    or section["Flags"]["Value"] != 0x6):
                raise RuntimeError(f"invalid graph ABI definition: {name} in {record['FileSummary']['File']}")
            digest = hashlib.sha256(archive_member_bytes(path, record)).hexdigest()
    if found != 1:
        raise RuntimeError(f"expected one graph ABI definition for {name} in {path}, found {found}")
    return digest



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
    if path is not None and value is not None and value["kind"] == "T":
        if (name in PSM_ABI and package_artifact(graph, path, "psm", "0.1.32",
                                                native=path.suffix == ".a")):
            graph_abi_function(path, name, ".text")
            return graph["graph"]
        if (name in WIT_ABI and package_artifact(graph, path, "wit-bindgen", "0.63.0")):
            graph_abi_function(path, name, ".text." + name)
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
        psm_copies = {}
        for path in sorted(paths):
            symbols = definitions(path)
            for name, value in symbols.items():
                owner(name, graph, version, path, value)
            if PSM_ABI & symbols.keys():
                if not PSM_ABI <= symbols.keys():
                    raise RuntimeError(f"incomplete psm native ABI in {path}")
                psm_copies[str(path)] = graph_abi_function(path, "rust_psm_on_stack", ".text")
            all_names.update(symbols)
            inventory.append({"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                              "definitions": symbols})
        if len(set(psm_copies.values())) > 1:
            raise RuntimeError(f"psm native archive copies differ in {graph['graph']}: {psm_copies}")
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
