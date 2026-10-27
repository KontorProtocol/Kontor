"""Verify graph references and common owners against concrete compiler/platform inputs."""

import ctypes
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

from audit import INPUT_RUNTIME, definitions
from symbol_tool import inspect

LINUX_RUNTIME = {"libgcc_s.so.1", "libm.so.6", "libc.so.6", "libpthread.so.0",
                 "libdl.so.2", "librt.so.1", "ld-linux-aarch64.so.1", "ld-linux-x86-64.so.2"}
MAC_RUNTIME = {"/usr/lib/libSystem.B.dylib",
               # libc links iconv on Apple outside rustc-dep-of-std, even without iconv calls.
               "/usr/lib/libiconv.2.dylib",
               "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
               "/System/Library/Frameworks/SystemConfiguration.framework/Versions/A/SystemConfiguration",
               "/System/Library/Frameworks/Security.framework/Versions/A/Security"}
OPTIONAL_UNWIND = {"__unw_add_dynamic_fde", "__unw_add_dynamic_eh_frame_section",
                   "__unw_remove_dynamic_eh_frame_section"}


def references(path):
    arguments = ["-m", "-u", path] if sys.platform == "darwin" else ["-u", path]
    output = inspect(arguments)
    names = {}
    for line in output.splitlines():
        fields = line.split()
        if not fields or line.endswith(":"):
            continue
        if sys.platform == "darwin":
            match = re.fullmatch(r"\s*\(undefined\)\s+(weak\s+)?(?:private\s+)?external\s+(\S+)(?:\s+\(from .+\))?\s*", line)
            if not match:
                raise RuntimeError(f"unknown Darwin undefined-symbol attributes: {line}")
            kind = "w" if match[1] else "U"
            name = match[2]
        elif len(fields) == 1:
            name = fields[0]
            kind = "U"
        elif len(fields) == 2 and fields[0] in ("U", "w", "v"):
            name = fields[1]
            kind = fields[0]
        else:
            raise RuntimeError(f"unknown undefined-symbol output: {line}")
        name = name.removeprefix("_") if sys.platform == "darwin" else name
        names.setdefault(name, set()).add(kind)
    return names


def runtime_paths(executable):
    if sys.platform == "darwin":
        text = subprocess.check_output(["otool", "-L", str(executable)], text=True)
        paths = [line.strip().split(" (", 1)[0] for line in text.splitlines()[1:]]
        if not set(paths) <= MAC_RUNTIME:
            raise RuntimeError(f"undeclared shared platform libraries: {paths}")
    else:
        text = subprocess.check_output(["ldd", str(executable)], text=True)
        paths = re.findall(r"(?:=>\s+)?(/\S+)", text)
        if not paths or any(Path(path).name not in LINUX_RUNTIME for path in paths):
            raise RuntimeError(f"undeclared shared platform libraries: {paths}")
    return list(dict.fromkeys(paths))


def platform_owners(executable, candidates):
    owners = {}
    libraries = []
    for path in runtime_paths(executable):
        library = ctypes.CDLL(path)
        names = []
        for name in sorted(candidates):
            try:
                getattr(library, name)
            except AttributeError:
                continue
            names.append(name)
            owners.setdefault(name, []).append(path)
        source = Path(path)
        libraries.append({"path": path, "sha256": hashlib.sha256(source.read_bytes()).hexdigest()
                          if source.is_file() else None,
                          "symbols_resolved_in_library_scope": names,
                          "dyld_shared_cache": sys.platform == "darwin" and not source.is_file()})
    return owners, libraries


def reject_common_shadow(graph, names, common):
    overlap = (names & common.keys()) - INPUT_RUNTIME
    if overlap:
        raise RuntimeError(f"{graph['graph']} shadows common host/sysroot definitions: {sorted(overlap)[:100]}")


def graph_references(graph, index, sets):
    names = set()
    strong = set()
    paths = {Path(item["path"]) for item in graph["artifacts"]}
    paths.update(Path(item["path"]) for item in graph["native_artifacts"])
    for path in sorted(paths):
        refs = references(path)
        names.update(refs)
        strong.update(name for name, kinds in refs.items() if "U" in kinds)
    for other, other_names in enumerate(sets):
        if index != other:
            foreign = (names & other_names) - INPUT_RUNTIME
            if foreign:
                raise RuntimeError(f"{graph['graph']} references another graph: {sorted(foreign)[:100]}")
    return names, (names - strong) & OPTIONAL_UNWIND


def linker_owners(executable):
    if sys.platform != "linux":
        return {}
    # ELF linkers keep the GOT anchor local, so the global definition inventory omits it.
    symbols = definitions(executable, globals_only=False)
    got = symbols.get("_GLOBAL_OFFSET_TABLE_")
    if got is None:
        return {}
    if got["kind"] not in ("d", "a"):
        raise RuntimeError("ELF GOT anchor is not local linker data or an absolute symbol")
    return {"_GLOBAL_OFFSET_TABLE_": got}


def reject_unowned_references(graph, names, refs, common, platform, optional, linker):
    shadowed = names & platform.keys()
    if shadowed:
        raise RuntimeError(f"{graph['graph']} shadows a platform export: {sorted(shadowed)[:100]}")
    unresolved = refs - names - common.keys() - platform.keys() - optional - linker.keys()
    if unresolved:
        raise RuntimeError(f"{graph['graph']} imports have no declared owner: {sorted(unresolved)[:100]}")


def verify(graphs, sets, host_objects, executable, env, output):
    common = {}
    inventories = []
    sysroot = Path(subprocess.check_output([env["RUSTC"], "--print", "sysroot"], env=env, text=True).strip())
    target = subprocess.check_output([env["RUSTC"], "-Vv"], env=env, text=True)
    target = next(line[6:] for line in target.splitlines() if line.startswith("host: "))
    paths = sorted((sysroot / "lib/rustlib" / target / "lib").glob("*.rlib")) + list(host_objects)
    if sys.platform == "linux":
        nonshared = Path(subprocess.check_output([env.get("CC", "cc"), "-print-file-name=libc_nonshared.a"], env=env, text=True).strip())
        if not nonshared.is_file():
            raise RuntimeError("missing compiler-selected libc_nonshared archive")
        paths.append(nonshared.resolve())
    if not host_objects or not paths:
        raise RuntimeError("missing concrete host/sysroot input inventory")
    for path in paths:
        names = definitions(path)
        record = {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                  "definitions": names}
        inventories.append(record)
        for name in names:
            common.setdefault(name, []).append(str(path))
    for graph, names in zip(graphs, sets, strict=True):
        reject_common_shadow(graph, names, common)
    graph_refs = []
    graph_optional = []
    for index, graph in enumerate(graphs):
        names, optional = graph_references(graph, index, sets)
        graph_refs.append(names)
        graph_optional.append(optional)
    candidates = set.union(*graph_refs, *sets) - common.keys()
    platform, libraries = platform_owners(executable, candidates)
    linker = linker_owners(executable)
    for graph, names, refs, optional in zip(graphs, sets, graph_refs, graph_optional, strict=True):
        reject_unowned_references(graph, names, refs, common, platform, optional, linker)
    report = {"common_inputs": inventories, "platform_libraries": libraries,
              "linker_definitions": linker,
              "optional_weak_system_unwind": [sorted(names) for names in graph_optional],
              "references": [{"graph": graph["graph"], "own": sorted(refs & names),
                              "common": sorted(refs & common.keys()), "platform": sorted(refs & platform.keys()),
                              "linker": sorted(refs & linker.keys())}
                             for graph, names, refs in zip(graphs, sets, graph_refs, strict=True)]}
    (output / "common-reference-ownership.json").write_text(json.dumps(report, sort_keys=True) + "\n")
    return common
