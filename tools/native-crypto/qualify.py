#!/usr/bin/env python3
"""Qualify native crypto patches against pristine sources and two retained graphs."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tomllib

from vendor import CONFIG, ROOT, archive


HERE = Path(__file__).resolve().parent
TOOLCHAIN = "1.99.1"
CRATES = {"blst", "ring", "secp256k1-sys"}
BLST_SYMBOLS = set((ROOT / "core/vendor/blst/kontor-symbols.txt").read_text().splitlines())
FINAL_RUNTIME_SYMBOLS = {
    "DW.ref.rust_eh_personality", "rust_eh_personality", "main", "_start",
    "__TMC_END__", "__bss_end__", "__bss_start", "__bss_start__", "__dso_handle",
    "__end__", "_bss_end__", "_edata", "_end", "_fini", "_init",
    "__aarch64_cpu_features", "__aarch64_have_lse_atomics", "__init_cpu_features",
    "__pthread_atfork", "__udivti3", "__umodti3",
}


def run(command, cwd, env, log):
    print("Running:", " ".join(map(str, command)), flush=True)
    with log.open("w") as output:
        result = subprocess.run(command, cwd=cwd, env=env, stdout=output, stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError(f"command failed: {log}\n{log.read_text()[-10000:]}")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_manifest():
    paths = {ROOT / "core/Cargo.toml", ROOT / "core/Cargo.lock"}
    for directory in (HERE, *(ROOT / "core/vendor" / name for name in (*sorted(CRATES), "kontor-native-build"))):
        paths.update(path for path in directory.rglob("*") if path.is_file()
                     and not {"target", "__pycache__"} & set(path.relative_to(directory).parts))
    return {str(path.relative_to(ROOT)): sha(path) for path in sorted(paths)}


def messages(log):
    result = []
    for line in log.read_text().splitlines():
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(message, dict):
            result.append(message)
    return result


def symbol_addresses(path, globals_only=True):
    command = ["nm", "-g", str(path)] if globals_only else ["nm", str(path)]
    output = subprocess.check_output(command, text=True, stderr=subprocess.PIPE)
    result = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) != 3 or not re.fullmatch(r"[0-9a-fA-F]+", fields[0]) or fields[1].upper() == "U":
            continue
        name = fields[2].removeprefix("_") if sys.platform == "darwin" else fields[2]
        if re.fullmatch(r"_ZN.+17h[0-9a-f]{16}E(?:\.llvm\.\d+)?", name) or re.match(r"_R[A-Z]", name):
            continue
        if re.fullmatch(r"anon\.[0-9a-f]+\.\d+(?:\.llvm\.\d+)?", name):
            continue
        result[name] = int(fields[0], 16)
    return result


def definitions(path):
    return set(symbol_addresses(path))


def crypto_owned(name):
    return (name.startswith(("rustsecp256k1_v0_10_0_", "ring_core_0_17_14_"))
            or name.split(".")[0] in BLST_SYMBOLS)


def undefined_references(path):
    output = subprocess.check_output(["nm", "-u", str(path)], text=True, stderr=subprocess.PIPE)
    references = set()
    for line in output.splitlines():
        fields = line.split()
        if not fields or line.endswith(":"):
            continue
        if len(fields) == 1:
            name = fields[0]
        elif len(fields) == 2 and fields[0] in ("U", "w", "v"):
            name = fields[1]
        else:
            raise RuntimeError(f"unrecognized nm undefined-symbol output for {path}: {line}")
        references.add(name.removeprefix("_") if sys.platform == "darwin" else name)
    return references


def validate_references(references, namespace):
    bare = sorted(name for name in references if namespace and crypto_owned(name))
    if bare:
        raise RuntimeError(f"unnamespaced crypto references in {namespace}: {bare}")


def inventory(build_messages, metadata, namespace):
    packages = {package["id"]: package["name"] for package in metadata["packages"]}
    native = {}
    inputs = set()
    facades = []
    for message in build_messages:
        if message.get("reason") == "build-script-executed":
            archives = sorted(Path(message["out_dir"]).rglob("*.a"))
            inputs.update(archives)
            package = packages[message["package_id"]]
            if archives and package not in CRATES:
                raise RuntimeError(f"unexpected native archive owner: {package}")
            for path in archives:
                filename = path.name.replace(namespace + "_", "") if namespace else path.name
                key = f"{package}/{filename}"
                if key in native:
                    raise RuntimeError(f"duplicate current archive: {key}")
                native[key] = path
        elif message.get("reason") == "compiler-artifact":
            rlibs = [Path(path) for path in message["filenames"] if path.endswith(".rlib")]
            inputs.update(rlibs)
            if message["target"]["name"].startswith("crypto_"):
                facades.extend(rlibs)
    if {key.split("/")[0] for key in native} != CRATES or len(facades) != 1:
        raise RuntimeError("missing current native archive or facade")
    return native, inputs, facades[0]


def build(output, env, pristine, configuration, variant):
    graph = "first" if configuration == "portable" else "second"
    if configuration == "portable" and variant == "default":
        graph = "node"
    name = f"{configuration}-{variant}"
    project = output / name
    project.mkdir()
    sources = pristine if variant == "upstream" else {
        crate: ROOT / "core/vendor" / crate for crate in CRATES}
    manifest = (
        f'[package]\nname = "crypto_{graph}"\nversion = "0.0.0"\nedition = "2024"\n'
        '[workspace]\n[lib]\npath = "bundle.rs"\n'
        '[[bin]]\nname = "vector-output"\npath = "main.rs"\n'
        '[profile.release]\ndebug = 0\n'
        '[dependencies]\n'
        f'blst = {{ path = {json.dumps(str(sources["blst"]))}, features = {json.dumps(["portable"] if configuration == "portable" else [])} }}\n'
        f'ring = {{ path = {json.dumps(str(sources["ring"]))} }}\n'
        f'secp256k1 = {{ version = "=0.29.1", features = {json.dumps(["recovery", "lowmemory"] if configuration == "portable" else ["recovery"])} }}\n'
        '[patch.crates-io]\n'
        f'secp256k1-sys = {{ path = {json.dumps(str(sources["secp256k1-sys"]))} }}\n'
    )
    (project / "Cargo.toml").write_text(manifest)
    shutil.copyfile(HERE / "fixtures/bundle.rs", project / "bundle.rs")
    (project / "main.rs").write_text(
        'use std::io::{self, Write};\n'
        f'fn main() {{ io::stdout().write_all(&crypto_{graph}::exercise()).unwrap(); }}\n')
    shutil.copyfile(ROOT / "core/Cargo.lock", project / "Cargo.lock")
    namespace = f"kontor_crypto_{graph}" if variant == "namespaced" else ""
    # Cargo normally caps registry dependency lints. The pristine path copy
    # needs upstream's two custom cfg names declared, without modifying sources.
    build_env = dict(env, CARGO_TARGET_DIR=str(project / "target"),
                     RUSTFLAGS=f"-Cmetadata=kontor_crypto_{graph} --check-cfg=cfg(secp256k1_fuzz) --check-cfg=cfg(rust_secp_no_symbol_renaming)")
    if namespace:
        build_env.update(KONTOR_NATIVE_NAMESPACE=namespace, KONTOR_PROTOCOL_BUNDLE="1")
    run(["cargo", "metadata", "--offline", "--format-version=1"], project, build_env, project / "metadata.json")
    metadata = json.loads((project / "metadata.json").read_text())
    identity = lambda package: (package["name"], package["version"], package.get("source"), package.get("checksum"))
    source_packages = {identity(p) for p in tomllib.loads((ROOT / "core/Cargo.lock").read_text())["package"]}
    resolved = tomllib.loads((project / "Cargo.lock").read_text())["package"]
    unexpected = [identity(p) for p in resolved if p["name"] != f"crypto_{graph}" and identity(p) not in source_packages]
    if unexpected:
        raise RuntimeError(f"independent graph drifted from source lock: {unexpected}")
    lock_before = sha(project / "Cargo.lock")
    run(["cargo", "build", "--locked", "--offline", "--release", "-j2", "--message-format=json"],
        project, build_env, project / "build.log")
    if sha(project / "Cargo.lock") != lock_before:
        raise RuntimeError("locked build changed the source graph")
    build_messages = messages(project / "build.log")
    native, inputs, facade = inventory(build_messages, metadata, namespace)
    package_names = {package["id"]: package["name"] for package in metadata["packages"]}
    for message in build_messages:
        if message.get("reason") == "build-script-executed":
            crate = package_names[message["package_id"]]
            if crate in CRATES:
                shutil.copyfile(Path(message["out_dir"]).parent / "output", project / f"native-{crate}.log")
    with (project / "vectors.bin").open("wb") as vectors:
        subprocess.run([str(project / "target/release/vector-output")], stdout=vectors, check=True)
    return {"name": name, "graph": graph, "namespace": namespace, "project": project,
            "native": native, "inputs": inputs, "facade": facade, "lock_sha256": lock_before}


def compare_objects(tool, reference, candidate, output):
    if reference["native"].keys() != candidate["native"].keys():
        raise RuntimeError("native archive inventory changed")
    results = []
    for key, path in reference["native"].items():
        other = candidate["native"][key]
        before = json.loads(subprocess.check_output([str(tool), str(path), ""], text=True))
        after = json.loads(subprocess.check_output([str(tool), str(other), candidate["namespace"]], text=True))
        audits = []
        for member in before.get("members", [before]):
            member.pop("namespace_audit")
        for member in after.get("members", [after]):
            audits.append(member.pop("namespace_audit"))
        audit_path = output / f'{candidate["name"]}-{key.replace("/", "-")}.namespace-audit.json'
        audit_path.write_text(json.dumps(audits, indent=2) + "\n")
        if before != after:
            prefix = output / f'{candidate["name"]}-{key.replace("/", "-")}'
            prefix.with_suffix(".before.json").write_text(json.dumps(before, indent=2) + "\n")
            prefix.with_suffix(".after.json").write_text(json.dumps(after, indent=2) + "\n")
            raise RuntimeError(f"native code/data/symbol/relocation drift: {key}, inspect {prefix}.*.json")
        results.append({"archive": key, "upstream_sha256": sha(path), "candidate_sha256": sha(other),
                        "normalized_report_sha256": hashlib.sha256(json.dumps(before, sort_keys=True).encode()).hexdigest(),
                        "namespace_audit_sha256": sha(audit_path)})
    return results


def audit(graphs, output):
    inventories, names, graph_references = [], [], []
    for graph in graphs:
        inventory = [{"path": str(path), "sha256": sha(path), "definitions": sorted(definitions(path)),
                      "undefined_references": sorted(undefined_references(path))}
                     for path in sorted(graph["inputs"])]
        symbols = {name for item in inventory for name in item["definitions"]}
        # This compiler-generated DWARF reference carries no crypto-owned state.
        symbols.discard("DW.ref.rust_eh_personality")
        prefix = graph["namespace"] + "_" if graph["namespace"] else ""
        unknown = sorted(name for name in symbols if not (name.startswith(prefix) if prefix else crypto_owned(name)))
        if unknown:
            raise RuntimeError(f'unowned native symbols in {graph["name"]}: {unknown}')
        callbacks = {prefix + "rustsecp256k1_v0_10_0_" + name for name in (
            "default_illegal_callback_fn", "default_error_callback_fn", "context_create", "context_destroy")}
        if not callbacks <= symbols:
            raise RuntimeError(f"missing secp Rust definitions: {callbacks - symbols}")
        inventories.append(inventory)
        names.append(symbols)
        references = {name for item in inventory for name in item["undefined_references"]}
        if not references:
            raise RuntimeError("crypto graph has no parsed undefined references")
        validate_references(references, graph["namespace"])
        graph_references.append(references)
    (output / "native-inputs.json").write_text(json.dumps(inventories, indent=2) + "\n")
    for index, symbols in enumerate(names):
        others = set.union(*(item for other, item in enumerate(names) if other != index))
        if symbols & others:
            raise RuntimeError(f"native graph collision: {sorted(symbols & others)}")
        if graph_references[index] & others:
            raise RuntimeError(f"cross-graph crypto references: {sorted(graph_references[index] & others)}")
    return names


def audit_final(executable, graphs, input_names, output):
    final_names = definitions(executable)
    runtime = FINAL_RUNTIME_SYMBOLS | ({"_mh_execute_header"} if sys.platform == "darwin" else set())
    unknown = final_names - set.union(*input_names) - runtime
    if unknown:
        raise RuntimeError(f"unowned final native definitions: {sorted(unknown)}")
    required = []
    for graph in graphs:
        prefix = graph["namespace"] + "_" if graph["namespace"] else ""
        required.extend([
            f"{prefix}blst_keygen",
            f"{prefix}rustsecp256k1_v0_10_0_ecdsa_sign_recoverable",
            f"{prefix}rustsecp256k1_v0_10_0_default_illegal_callback_fn",
            f"{prefix}ring_core_0_17_14__CRYPTO_memcmp",
        ])
    # ring deliberately hides many global input symbols at the final link.
    # Their definitions must still exist independently as local symbols.
    addresses = symbol_addresses(executable, globals_only=False)
    if not set(required) <= addresses.keys():
        raise RuntimeError(f"missing live crypto families after linking: {set(required) - addresses.keys()}")
    if len({addresses[name] for name in required}) != len(required):
        raise RuntimeError("independent crypto function definitions alias after linking")
    (output / "native-final.json").write_text(json.dumps({
        "definitions": sorted(final_names), "required_live_symbols": {name: addresses[name] for name in required},
        "runtime_definitions": sorted(final_names & runtime),
    }, indent=2) + "\n")


def reject_missing_namespace(graph, output, env):
    project = graph["project"]
    rejection_env = dict(env, KONTOR_PROTOCOL_BUNDLE="1", CARGO_TARGET_DIR=str(output / "rejection-target"))
    for crate in sorted(CRATES):
        log = output / f"reject-missing-namespace-{crate}.log"
        with log.open("w") as target:
            result = subprocess.run(["cargo", "build", "--locked", "--offline", "--release", "-j2", "-p", crate],
                                    cwd=project, env=rejection_env, stdout=target, stderr=subprocess.STDOUT)
        if result.returncode == 0 or "protocol bundle requires an explicit KONTOR_NATIVE_NAMESPACE" not in log.read_text():
            raise RuntimeError(f"{crate} failed to reject missing namespace for the expected reason: {log}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="New evidence directory, never reused")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    sources = source_manifest()
    env = dict(os.environ, RUSTUP_TOOLCHAIN=TOOLCHAIN, CCACHE_DISABLE="1", CC_ENABLE_DEBUG_OUTPUT="1")
    for name in ("RUSTC_WRAPPER", "CARGO_ENCODED_RUSTFLAGS", "RUSTFLAGS", "CARGO_TARGET_DIR",
                 "KONTOR_NATIVE_NAMESPACE", "KONTOR_PROTOCOL_BUNDLE"):
        env.pop(name, None)
    run([sys.executable, str(HERE / "vendor.py")], ROOT, env, output / "vendor.log")
    pristine_dir = output / "pristine"
    pristine_dir.mkdir()
    pristine = {entry["name"]: archive(entry, pristine_dir) for entry in json.loads(CONFIG.read_text())}
    tool_project = HERE / "object-report"
    tool_env = dict(env, CARGO_TARGET_DIR=str(output / "object-tool"))
    run(["cargo", "build", "--locked", "--offline", "-j2"], tool_project, tool_env, output / "object-tool.log")
    tool = output / "object-tool/debug/kontor-native-object-report"
    graphs, reports = [], []
    baseline = None
    for configuration in ("portable", "native"):
        upstream = build(output, env, pristine, configuration, "upstream")
        for variant in ("default", "namespaced"):
            candidate = build(output, env, pristine, configuration, variant)
            objects = compare_objects(tool, upstream, candidate, output)
            actual = (candidate["project"] / "vectors.bin").read_bytes()
            expected = (upstream["project"] / "vectors.bin").read_bytes()
            if actual != expected or (baseline is not None and expected != baseline):
                raise RuntimeError("crypto outputs differ from pristine baseline")
            baseline = expected
            reports.append({"graph": candidate["name"], "lock_sha256": candidate["lock_sha256"], "objects": objects})
            if variant == "namespaced":
                graphs.append(candidate)
            elif configuration == "portable":
                graphs.append(candidate)
    names = audit(graphs, output)
    executable = output / "dual-crypto"
    command = ["rustc", "--edition=2024", str(HERE / "fixtures/host.rs"), "-o", str(executable)]
    for graph in graphs:
        command.extend(["--extern", f'crypto_{graph["graph"]}={graph["facade"]}',
                        "-L", f'dependency={graph["project"] / "target/release/deps"}'])
    run(command, ROOT, env, output / "link.log")
    audit_final(executable, graphs, names, output)
    run([str(executable), str(graphs[0]["project"] / "vectors.bin")], ROOT, env, output / "run.log")
    reject_missing_namespace(next(graph for graph in graphs if graph["namespace"]), output, env)
    if source_manifest() != sources:
        raise RuntimeError("qualification sources changed during the run")
    report = {"compiler": subprocess.check_output(["rustc", "-Vv"], env=env, text=True),
              "sources": sources,
              "graphs": reports, "native_definition_counts": [len(symbols) for symbols in names],
              "vectors_sha256": hashlib.sha256(baseline).hexdigest(), "result": (output / "run.log").read_text()}
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(report["result"], flush=True)


if __name__ == "__main__":
    main()
