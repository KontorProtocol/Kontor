#!/usr/bin/env python3
"""Resolve, build and attest separately owned protocol dependency graphs."""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib

from audit import audit_final, audit_inputs
from common_ownership import verify as verify_common_ownership
from execution_definition import verify_reference
from metadata_control import proc_macro_hashes
from provenance import fingerprint, locked_packages, runtime_libraries, source_inputs
from provenance import tools as toolchain_inputs
from source_policy import check as check_source_policy
from symbol_tool import TOOLCHAIN
from recipes import EXECUTOR_LINK_SETS, GRAPHS, executor_graphs, graph_root, identity, verify_engine_observations, verify_identity, verify_reservations
from capabilities import verify as verify_capabilities
from type_boundary import verify as verify_type_boundary

ROOT = Path(__file__).resolve().parents[2]
MALACHITE = "6d99c0a43a21ff48ff3f69a5f9e834310d0b0b09"
TARGETS = {"aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu", "aarch64-apple-darwin"}
FORBIDDEN = {"cache", "profiling", "debug-builtins"}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def run(args, cwd, env, log):
    print("Running: " + " ".join(map(str, args)), flush=True)
    with log.open("w") as output:
        result = subprocess.run(args, cwd=cwd, env=env, stdout=output, stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {log}\n{log.read_text()[-12000:]}")


def metadata(manifest, target, env, offline, features=(), *, source_root=None):
    command = ["cargo", "metadata", "--locked", "--format-version=1",
               "--manifest-path", str(manifest)]
    if target is not None:
        command.extend(["--filter-platform", target])
    if features:
        command.extend(["--features", ",".join(features)])
    if offline:
        command.append("--offline")
    return json.loads(subprocess.check_output(command, cwd=ROOT if source_root is None else source_root,
                                             env=env, text=True))


def identities(graph, data, graphs=None):
    recipe = (GRAPHS if graphs is None else graphs)[graph]
    source_root = graph_root(ROOT, recipe)
    revision, version, itoa = recipe.revision, recipe.version, recipe.itoa
    packages = {p["id"]: p for p in data["packages"]}
    nodes = {node["id"]: node for node in data["resolve"]["nodes"]}
    root = data["resolve"]["root"]
    reachable = set()
    pending = [root]
    while pending:
        key = pending.pop()
        if key in reachable:
            continue
        reachable.add(key)
        pending.extend(dep["pkg"] for dep in nodes[key]["deps"])
    selected = [packages[key] for key in sorted(reachable)]
    def one(name):
        found = [p for p in selected if p["name"] == name]
        if len(found) != 1:
            raise RuntimeError(f"{graph}: expected one {name}, found {len(found)}")
        return found[0]
    vm = one("wasmtime")
    if vm["version"] != version or not vm["source"].endswith("#" + revision):
        raise RuntimeError(f"{graph}: immutable Wasmtime identity changed")
    if FORBIDDEN & set(nodes[vm["id"]]["features"]):
        raise RuntimeError(f"{graph}: forbidden Wasmtime feature")
    for name in (("arc-malachitebft-app-channel", "if-watch") if recipe.malachite_engine else ()):
        package = one(name)
        if not package["source"].endswith("#" + MALACHITE):
            raise RuntimeError(f"{graph}: unqualified {name} source")
    if itoa is not None and one("itoa")["version"] != itoa:
        raise RuntimeError(f"{graph}: missing conflicting itoa version")
    for name in recipe.native_patches:
        package = one(name)
        if Path(package["manifest_path"]).parent.resolve() != source_root / "core/vendor" / name:
            raise RuntimeError(f"{graph}: missing native patch for {name}")
    if recipe.kind == "executor":
        forbidden = {"libsql", "arc-malachitebft-app-channel", "if-watch"}
        if forbidden & {p["name"] for p in selected}:
            raise RuntimeError(f"{graph}: executor graph contains node-owned storage or consensus services")
        # An optional native library still needs its patch if a new dependency
        # makes it reachable. Absence is not permission to use unowned symbols.
        for package in selected:
            if package["name"] == "ring" and Path(package["manifest_path"]).parent.resolve() != source_root / "core/vendor/ring":
                raise RuntimeError(f"{graph}: missing native patch for ring")
    return [{"name": p["name"], "version": p["version"], "source": p["source"],
             "features": sorted(nodes[p["id"]]["features"])} for p in selected]


def current_artifacts(log, target_dir, target, package):
    messages = []
    for line in log.read_text().splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            messages.append(value)
    target_root = target_dir / target
    archives = set()
    proc_macros = set()
    facades = set()
    native_outputs = []
    for item in messages:
        if item.get("reason") == "compiler-artifact":
            if "proc-macro" in item["target"]["kind"]:
                proc_macros.update(Path(path) for path in item["filenames"]
                                   if Path(path).suffix in (".so", ".dylib"))
            for filename in item["filenames"]:
                path = Path(filename)
                if path.suffix == ".rlib" and path.is_relative_to(target_root):
                    archives.add(path)
                    if item["target"]["name"] == package.replace("-", "_"):
                        facades.add(path)
        elif item.get("reason") == "build-script-executed":
            output = Path(item["out_dir"])
            if output.is_relative_to(target_root):
                native_outputs.append(item)
    if len(facades) != 1 or not archives:
        raise RuntimeError(f"missing or ambiguous current bundle rlib: {facades}")
    return sorted(archives), facades.pop(), native_outputs, sorted(proc_macros)


def build_graph(graph, args, base_env, output, graphs=None):
    graphs = GRAPHS if graphs is None else graphs
    selected_recipe = graphs[graph]
    source_root = graph_root(ROOT, selected_recipe)
    manifest = source_root / "protocol-bundles" / selected_recipe.directory / "Cargo.toml"
    lock = manifest.with_name("Cargo.lock")
    recipe = tomllib.loads(manifest.read_text())
    if any(recipe["profile"][profile].get("panic") != "unwind" for profile in ("dev", "release")):
        raise RuntimeError("bundle profiles must use the common unwind runtime")
    graph_output = output / graph
    graph_output.mkdir(parents=True, exist_ok=True)
    lock_hash = digest(lock)
    graph_identity = identity(ROOT, graph, graphs)
    namespace = "kontor_" + graph + "_" + fingerprint(graph_identity)[:24]
    wrapper = ROOT / "tools/protocol-bundles/rustc-wrapper.py"
    target_dir = graph_output / "target" / (namespace + "_" + digest(wrapper)[:16])
    env = dict(base_env, CARGO_TARGET_DIR=str(target_dir), KONTOR_PROTOCOL_BUNDLE="1",
               KONTOR_NATIVE_NAMESPACE=namespace, BUNDLE_LIFT_RATE=str(selected_recipe.lift_rate),
               BUNDLE_GRAPH=graph,
               RUSTC_WRAPPER=str(wrapper),
               RUSTFLAGS=f"-Cmetadata={namespace} -Cpanic=unwind")
    data = metadata(manifest, args.target, env, args.offline, source_root=source_root)
    definition = None
    if selected_recipe.kind == "executor":
        # Network identity covers all target dependencies, independently of the
        # platform-filtered artifact inventory used below.
        definition = verify_reference(source_root, manifest, metadata(
            manifest, None, env, args.offline, source_root=source_root))
    packages = identities(graph, data, graphs)
    sources = source_inputs(source_root, data, kind=selected_recipe.kind, tool_root=ROOT)
    source_policy = check_source_policy(source_root, data, kind=selected_recipe.kind)
    write_json(graph_output / "source-inputs.json", sources)
    write_json(graph_output / "metadata.json", data)
    command = ["cargo", "build", "--locked", "--manifest-path", str(manifest),
               "--target", args.target, "--profile", args.profile, "-j", str(args.jobs),
               "--message-format=json-render-diagnostics"]
    if args.offline:
        command.append("--offline")
    log = graph_output / "build.log"
    run(command, source_root, env, log)
    if digest(lock) != lock_hash:
        raise RuntimeError("locked build modified the dependency lock")
    if source_inputs(source_root, data, kind=selected_recipe.kind, tool_root=ROOT) != sources:
        raise RuntimeError("source inputs changed while the graph was compiling")
    if metadata(manifest, args.target, env, args.offline, source_root=source_root) != data:
        raise RuntimeError("resolved metadata changed while the graph was compiling")
    if definition is not None and verify_reference(
        source_root, manifest, metadata(manifest, None, env, args.offline, source_root=source_root)
    ) != definition:
        raise RuntimeError("execution definition changed while the graph was compiling")
    archives, facade, native_outputs, proc_macros = current_artifacts(log, target_dir, args.target, recipe["package"]["name"])
    # Supply rustc only this invocation's rlibs, never stale target-directory glob matches.
    inputs = graph_output / "link-inputs"
    if inputs.exists():
        shutil.rmtree(inputs)
    inputs.mkdir()
    for archive in archives:
        shutil.copyfile(archive, inputs / archive.name)
    native_artifacts = []
    for index, script in enumerate(native_outputs):
        for path in sorted(Path(script["out_dir"]).rglob("*.a")):
            staged = inputs / "native" / str(index) / path.name
            staged.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, staged)
            native_artifacts.append({"path": str(staged), "source_path": str(path), "sha256": digest(staged)})
    # rustc loads proc-macro metadata while reading dependent rlibs. These shared
    # libraries execute in the compiler, not in the retained node executable.
    compiler_inputs = []
    for artifact in proc_macros:
        prefix, original_suffix = artifact.name.rsplit("-", 1)
        staged = inputs / f"{prefix}-{namespace}-{original_suffix}"
        shutil.copyfile(artifact, staged)
        compiler_inputs.append({"path": str(artifact), "staged": str(staged), "sha256": digest(artifact)})
    result = {"graph": graph, "identity": graph_identity, "namespace": namespace, "lock_sha256": lock_hash,
              "build_log_sha256": digest(log),
              "manifest_sha256": digest(manifest), "packages": packages,
              "artifacts": [{"path": str(inputs / p.name), "source_path": str(p),
                             "sha256": digest(inputs / p.name)} for p in archives],
              "native_artifacts": native_artifacts,
              "facade": str(inputs / facade.name), "link_inputs": str(inputs),
              "compiler_proc_macros": compiler_inputs,
              "source_inputs_sha256": fingerprint(sources), "locked_packages": locked_packages(lock),
              "source_policy": source_policy,
              "wrapper_sha256": digest(wrapper), "injected_metadata": namespace,
              "rustflags": env["RUSTFLAGS"],
              "native_outputs": native_outputs}
    if definition is not None:
        result["execution_definition"] = definition
    write_json(graph_output / "build-inputs.json", result)
    return result


def qualify(graphs, args, env, output):
    for graph in graphs:
        verify_identity(ROOT, graph)
        verify_staged_inputs(graph)
    sets, versions = audit_inputs(graphs, output)
    host_output = output / "host"
    if host_output.exists():
        shutil.rmtree(host_output)
    host_output.mkdir()
    executable = host_output / "protocol-bundle-proof"
    options = ["--edition=2024", "--target", args.target, "-Cpanic=unwind",
               "-Cmetadata=kontor_proof_host", "-Cdebuginfo=1",
               "-Copt-level=" + ("3" if args.profile == "release" else "1")]
    dependencies = []
    for graph in graphs:
        dependencies.extend(["--extern", f"kontor_proof_{graph['graph']}={graph['facade']}",
                             "-L", f"dependency={graph['link_inputs']}"])
    run([env["RUSTC"], *options, "-Ccodegen-units=1", "-Csave-temps", "--emit=link,obj",
         str(ROOT / "protocol-bundles/proof/host.rs"), *dependencies, "-o", str(executable)],
        host_output, env, output / "link.log")
    host_objects = sorted(host_output.glob("*.rcgu.o"))
    common, _ = verify_common_ownership(graphs, sets, host_objects, executable, env, output)
    helpers = audit_final(executable, graphs, sets, versions, output, common)
    macro_hashes = proc_macro_hashes(graphs, options, env, output)
    libraries = runtime_libraries(executable, env, graphs)
    unified_resolution_control(env, output)
    negative = [env["RUSTC"], *options, str(ROOT / "protocol-bundles/proof/cross_graph_rejected.rs"),
                "-o", str(output / "cross-graph-must-not-build")]
    for graph in graphs:
        artifacts = [Path(item["path"]) for item in graph["artifacts"]
                     if Path(item["path"]).name.startswith("libtokio-")]
        if len(artifacts) != 1:
            raise RuntimeError("ambiguous Tokio artifact for cross-graph negative control")
        negative.extend(["--extern", f"{graph['graph']}_tokio={artifacts[0]}",
                         "-L", f"dependency={graph['link_inputs']}"])
    rejected = subprocess.run(negative, cwd=ROOT, env=env, text=True, capture_output=True)
    (output / "cross-graph-rejected.log").write_text(rejected.stdout + rejected.stderr)
    if rejected.returncode == 0 or "E0308" not in rejected.stderr or "Sender" not in rejected.stderr:
        raise RuntimeError("cross-graph dependency types were not rejected for the expected mismatch")
    wal = output / "proof-wal"
    if wal.exists():
        raise RuntimeError(f"previous proof left WAL evidence at {wal}; inspect before removing")
    run([str(executable), str(wal)], ROOT, env, output / "run.log")
    observations = verify_engine_observations((output / "run.log").read_text())
    for graph in graphs:
        verify_identity(ROOT, graph)
        verify_staged_inputs(graph)
    return {"executable_sha256": digest(executable), "native_helpers": helpers,
            "engine_observations": observations,
            "runtime_libraries": libraries,
            "proc_macro_metadata": macro_hashes,
            "common_reference_ownership_sha256": digest(output / "common-reference-ownership.json"),
            "input_ownership_sha256": digest(output / "input-ownership.json"),
            "final_ownership_sha256": digest(output / "final-ownership.json"),
            "cross_graph_rejected_sha256": digest(output / "cross-graph-rejected.log"),
            "unified_resolution_rejected_sha256": digest(output / "unified-resolution-rejected.log"),
            "result": (output / "run.log").read_text()}


def unified_resolution_control(env, output):
    with tempfile.TemporaryDirectory(prefix="unified-negative-", dir=output) as directory:
        root = Path(directory)
        manifest = root / "Cargo.toml"
        manifest.write_text('''[package]
name = "kontor-unified-negative"
version = "0.0.0"
edition = "2024"
[workspace]
[lib]
path = "lib.rs"
[dependencies]
first = { package = "itoa", version = "=1.0.14" }
second = { package = "itoa", version = "=1.0.15" }
''')
        (root / "lib.rs").write_text("")
        result = subprocess.run(["cargo", "metadata", "--offline", "--format-version=1",
                                 "--manifest-path", str(manifest)], env=env, text=True,
                                capture_output=True)
        (output / "unified-resolution-rejected.log").write_text(result.stdout + result.stderr)
        if result.returncode == 0 or not all(token in result.stderr for token in (
                "failed to select a version", "itoa", "1.0.14", "1.0.15", "conflict")):
            raise RuntimeError("unified Cargo graph did not reject the conflicting patch requirements")


def verify_staged_inputs(graph):
    for item in graph["artifacts"] + graph["native_artifacts"]:
        if digest(Path(item["path"])) != item["sha256"]:
            raise RuntimeError(f"staged compiler input changed: {item['path']}")
    for item in graph["compiler_proc_macros"]:
        if digest(Path(item["staged"])) != item["sha256"]:
            raise RuntimeError(f"staged compiler plugin changed: {item['staged']}")


def node_dependencies(data):
    names = {package["name"] for package in data["packages"]}
    if any(name.startswith(("wasmtime", "kontor-executor-")) for name in names):
        raise RuntimeError("node Cargo graph contains a retained execution implementation")
    for package in data["packages"]:
        if package["name"] in {"blst", "secp256k1-sys", "ring", "psm", "wit-bindgen"}:
            expected = ROOT / "core/vendor" / package["name"]
            if Path(package["manifest_path"]).parent.resolve() != expected:
                raise RuntimeError(f"node is missing native patch for {package['name']}")


def node_executable(log):
    executables = set()
    for line in log.read_text().splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (isinstance(item, dict) and item.get("reason") == "compiler-artifact"
                and item["target"]["name"] == "kontor" and "bin" in item["target"]["kind"]
                and item.get("executable")):
            executables.add(Path(item["executable"]))
    if len(executables) != 1:
        raise RuntimeError("missing or ambiguous current node executable")
    return executables.pop()


def node_codegen_objects(path, spec):
    record = json.loads(path.read_text())
    if record["spec_sha256"] != digest(spec) or not record["objects"]:
        raise RuntimeError("node codegen objects do not match this link specification")
    for item in record["objects"]:
        if digest(Path(item["path"])) != item["sha256"]:
            raise RuntimeError("node codegen object changed after compilation")
    return [Path(item["path"]) for item in record["objects"]]


def build_node(graphs, args, base_env, output):
    recipes = executor_graphs(args.link_set)
    manifest = ROOT / "protocol-bundles/node/Cargo.toml"
    lock = manifest.with_name("Cargo.lock")
    recipe = tomllib.loads(manifest.read_text())
    if any(recipe["profile"][profile].get("panic") != "unwind" for profile in ("dev", "release")):
        raise RuntimeError("node profiles must use the common unwind runtime")
    directory = output / "node"
    directory.mkdir(parents=True, exist_ok=True)
    env = dict(base_env, CARGO_TARGET_DIR=str(directory / "target"), RUSTC_WRAPPER="",
               RUSTFLAGS="-Cpanic=unwind")
    for key in ("KONTOR_PROTOCOL_BUNDLE", "KONTOR_NATIVE_NAMESPACE", "BUNDLE_GRAPH", "BUNDLE_LIFT_RATE"):
        env.pop(key, None)
    features = ["protocol-qualification"] if args.node_qualification else []
    data = metadata(manifest, args.target, env, args.offline, features)
    node_dependencies(data)
    sources = source_inputs(ROOT, data, kind="node")
    lock_hash = digest(lock)
    write_json(directory / "metadata.json", data)
    write_json(directory / "source-inputs.json", sources)
    for graph in graphs:
        verify_identity(ROOT, graph, recipes)
        verify_staged_inputs(graph)
    sets, versions = audit_inputs(graphs, directory)
    spec = {"compiler": env["RUSTC"], "features": features, "link_set": args.link_set,
            "source_inputs_sha256": fingerprint(sources),
            "lock_sha256": lock_hash, "root_objects": str(directory / "root-objects.json"),
            "graphs": [{"graph": graph["graph"], "facade": graph["facade"],
                        "facade_sha256": digest(Path(graph["facade"])),
                        "link_inputs": graph["link_inputs"], "build_inputs_sha256": fingerprint(graph)}
                       for graph in graphs]}
    spec_path = directory / "link-spec.json"
    write_json(spec_path, spec)
    # Cargo does not know that external --extern inputs changed. A content-keyed
    # workspace wrapper invalidates only the node, preserving dependency caches.
    wrapper = directory / ("rustc-wrapper-" + fingerprint(spec) + ".py")
    shutil.copyfile(ROOT / "tools/protocol-bundles/node-rustc-wrapper.py", wrapper)
    wrapper.chmod(0o755)
    env.update(RUSTC_WORKSPACE_WRAPPER=str(wrapper), KONTOR_NODE_LINK_SPEC=str(spec_path))
    command = ["cargo", "build", "--locked", "--manifest-path", str(manifest), "--bin", "kontor",
               "--target", args.target, "--profile", args.profile, "-j", str(args.jobs),
               "--message-format=json-render-diagnostics"]
    if args.offline:
        command.append("--offline")
    if args.node_qualification:
        command.extend(["--features", "protocol-qualification"])
    log = directory / "build.log"
    run(command, ROOT, env, log)
    executable = node_executable(log)
    archives, _, native_outputs, proc_macros = current_artifacts(log, directory / "target", args.target, "indexer")
    root_objects = node_codegen_objects(Path(spec["root_objects"]), spec_path)
    node_inputs = set(archives)
    node_inputs.update(root_objects)
    for script in native_outputs:
        node_inputs.update(Path(script["out_dir"]).rglob("*.a"))
    common, node = verify_common_ownership(graphs, sets, [], executable, env, directory,
                                          kind="executor", node_objects=sorted(node_inputs),
                                          compiler_objects=root_objects)
    helpers = audit_final(executable, graphs, sets, versions, directory, common,
                          kind="executor", node=node)
    libraries = runtime_libraries(executable, env, graphs)
    if digest(lock) != lock_hash or source_inputs(ROOT, data, kind="node") != sources:
        raise RuntimeError("node source or lock changed during compilation")
    if metadata(manifest, args.target, env, args.offline, features) != data:
        raise RuntimeError("node dependency metadata changed during compilation")
    for graph in graphs:
        verify_identity(ROOT, graph, recipes)
        verify_staged_inputs(graph)
    result = {"qualification_command": args.node_qualification, "executable": str(executable), "executable_sha256": digest(executable),
              "source_inputs_sha256": fingerprint(sources), "lock_sha256": lock_hash,
              "link_spec_sha256": digest(spec_path), "build_log_sha256": digest(log),
              "root_codegen_sha256": digest(Path(spec["root_objects"])), "wrapper_sha256": digest(wrapper),
              "native_helpers": helpers, "runtime_libraries": libraries,
              "compiler_proc_macros": [{"path": str(path), "sha256": digest(path)} for path in proc_macros],
              "ownership": {name: digest(directory / name) for name in (
                  "common-reference-ownership.json", "node-input-ownership.json", "input-ownership.json",
                  "input-local-ownership.json", "final-ownership.json")},
              "status": "node linked and native ownership checked; execution qualification required"}
    if args.node_qualification:
        result["interface_checks"] = verify_type_boundary(graphs, args.target, env, directory)
    write_json(directory / "build-inputs.json", result)
    return result


def install_node(node, destination):
    source = Path(node["executable"])
    destination = destination.absolute()
    if source.resolve() == destination.resolve():
        raise RuntimeError("installation must not overwrite the audited build output")
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Verify the copied bytes before replacing an existing installed executable.
    with tempfile.NamedTemporaryFile(dir=destination.parent, prefix=".kontor-", delete=False) as file:
        temporary = Path(file.name)
    try:
        shutil.copyfile(source, temporary)
        if digest(temporary) != node["executable_sha256"]:
            raise RuntimeError("node executable changed after its ownership audit")
        temporary.chmod(0o755)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return {"path": str(destination), "sha256": node["executable_sha256"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / ".build-cache/protocol-bundles")
    parser.add_argument("--target", choices=sorted(TARGETS))
    parser.add_argument("--profile", choices=("release", "dev"), default="release")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--link-set", choices=sorted(EXECUTOR_LINK_SETS),
                        help="select an explicit retained executor source configuration")
    parser.add_argument("--jobs", type=int, default=2)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--build-executors", action="store_true",
                        help="stage production executor libraries for the node linker; does not qualify a node")
    mode.add_argument("--build-node", action="store_true",
                      help="build the production node with retained executors and audit native ownership")
    parser.add_argument("--node-qualification", action="store_true",
                        help="include the isolated executor integration command; requires --build-node")
    parser.add_argument("--install-node", type=Path,
                        help="copy the audited executable to this path; requires --build-node")
    args = parser.parse_args()
    if args.node_qualification and not args.build_node:
        parser.error("--node-qualification requires --build-node")
    if args.install_node and not args.build_node:
        parser.error("--install-node requires --build-node")
    production = args.build_executors or args.build_node
    if args.link_set and not production:
        parser.error("--link-set requires --build-executors or --build-node")
    if production and args.link_set is None:
        args.link_set = "k4-node"
    if not 1 <= args.jobs <= 2:
        parser.error("protocol qualification uses one or two compiler jobs")
    env = dict(os.environ, RUSTUP_TOOLCHAIN=TOOLCHAIN, RUSTC_WRAPPER="", CCACHE_DISABLE="1",
               CARGO_BUILD_JOBS=str(args.jobs))
    for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC", "RUSTC_WORKSPACE_WRAPPER",
                "CARGO_BUILD_RUSTC", "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER"):
        env.pop(key, None)
    for key in list(env):
        if key.startswith("CARGO_PROFILE_") or (key.startswith("CARGO_TARGET_") and key.endswith("RUSTFLAGS")):
            env.pop(key)
    pinned = subprocess.check_output(["rustup", "which", "--toolchain", TOOLCHAIN, "rustc"],
                                     env=env, text=True).strip()
    env.update(RUSTC=pinned, KONTOR_PINNED_RUSTC=pinned, RUSTC_WORKSPACE_WRAPPER="")
    compiler = subprocess.check_output([pinned, "-Vv"], env=env, text=True)
    host = next(line.removeprefix("host: ") for line in compiler.splitlines() if line.startswith("host: "))
    args.target = args.target or host
    if args.target not in TARGETS or args.target != host:
        parser.error("qualification must execute natively on a supported target")
    toolchain = toolchain_inputs(env, args.target)
    output = args.output.resolve() / args.target / args.profile
    if production:
        output /= "executors"
        if args.link_set:
            output /= args.link_set
    output.mkdir(parents=True, exist_ok=True)
    lock = (args.output.resolve() / ".build.lock").open("a")
    try:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        raise RuntimeError("another protocol bundle builder owns this output directory") from error
    (output / "qualification.json").unlink(missing_ok=True)
    if production:
        (output / "executor-build.json").unlink(missing_ok=True)
        (output / "node-build.json").unlink(missing_ok=True)
    graphs = executor_graphs(args.link_set) if production else GRAPHS
    verify_reservations(ROOT, graphs)
    verify_capabilities(ROOT)
    reports = [build_graph(graph, args, env, output, graphs) for graph in graphs]
    write_json(output / "build-inputs.json", {"compiler": compiler, "target": args.target,
               "profile": args.profile, "graphs": reports})
    proof = None if production else qualify(reports, args, env, output)
    node = build_node(reports, args, env, output) if args.build_node else None
    for report in reports:
        data = json.loads((output / report["graph"] / "metadata.json").read_text())
        recipe = graphs[report["graph"]]
        if fingerprint(source_inputs(graph_root(ROOT, recipe), data, kind=recipe.kind,
                                     tool_root=ROOT)) != report["source_inputs_sha256"]:
            raise RuntimeError("source inputs changed before qualification finished")
    if toolchain_inputs(env, args.target) != toolchain:
        raise RuntimeError("common compiler inputs changed during qualification")
    verify_reservations(ROOT, graphs)
    verify_capabilities(ROOT)
    if production:
        for report in reports:
            verify_identity(ROOT, report, graphs)
            verify_staged_inputs(report)
        write_json(output / "executor-build.json", {"compiler": compiler, "toolchain_inputs": toolchain,
                   "target": args.target, "profile": args.profile, "link_set": args.link_set, "graphs": reports,
                   "status": "staged libraries; final node link and execution qualification required"})
        if node is not None:
            if args.install_node:
                node["installed"] = install_node(node, args.install_node)
            write_json(output / "node-build.json", {"compiler": compiler, "toolchain_inputs": toolchain,
                       "target": args.target, "profile": args.profile, "link_set": args.link_set,
                       "graphs": reports, "node": node})
            print(f"Node built at {node['executable']}; execution qualification has not run.", flush=True)
            return
        print(f"Executor libraries staged at {output}; node qualification has not run.", flush=True)
        return
    write_json(output / "qualification.json", {"compiler": compiler, "toolchain_inputs": toolchain, "target": args.target,
               "profile": args.profile, "graphs": reports, "proof": proof})
    print(json.dumps(proof, indent=2), flush=True)


if __name__ == "__main__":
    main()
