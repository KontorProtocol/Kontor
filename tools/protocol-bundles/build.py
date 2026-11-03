#!/usr/bin/env python3
"""Resolve, build and attest separately owned protocol dependency graphs."""

import argparse
from dataclasses import asdict
import fcntl
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from audit import audit_final, audit_inputs
from common_ownership import verify as verify_common_ownership
from provenance import _request, fingerprint, proc_macro_hashes, runtime_libraries, source_inputs
from provenance import tools as toolchain_inputs
from symbol_tool import TOOLCHAIN
from recipes import CONSENSUS_GRAPHS, EXECUTOR_LINK_SETS, GRAPHS, executor_graphs, graph_root, verify_engine_observations, verify_identity, verify_reservations
from type_boundary import verify as verify_type_boundary, verify_node_adapter

ROOT = Path(__file__).resolve().parents[2]
TARGETS = {"aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu", "aarch64-apple-darwin"}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def stage_compiler_wrapper(output, env, offline, *, kind="graph"):
    if offline:
        env = dict(env, CARGO_NET_OFFLINE="true")
    tool = env.get("KONTOR_BUILD_TOOL") or str(ROOT / "tools/kontor")
    return Path(subprocess.check_output(
        [tool, f"stage-{kind}-wrapper", str(output.resolve())],
        cwd=ROOT, env=env, text=True).strip())


@lru_cache(maxsize=1)
def linker_validator():
    return stage_compiler_wrapper(ROOT / ".build-cache/linker-validation", dict(os.environ), False, kind="linker")


def validate_linker_record(record, spec_hash, output_hash, compiler_output=None, *, verifier=None):
    request = dict(record=record, spec_hash=spec_hash, output_hash=output_hash, compiler_output=compiler_output)
    result = subprocess.run([str(verifier or linker_validator()), "--verify-record"], input=json.dumps(request),
                            capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(result.stderr.strip())


def linker_wrapper_source_hash(root):
    return fingerprint({path: digest(root / path) for path in (
        "core/kontor-build/src/bin/kontor-node-linker.rs", "core/kontor-build/src/linker_record.rs")})


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
    return _request(dict(operation="identities", root=str(ROOT), recipe=asdict(recipe),
                         data=data), command="build-inputs")


def verify_capabilities(root):
    _request(dict(operation="capabilities", root=str(root.absolute())), command="build-inputs")


def build_graph(graph, args, base_env, output, graphs=None):
    graphs = GRAPHS if graphs is None else graphs
    wrapper = stage_compiler_wrapper(output / graph, base_env, args.offline)
    request = dict(root=str(ROOT), label=graph, graphs={name: asdict(recipe) for name, recipe in graphs.items()},
                   options=dict(target=args.target, profile=args.profile, jobs=args.jobs, offline=args.offline),
                   env=base_env, output=str(output.resolve()), wrapper=str(wrapper),
                   cargo_home=str(Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo")).absolute()))
    return _request(dict(operation="build_graph", request=request), command="build-inputs", env=base_env)


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


def _artifacts(action, **values):
    return _request(dict(operation="artifacts", action=action, cwd=str(Path.cwd()), **values), command="build-inputs")


def verify_staged_inputs(graph):
    _artifacts("verify_staged", graph=graph)

def build_node(graphs, args, base_env, output, consensus=()):
    directory = output / "node"
    linker = stage_compiler_wrapper(directory, base_env, args.offline, kind="linker")
    wrapper = stage_compiler_wrapper(directory, base_env, args.offline, kind="node")
    request = dict(root=str(ROOT), graphs=graphs, consensus=list(consensus),
                   options=dict(target=args.target, profile=args.profile, jobs=args.jobs, offline=args.offline,
                                link_set=args.link_set, node_qualification=args.node_qualification),
                   env=base_env, output=str(output.resolve()), node_wrapper=str(wrapper), linker_wrapper=str(linker),
                   cargo_home=str(Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo")).absolute()))
    return _request(dict(operation="build_node", request=request), command="build-inputs", env=base_env)


def install_node(node, destination):
    return _artifacts("install_node", node=node, destination=str(destination.absolute()))

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
    mode.add_argument("--build-consensus", action="store_true",
                      help="stage production consensus libraries; does not qualify a node or handoff")
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
    execution = args.build_executors or args.build_node
    production = execution or args.build_consensus
    if args.link_set and not execution:
        parser.error("--link-set requires --build-executors or --build-node")
    if execution and args.link_set is None:
        args.link_set = "managed-node" if args.build_node else "k4-node"
    if not 1 <= args.jobs <= 2:
        parser.error("protocol qualification uses one or two compiler jobs")
    env = dict(os.environ, RUSTUP_TOOLCHAIN=TOOLCHAIN, RUSTC_WRAPPER="", CCACHE_DISABLE="1",
               CARGO_BUILD_JOBS=str(args.jobs))
    if args.offline:
        env["CARGO_NET_OFFLINE"] = "true"
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
    if args.build_consensus:
        output /= "consensus"
    elif execution:
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
        (output / "consensus-build.json").unlink(missing_ok=True)
        (output / "node-build.json").unlink(missing_ok=True)
    graphs = (CONSENSUS_GRAPHS if args.build_consensus else
              executor_graphs(args.link_set) if execution else GRAPHS)
    verify_reservations(ROOT, graphs)
    if not args.build_consensus:
        verify_capabilities(ROOT)
    reports = [build_graph(graph, args, env, output, graphs) for graph in graphs]
    write_json(output / "build-inputs.json", {"compiler": compiler, "target": args.target,
               "profile": args.profile, "graphs": reports})
    proof = None if production else qualify(reports, args, env, output)
    consensus_reports = []
    if args.build_node and args.link_set == "managed-node":
        consensus_output = args.output.resolve() / args.target / args.profile / "consensus"
        consensus_output.mkdir(parents=True, exist_ok=True)
        verify_reservations(ROOT, CONSENSUS_GRAPHS)
        consensus_reports = [build_graph(graph, args, env, consensus_output, CONSENSUS_GRAPHS)
                             for graph in CONSENSUS_GRAPHS]
    node = build_node(reports, args, env, output, consensus_reports) if args.build_node else None
    consensus_controls = None
    if args.build_consensus:
        audit_inputs(reports, output)
        consensus_controls = {"interfaces": verify_type_boundary(reports, args.target, env, output),
                              "node_adapter": verify_node_adapter(ROOT, reports, args.target, env, output),
                              "input_ownership_sha256": digest(output / "input-ownership.json")}
    for report in reports:
        data = json.loads((output / report["graph"] / "metadata.json").read_text())
        recipe = graphs[report["graph"]]
        if fingerprint(source_inputs(graph_root(ROOT, recipe), data, kind=recipe.kind,
                                     tool_root=ROOT, env=env)) != report["source_inputs_sha256"]:
            raise RuntimeError("source inputs changed before qualification finished")
    for report in consensus_reports:
        data = json.loads((consensus_output / report["graph"] / "metadata.json").read_text())
        if fingerprint(source_inputs(ROOT, data, kind="consensus", env=env)) != report["source_inputs_sha256"]:
            raise RuntimeError("consensus source inputs changed before node build finished")
        verify_identity(ROOT, report, CONSENSUS_GRAPHS)
        verify_staged_inputs(report)
    if toolchain_inputs(env, args.target) != toolchain:
        raise RuntimeError("common compiler inputs changed during qualification")
    verify_reservations(ROOT, graphs)
    if not args.build_consensus:
        verify_capabilities(ROOT)
    if production:
        for report in reports:
            verify_identity(ROOT, report, graphs)
            verify_staged_inputs(report)
        report_name = "consensus-build.json" if args.build_consensus else "executor-build.json"
        build_report = {"compiler": compiler, "toolchain_inputs": toolchain,
                   "target": args.target, "profile": args.profile, "link_set": args.link_set, "graphs": reports,
                   "status": "staged libraries; final node link and execution qualification required"}
        if consensus_controls is not None:
            build_report["consensus_controls"] = consensus_controls
        write_json(output / report_name, build_report)
        if node is not None:
            if args.install_node:
                node["installed"] = install_node(node, args.install_node)
            write_json(output / "node-build.json", {"compiler": compiler, "toolchain_inputs": toolchain,
                       "target": args.target, "profile": args.profile, "link_set": args.link_set,
                       "graphs": reports, "consensus_graphs": consensus_reports, "node": node})
            print(f"Node built at {node['executable']}; execution qualification has not run.", flush=True)
            return
        print(f"{'Consensus' if args.build_consensus else 'Executor'} libraries staged at {output}; node qualification has not run.", flush=True)
        return
    write_json(output / "qualification.json", {"compiler": compiler, "toolchain_inputs": toolchain, "target": args.target,
               "profile": args.profile, "graphs": reports, "proof": proof})
    print(json.dumps(proof, indent=2), flush=True)


if __name__ == "__main__":
    main()
