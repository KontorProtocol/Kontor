"""Bind separately linked graphs to immutable sources and execution settings."""

from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import PurePosixPath
import tomllib

from audit import suffix
from freeze_sources import verify_snapshot


@dataclass(frozen=True)
class Graph:
    directory: str
    revision: str | None
    version: str | None
    itoa: str | None
    lift_rate: int
    kind: str = "proof"
    native_patches: tuple[str, ...] = ("blst", "ring", "secp256k1-sys")
    malachite_engine: bool = True
    source_root: str = "."
    source_snapshot: str | None = None


def graph_root(root, graph):
    relative = PurePosixPath(graph.source_root)
    if relative.is_absolute() or ".." in relative.parts or str(relative) != graph.source_root:
        raise RuntimeError("graph source root must be a canonical repository-relative path")
    root = root.resolve()
    selected = (root / relative).resolve(strict=True)
    if not selected.is_relative_to(root) or not selected.is_dir():
        raise RuntimeError("graph source root escapes the repository")
    if graph.source_snapshot is not None:
        verify_snapshot(selected, graph.source_snapshot)
    return selected


GRAPHS = {
    "first": Graph("pulley-first", "0f84389ecd927c2e154f8d0de31fc2dfa5ebcae7", "51.0.0-kontor.2", "1.0.14", 512),
    "second": Graph("pulley-second", "0dbc68b31c0bcf1a05c93122f1939fb8784e4e48", "51.0.0-kontor.3", "1.0.15", 513),
}
# These are separate link sets. A proof and an executor using the same Wasmtime
# version must never be combined into one executable.
EXECUTOR_GRAPHS = {
    "first": Graph("executor-first", "0f84389ecd927c2e154f8d0de31fc2dfa5ebcae7",
                   "51.0.0-kontor.2", None, 512, kind="executor",
                   native_patches=("blst", "secp256k1-sys", "psm", "wit-bindgen"), malachite_engine=False),
    "second": Graph("executor-second", "0dbc68b31c0bcf1a05c93122f1939fb8784e4e48",
                    "51.0.0-kontor.3", None, 512, kind="executor",
                    native_patches=("blst", "secp256k1-sys", "psm", "wit-bindgen"), malachite_engine=False),
}
RETAINED_EXECUTOR_GRAPHS = {
    label: replace(graph, source_root="protocol-bundles/retained/k3",
                   source_snapshot="fc85d7f7479662012faef9bc43e3efaf7c9299ddc940ffd5ef5865abe5667592")
    for label, graph in EXECUTOR_GRAPHS.items()
}
P1_GRAPH = replace(EXECUTOR_GRAPHS["first"], source_root="protocol-bundles/retained/p1",
                   source_snapshot="4df4b75941b026b19a6dffcf2371afdd4d997e2b8cd33322002c782e3bc36cfc")
OBSERVER_GRAPH = replace(EXECUTOR_GRAPHS["second"], directory="executor-observer")
EXECUTOR_LINK_SETS = {
    "legacy-qualification": RETAINED_EXECUTOR_GRAPHS,
    "k4-node": {"first": RETAINED_EXECUTOR_GRAPHS["first"], "observer": OBSERVER_GRAPH},
    "managed-node": {"first": P1_GRAPH, "observer": OBSERVER_GRAPH},
}

MALACHITE_REVISION = "6d99c0a43a21ff48ff3f69a5f9e834310d0b0b09"
MALACHITE_VERSION = "0.9.0-kontor.1"
CONSENSUS_GRAPHS = {
    label: Graph("consensus-" + label, None, None, None, 0, kind="consensus",
                 native_patches=("ring", "secp256k1-sys"))
    for label in ("first",)
}


def verify_consensus_manifest(manifest):
    dependencies = tomllib.loads(manifest.read_text())["dependencies"]
    if "wasmtime" in dependencies:
        raise RuntimeError("consensus graph must not contain Wasmtime")
    engines = [value for value in dependencies.values()
               if isinstance(value, dict) and value.get("package", "").startswith("arc-malachite")]
    if not engines or any(value.get("git") != "https://github.com/KontorProtocol/malachite"
                          or value.get("rev") != MALACHITE_REVISION
                          or value.get("version") != "=" + MALACHITE_VERSION for value in engines):
        raise RuntimeError("consensus manifest has the wrong immutable identity")


def executor_graphs(link_set):
    if link_set is None:
        return EXECUTOR_GRAPHS
    try:
        return EXECUTOR_LINK_SETS[link_set]
    except KeyError as error:
        raise ValueError(f"unknown executor link set: {link_set}") from error


HISTORICAL = {
    "first": ("75a06735d294f3fc04a4ffff54492d3bf80e4121faa2e2aae64434e5b252db6b",
              "0a84113a26aea6aa3faef82eba2c5fd3164db061082da3fc4497517962d243de"),
    "second": ("66dc6afb0e37b34158ec0333962c5f29fec3d3b545f253d7dc9cebe78ea4fae5",
               "6e7f58ee120e85b853541827993512f2ace20b71dc65afa25c63ac08576a95c3"),
}
EXECUTION = {"target": "pulley64-unknown-unknown-elf", "max_wasm_stack": 524288,
             "async_stack_size": 2097152, "logical_stack_alignment": 16,
             "guest_concurrency": False}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_reservations(root, graphs=None):
    graphs = GRAPHS if graphs is None else graphs
    versions = set()
    prefixes = set()
    for directory, hashes in HISTORICAL.items():
        base = root / "protocol-bundles" / directory
        if tuple(sha(base / name) for name in ("Cargo.toml", "Cargo.lock")) != hashes:
            raise RuntimeError(f"historical proof inputs changed: {directory}")
        dependency = tomllib.loads((base / "Cargo.toml").read_text())["dependencies"]["wasmtime"]
        version = dependency["version"].removeprefix("=")
        versions.add(version)
        prefixes.add(suffix(version))
    for label, graph in graphs.items():
        manifest = graph_root(root, graph) / "protocol-bundles" / graph.directory / "Cargo.toml"
        if graph.kind == "consensus":
            if graph.version is not None or graph.revision is not None:
                raise RuntimeError("consensus recipe has an unexpected Wasmtime identity")
            verify_consensus_manifest(manifest)
            continue
        if graph.version in versions or suffix(graph.version) in prefixes:
            raise RuntimeError(f"reserved Wasmtime version or native prefix: {label}")
        versions.add(graph.version)
        prefixes.add(suffix(graph.version))
        dependency = tomllib.loads(manifest.read_text())["dependencies"]["wasmtime"]
        if dependency.get("rev") != graph.revision or dependency.get("version") != "=" + graph.version:
            raise RuntimeError(f"proof manifest has the wrong immutable identity: {label}")


def identity(root, label, graphs=None):
    graph = (GRAPHS if graphs is None else graphs)[label]
    base = graph_root(root, graph) / "protocol-bundles" / graph.directory
    if graph.kind == "consensus":
        return {"kind": "consensus", "directory": graph.directory,
                "source_root": graph.source_root, "source_snapshot": graph.source_snapshot,
                "malachite_revision": MALACHITE_REVISION, "malachite_version": MALACHITE_VERSION,
                "manifest_sha256": sha(base / "Cargo.toml"), "lock_sha256": sha(base / "Cargo.lock")}
    return {"directory": graph.directory, "wasmtime_revision": graph.revision,
            "source_root": graph.source_root,
            "source_snapshot": graph.source_snapshot,
            "wasmtime_version": graph.version, "manifest_sha256": sha(base / "Cargo.toml"),
            "lock_sha256": sha(base / "Cargo.lock"), "execution": dict(EXECUTION),
            "lift_rate": graph.lift_rate}


def verify_identity(root, report, graphs=None):
    graphs = GRAPHS if graphs is None else graphs
    label = report.get("graph")
    if label not in graphs or report.get("identity") != identity(root, label, graphs):
        raise RuntimeError("graph identity or execution attestation changed")


def verify_engine_observations(log):
    observations = []
    seen = set()
    for line in log.splitlines():
        if not line.startswith("KONTOR_VM_ATTESTATION "):
            continue
        item = json.loads(line.removeprefix("KONTOR_VM_ATTESTATION "))
        label = item.get("graph")
        if label not in GRAPHS or item != {"graph": label, **EXECUTION,
                                           "lift_rate": GRAPHS[label].lift_rate}:
            raise RuntimeError("resolved proof engine differs from its recipe")
        observations.append(item)
        seen.add(label)
    if seen != set(GRAPHS):
        raise RuntimeError("missing resolved proof engine observations")
    return observations
