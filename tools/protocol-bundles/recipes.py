"""Bind separately linked graphs to immutable sources and execution settings."""

from dataclasses import dataclass
import hashlib
import json
import tomllib

from audit import suffix


@dataclass(frozen=True)
class Graph:
    directory: str
    revision: str
    version: str
    itoa: str | None
    lift_rate: int
    kind: str = "proof"
    native_patches: tuple[str, ...] = ("blst", "ring", "secp256k1-sys")
    malachite_engine: bool = True


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
}
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
        if graph.version in versions or suffix(graph.version) in prefixes:
            raise RuntimeError(f"reserved Wasmtime version or native prefix: {label}")
        versions.add(graph.version)
        prefixes.add(suffix(graph.version))
        manifest = root / "protocol-bundles" / graph.directory / "Cargo.toml"
        dependency = tomllib.loads(manifest.read_text())["dependencies"]["wasmtime"]
        if dependency.get("rev") != graph.revision or dependency.get("version") != "=" + graph.version:
            raise RuntimeError(f"proof manifest has the wrong immutable identity: {label}")


def identity(root, label, graphs=None):
    graph = (GRAPHS if graphs is None else graphs)[label]
    base = root / "protocol-bundles" / graph.directory
    return {"directory": graph.directory, "wasmtime_revision": graph.revision,
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
