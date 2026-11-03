"""Compatibility access to Rust graph recipes until the builder migration."""

from dataclasses import asdict, dataclass
import os
from pathlib import Path
import sys

from provenance import _request, sha


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


def _recipe(operation, **values):
    env = dict(os.environ)
    # Direct callers import the catalog before argparse propagates offline mode.
    if "--offline" in sys.argv[1:]:
        env["CARGO_NET_OFFLINE"] = "true"
    return _request(dict(operation=operation, **values), command="recipes", env=env)


def _graph(value):
    return Graph(**dict(value, native_patches=tuple(value["native_patches"])))


def _graphs(values):
    return {label: _graph(graph) for label, graph in values.items()}


_catalog = _recipe("catalog")
GRAPHS = _graphs(_catalog["graphs"])
EXECUTOR_GRAPHS = _graphs(_catalog["executor_graphs"])
RETAINED_EXECUTOR_GRAPHS = _graphs(_catalog["retained_executor_graphs"])
P1_GRAPH = _graph(_catalog["p1_graph"])
OBSERVER_GRAPH = _graph(_catalog["observer_graph"])
EXECUTOR_LINK_SETS = {name: _graphs(_catalog["executor_link_sets"][name])
                      for name in ("legacy-qualification", "k4-node", "managed-node")}
CONSENSUS_GRAPHS = _graphs(_catalog["consensus_graphs"])
MALACHITE_REVISION = _catalog["malachite_revision"]
MALACHITE_VERSION = _catalog["malachite_version"]
HISTORICAL = {name: tuple(hashes) for name, hashes in _catalog["historical"].items()}
EXECUTION = _catalog["execution"]
del _catalog


def graph_root(root, graph):
    return Path(_recipe("graph_root", root=str(root.absolute()), graph=asdict(graph)))


def verify_consensus_manifest(manifest):
    _recipe("verify_consensus_manifest", manifest=str(manifest.absolute()))


def executor_graphs(link_set):
    if link_set is None:
        return EXECUTOR_GRAPHS
    try:
        return EXECUTOR_LINK_SETS[link_set]
    except KeyError as error:
        raise ValueError(f"unknown executor link set: {link_set}") from error


def _selected(graphs):
    return {label: asdict(graph) for label, graph in (GRAPHS if graphs is None else graphs).items()}


def verify_reservations(root, graphs=None):
    _recipe("verify_reservations", root=str(root.absolute()), graphs=_selected(graphs))


def identity(root, label, graphs=None):
    return _recipe("identity", root=str(root.absolute()), label=label, graphs=_selected(graphs))


def verify_identity(root, report, graphs=None):
    _recipe("verify_identity", root=str(root.absolute()), report=report, graphs=_selected(graphs))


def verify_engine_observations(log):
    return _recipe("verify_engine_observations", log=log)
