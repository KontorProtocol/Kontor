"""Compatibility access to Rust managed consensus provenance."""

import argparse
import json
from pathlib import Path

from coordinator_definition import CATALOG, _definition

DESTINATION = CATALOG["destination"]
REFERENCE_DIRECTORY = CATALOG["directory"]
GRAPH = CATALOG["graph"]
BUILD_INPUTS = tuple(CATALOG["build_inputs"])
TOOL = BUILD_INPUTS[0]


def graph_manifest(label):
    if label != "first":
        raise ValueError("unknown managed consensus graph")
    return GRAPH


def destination(label):
    graph_manifest(label)
    return DESTINATION


def graph_reference(root, metadata, lock, label="first"):
    return _definition("graph", root=str(root.absolute()), metadata=metadata, lock=lock, label=label)


def reference(root, node_metadata, node_lock, graph_metadata, graph_lock, label="first"):
    return _definition("managed", root=str(root.absolute()), node=node_metadata, node_lock=node_lock,
                       graph=graph_metadata, graph_lock=graph_lock, label=label, verify=False).encode()


def verify(root, node_metadata, node_lock, graph_metadata, graph_lock, label="first"):
    return _definition("managed", root=str(root.absolute()), node=node_metadata, node_lock=node_lock,
                       graph=graph_metadata, graph_lock=graph_lock, label=label, verify=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--graph", choices=("first",), default="first")
    parser.add_argument("--node-metadata", type=Path)
    parser.add_argument("--graph-metadata", type=Path)
    args = parser.parse_args()
    print(json.dumps(_definition("freeze", root=str(Path(__file__).resolve().parents[2]), baseline=False,
                                 write=args.write, graph=args.graph,
                                 node_metadata=str(args.node_metadata.absolute()) if args.node_metadata else None,
                                 graph_metadata=str(args.graph_metadata.absolute()) if args.graph_metadata else None)))


if __name__ == "__main__":
    main()
