"""Compatibility access to Rust consensus-reference tooling."""

import argparse
import json
import os
from pathlib import Path
import sys

from provenance import _request


def _definition(operation, **values):
    if operation in ("coordinator", "graph", "managed"):
        values["cwd"] = str(Path.cwd())
    env = dict(os.environ)
    if (__name__ == "__main__" or Path(sys.argv[0]).name == "managed_definition.py"
            or "--offline" in sys.argv[1:]):
        env["CARGO_NET_OFFLINE"] = "true"
    try:
        return _request(dict(operation=operation, **values), command="consensus-definition", env=env)
    except RuntimeError as error:
        raise ValueError(str(error)) from error


CATALOG = _definition("catalog")
ROOTS = set(CATALOG["roots"])
TREES = tuple(CATALOG["trees"])
FILES = tuple(CATALOG["files"])
DESTINATION = CATALOG["baseline"]
POLICY = CATALOG["policy"]


def canonical(value):
    return _definition("canonical", value=value).encode()


def reference(root, metadata, lock):
    return _definition("coordinator", root=str(root.absolute()), metadata=metadata, lock=lock, verify=False).encode()


def verify(root, metadata, lock):
    return _definition("coordinator", root=str(root.absolute()), metadata=metadata, lock=lock, verify=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--metadata", type=Path)
    args = parser.parse_args()
    print(json.dumps(_definition("freeze", root=str(Path(__file__).resolve().parents[2]), baseline=True,
                                 write=args.write, graph="first", graph_metadata=None,
                                 node_metadata=str(args.metadata.absolute()) if args.metadata else None)))


if __name__ == "__main__":
    main()
