"""Compatibility access to Rust execution references until caller migration."""

import argparse
import json
import os
from pathlib import Path
import sys

from provenance import _request


def _definition(operation, **values):
    if operation in ("reference", "verify", "effective_manifest"):
        values["cwd"] = str(Path.cwd())
    env = dict(os.environ)
    if __name__ == "__main__" or "--offline" in sys.argv[1:]:
        env["CARGO_NET_OFFLINE"] = "true"
    try:
        return _request(dict(operation=operation, **values), command="execution-definition", env=env)
    except RuntimeError as error:
        raise ValueError(str(error)) from error


SEMANTIC_TREES = tuple(_definition("catalog")["semantic_trees"])


def effective_manifest(root, package):
    return _definition("effective_manifest", root=str(root.absolute()), package=package)


def encode(sources, locks, features, policy):
    return bytes.fromhex(_definition("encode", sources={path: digest.hex() for path, digest in sources.items()},
                                    locks={path: digest.hex() for path, digest in locks.items()},
                                    features=features, policy=policy.hex()))


def reference(root, manifest, metadata):
    return bytes.fromhex(_definition("reference", root=str(root.absolute()),
                                    manifest=str(manifest.absolute()), metadata=metadata))


def verify_reference(root, manifest, metadata):
    manifest.with_name("definition.bin").read_bytes()
    return _definition("verify", root=str(root.absolute()), manifest=str(manifest.absolute()), metadata=metadata)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("graph", choices=("first", "second", "observer"))
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    print(json.dumps(_definition("freeze", root=str(Path(__file__).resolve().parents[2]), graph=args.graph, write=args.write)))


if __name__ == "__main__":
    main()
