#!/usr/bin/env python3
"""Compatibility helpers for remaining evidence tools; builds run in Rust."""

import argparse
from dataclasses import asdict
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import subprocess

from provenance import _request, fingerprint
from recipes import GRAPHS

ROOT = Path(__file__).resolve().parents[2]


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


def identities(graph, data, graphs=None):
    recipe = (GRAPHS if graphs is None else graphs)[graph]
    return _request(dict(operation="identities", root=str(ROOT), recipe=asdict(recipe),
                         data=data), command="build-inputs")


def verify_capabilities(root):
    _request(dict(operation="capabilities", root=str(root.absolute())), command="build-inputs")


def _artifacts(action, **values):
    return _request(dict(operation="artifacts", action=action, cwd=str(Path.cwd()), **values), command="build-inputs")


def verify_staged_inputs(graph):
    _artifacts("verify_staged", graph=graph)


def main():
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--install-node", type=Path)
    paths, arguments = parser.parse_known_args()
    # The Rust entry point uses checkout-relative paths; preserve this legacy CLI's caller-relative paths.
    for option, value in (("--output", paths.output), ("--install-node", paths.install_node)):
        if value is not None:
            arguments.extend([option, str(value.absolute())])
    tool = str(ROOT / "tools/kontor")
    os.execv(tool, [tool, "protocol-bundles", *arguments])


if __name__ == "__main__":
    main()
