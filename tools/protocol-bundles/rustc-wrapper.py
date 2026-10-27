#!/usr/bin/env python3
"""Give target and host compiler units the same graph-specific crate namespace."""

import os
from pathlib import Path
import re
import sys

namespace = os.environ.get("KONTOR_NATIVE_NAMESPACE", "")
if not re.fullmatch(r"kontor_(first|second)_[0-9a-f]{24}", namespace):
    raise SystemExit("missing or invalid protocol graph compiler namespace")
wrapper = Path(__file__).resolve()
if Path(os.environ.get("RUSTC_WRAPPER", "")).resolve() != wrapper or os.environ.get("RUSTC_WORKSPACE_WRAPPER"):
    raise SystemExit("protocol builds forbid an additional compiler wrapper")
compiler, *arguments = sys.argv[1:]
expected = os.environ.get("KONTOR_PINNED_RUSTC")
if not expected or Path(compiler).resolve() != Path(expected).resolve():
    raise SystemExit("protocol wrapper requires the exact pinned rustc, not another compiler or wrapper")
probe = any(arg in ("-vV", "--version", "--print", "-") or arg.startswith("--print=") for arg in arguments)
if "--crate-name" in arguments and not probe:
    # rustc folds repeated metadata options into the identity. Keep Cargo's
    # per-unit metadata and add the graph identity for host and target units.
    arguments.append("-Cmetadata=" + namespace)
os.execv(compiler, [compiler, *arguments])
