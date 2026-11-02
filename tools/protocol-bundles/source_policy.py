"""Guard maintained bundle code against taking node signal or child ownership.

This source check is a review tripwire, not a Rust sandbox. Dependency source
hashes, reviewed process-resource exceptions and the live ownership proof remain
required. Renaming a forbidden operation does not make it permitted.
"""

import hashlib
from pathlib import Path
import re

from provenance import RETAINED_TREES, consensus_sources


# Certified-input enum variants and reading a PID do not take process ownership.
CONTROL = re.compile(
    r"\b(?:tokio\s*::\s*(?:signal|process)|signal_hook|ctrl_c|"
    r"SIGCHLD|SIGTERM|SIGINT|sigaction|sighandler|"
    r"Command\s*::(?!\s*(?:Block|Batch|Control)\b)|(?:std|tokio)\s*::\s*process\s*::(?!\s*id\b)|"
    r"(?:fork|vfork|posix_spawn|execve|waitpid|signal)\s*\()"
)


def excluded_module(root, parent, module, guard):
    path = root / parent
    declaration = re.escape(guard) + r"\s*(?:pub(?:\([^)]*\))?\s+)?mod " + module + ";"
    if not re.search(declaration, path.read_text()):
        raise RuntimeError(f"retained module exclusion guard changed: {parent}::{module}")
    directory = path.parent if path.name == "mod.rs" else path.with_suffix("")
    return {directory / f"{module}.rs", *(directory / module).rglob("*.rs")}


def check(root, metadata, *, kind="proof"):
    if kind not in ("proof", "executor", "consensus"):
        raise RuntimeError(f"unknown graph source kind: {kind}")
    paths = set()
    for package in metadata["packages"]:
        if package["name"].startswith("arc-malachite") or package["name"] == "if-watch":
            paths.update(Path(package["manifest_path"]).parent.joinpath("src").rglob("*.rs"))
    test_sources = []
    node_sources = []
    if kind == "proof":
        paths.update(path for path in (root / "protocol-bundles/proof").glob("*.rs")
                     if path.name not in ("host.rs", "cross_graph_rejected.rs"))
    elif kind == "consensus":
        paths.update(root / relative for relative in consensus_sources(root) if relative.endswith(".rs"))
        # These node adapters are inventoried for provenance but are not part
        # of the bundle. Only the explicitly imported production types compile.
        shared = root / "protocol-bundles/consensus"
        imported = set()
        for source in shared.rglob("*.rs"):
            for relative in re.findall(r'#\[path\s*=\s*"([^"]+)"\]', source.read_text()):
                imported.add((source.parent / relative).resolve())
        paths = {path for path in paths if not path.is_relative_to(root / "core/indexer")
                 or path.resolve() in imported}
    else:
        for relative in RETAINED_TREES:
            paths.update((root / relative).rglob("*.rs"))
        # The subprocess probes are only reachable through this test module.
        # Their bytes remain bound by the complete source fingerprint.
        excluded = excluded_module(root, "core/indexer/src/runtime/call.rs", "tests", "#[cfg(test)]")
        test_sources = [{"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                        for path in sorted(paths & excluded)]
        paths -= excluded
        excluded = set()
        for parent, module in (("core/indexer/src/runtime/mod.rs", "ownership"),
                               ("core/indexer/src/runtime/mod.rs", "pool"),
                               ("core/indexer/src/protocol/mod.rs", "coordinator")):
            excluded.update(excluded_module(root, parent, module, "#[cfg(not(kontor_retained))]"))
        node_sources = [{"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                        for path in sorted(paths & excluded)]
        paths -= excluded
    result = []
    for path in sorted(paths):
        source = path.read_text()
        if CONTROL.search(source):
            raise RuntimeError(f"maintained bundle source needs process-ownership review: {path}")
        result.append({"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    if not result:
        raise RuntimeError("empty maintained bundle source-policy inventory")
    return {"maintained_sources": result, "test_only_sources": test_sources, "node_only_sources": node_sources,
            "exceptions": (["node-owned proof/host.rs signals and child reaping"] if kind == "proof" else []) + [
                           "pinned Tokio Unix registry pairs without bundle subscribers",
                           "pinned futures-timer helper"] + ([] if kind == "consensus" else [
                           "pinned Wasmtime F1 Unix VM trap handlers and Rayon pool",
                           "blst crypto-only pool"])}
