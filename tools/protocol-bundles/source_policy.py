"""Guard maintained bundle code against taking node signal or child ownership.

This source check is a review tripwire, not a Rust sandbox. Dependency source
hashes, reviewed process-resource exceptions and the live ownership proof remain
required. Renaming a forbidden operation does not make it permitted.
"""

import hashlib
from pathlib import Path
import re


CONTROL = re.compile(
    r"\b(?:tokio\s*::\s*(?:signal|process)|signal_hook|ctrl_c|"
    r"SIGCHLD|SIGTERM|SIGINT|sigaction|sighandler|"
    r"Command\s*::|(?:std|tokio)\s*::\s*process\s*::|"
    r"(?:fork|vfork|posix_spawn|execve|waitpid|signal)\s*\()"
)


def check(root, metadata):
    paths = set()
    for package in metadata["packages"]:
        if package["name"].startswith("arc-malachite") or package["name"] == "if-watch":
            paths.update(Path(package["manifest_path"]).parent.joinpath("src").rglob("*.rs"))
    paths.update(path for path in (root / "protocol-bundles/proof").glob("*.rs")
                 if path.name not in ("host.rs", "cross_graph_rejected.rs"))
    result = []
    for path in sorted(paths):
        source = path.read_text()
        if CONTROL.search(source):
            raise RuntimeError(f"maintained bundle source needs process-ownership review: {path}")
        result.append({"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    if not result:
        raise RuntimeError("empty maintained bundle source-policy inventory")
    return {"maintained_sources": result,
            "exceptions": ["node-owned proof/host.rs signals and child reaping",
                           "pinned Wasmtime F1 Unix VM trap handlers and Rayon pool",
                           "pinned Tokio Unix registry pairs without bundle subscribers",
                           "pinned futures-timer helper and blst crypto-only pool"]}
