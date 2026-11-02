"""Prove that host compiler plugins retain distinct graph metadata identities."""

import os
from pathlib import Path
import re
import subprocess
import tempfile


def proc_macro_hashes(graphs, options, env, output):
    values = []
    for index, graph in enumerate(graphs):
        native = [item for item in graph["compiler_proc_macros"] if Path(item["path"]).name.startswith("librustversion-")]
        other = [item for item in graphs[1-index]["compiler_proc_macros"] if Path(item["path"]).name.startswith("librustversion-")]
        if len(native) != 1 or len(other) != 1:
            raise RuntimeError("expected one rustversion compiler plugin per graph")
        with tempfile.TemporaryDirectory(prefix="metadata-control-", dir=output) as directory:
            root = Path(directory)
            for path in Path(graph["link_inputs"]).iterdir():
                if path == Path(native[0]["staged"]):
                    continue
                os.symlink(path, root / path.name)
            replacement = Path(other[0]["staged"])
            os.symlink(replacement, root / replacement.name)
            source = root / "probe.rs"
            source.write_text(f'use kontor_proof_{graph["graph"]} as bundle;\nfn main() {{ let _ = bundle::shape(); }}\n')
            command = [env["RUSTC"], *options, "--emit=metadata", str(source), "-o", str(root / "probe.rmeta"),
                       "--extern", f'kontor_proof_{graph["graph"]}={graph["facade"]}', "-L", f"dependency={root}"]
            checked = subprocess.run(command, env=dict(env, RUSTC_LOG="rustc_metadata::locator=info"),
                                     text=True, capture_output=True)
            log = checked.stdout + checked.stderr
            (output / (graph["graph"] + "-wrong-proc-macro.log")).write_text(log)
            if checked.returncode == 0 or "E0463" not in log:
                raise RuntimeError("foreign proc-macro metadata was not rejected")
            mismatches = []
            candidate = ""
            for line in log.splitlines():
                if "reading metadata from: " in line:
                    candidate = line.split("reading metadata from: ", 1)[1]
                match = re.search(r"Rejecting via hash: expected ([0-9a-f]+) got ([0-9a-f]+)", line)
                if match and Path(candidate).name.startswith("librustversion-"):
                    mismatches.append(match.groups())
            if len(set(mismatches)) != 1:
                raise RuntimeError(f"ambiguous proc-macro metadata rejection: {mismatches}")
            expected, foreign = mismatches[0]
            if expected == foreign:
                raise RuntimeError("compiler plugins unexpectedly share an SVH")
            values.append({"graph": graph["graph"], "svh": expected, "foreign_svh": foreign,
                           "artifact": native[0]})
    if values[0]["svh"] != values[1]["foreign_svh"] or values[1]["svh"] != values[0]["foreign_svh"]:
        raise RuntimeError("bidirectional proc-macro rejection hashes do not match")
    return values
