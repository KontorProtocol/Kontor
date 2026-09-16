import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    experiment = Path(__file__).resolve().parent
    root = experiment.parents[1]
    manifest = root / "core/Cargo.toml"
    metadata = json.loads(subprocess.check_output([
        "cargo", "metadata", "--locked", "--offline", "--format-version=1",
        "--manifest-path", str(manifest),
    ]))
    ffi = next(p for p in metadata["packages"] if p["name"] == "libsql-ffi")
    headers = Path(ffi["manifest_path"]).parent / "bundled/src"
    source = root / "core/indexer/src/database/queries/contract_state.rs"
    original = source.read_bytes()
    marker = "mod extension_probe;"
    if marker.encode() in original:
        raise RuntimeError("An extension probe is already attached; finish that run first")
    attachment = (
        '\n#[cfg(test)]\n#[path = '
        + json.dumps(str(experiment / "probe.rs"))
        + ']\n' + marker + '\n'
    ).encode()
    candidate = original + attachment
    with tempfile.TemporaryDirectory(prefix="kontor-blob-extension-") as temp:
        if sys.platform == "darwin":
            library = Path(temp) / "kontor_blob.dylib"
            shared = "-dynamiclib"
        elif sys.platform.startswith("linux"):
            library = Path(temp) / "kontor_blob.so"
            shared = "-shared"
        else:
            raise RuntimeError("This local experiment supports Linux and macOS")
        subprocess.run([
            "cc", "-O3", "-Wall", "-Wextra", "-Werror", "-fPIC", shared,
            "-I", str(headers), str(experiment / "blob.c"), "-o", str(library),
        ], check=True)
        env = dict(os.environ, KONTOR_BLOB_EXTENSION=str(library))
        try:
            source.write_bytes(candidate)
            subprocess.run([
                "cargo", "test", "--manifest-path", str(manifest), "--locked",
                "-p", "indexer", "--release", "--lib", "extension_probe", "--",
                "--ignored", "--nocapture", "--test-threads=1",
            ], cwd=root / "core/indexer", env=env, check=True)
        finally:
            if source.read_bytes() != candidate:
                raise RuntimeError("Source changed during probe; remove its module attachment manually")
            source.write_bytes(original)


if __name__ == "__main__":
    main()
