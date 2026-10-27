#!/usr/bin/env python3
"""Verify or regenerate pinned native crypto vendors from pristine crate archives."""

import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request


ROOT = Path(__file__).resolve().parents[2]
CONFIG = Path(__file__).with_name("sources.json")
PATCHES = Path(__file__).with_name("patches")


def archive(entry, temporary):
    filename = f"{entry['name']}-{entry['version']}.crate"
    cargo = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
    cached = list((cargo / "registry/cache").glob(f"*/{filename}"))
    if cached:
        data = cached[0].read_bytes()
    else:
        url = f"https://static.crates.io/crates/{entry['name']}/{filename}"
        with urllib.request.urlopen(url, timeout=60) as response:
            data = response.read()
    actual = hashlib.sha256(data).hexdigest()
    if actual != entry["archive_sha256"]:
        raise RuntimeError(f"{filename}: archive SHA256 mismatch: {actual}")
    path = temporary / filename
    path.write_bytes(data)
    with tarfile.open(path) as package:
        package.extractall(temporary, filter="data")
    return temporary / filename.removesuffix(".crate")


def files(root):
    return {path.relative_to(root): path.read_bytes() for path in root.rglob("*") if path.is_file()}


def file_metadata(root):
    return {path.relative_to(root): (bool(path.stat().st_mode & 0o111),
                                   os.readlink(path) if path.is_symlink() else None)
            for path in root.rglob("*") if path.is_file() or path.is_symlink()}


def make_patch(pristine, vendor):
    before, after = files(pristine), files(vendor)
    chunks = []
    for name in sorted(before.keys() | after.keys()):
        old, new = before.get(name), after.get(name)
        if old == new:
            continue
        if b"\0" in (old or b"") or b"\0" in (new or b""):
            raise RuntimeError(f"unexpected binary vendor change: {name}")
        chunks.extend(difflib.unified_diff(
            (old or b"").decode().splitlines(keepends=True),
            (new or b"").decode().splitlines(keepends=True),
            fromfile=f"a/{name}" if old is not None else "/dev/null",
            tofile=f"b/{name}" if new is not None else "/dev/null"))
    return "".join(chunks)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--refresh-patches", action="store_true",
                        help="Record intentional vendor edits against verified pristine sources")
    parser.add_argument("--apply", action="store_true",
                        help="Recreate vendor directories from the recorded archives and patches")
    args = parser.parse_args()
    if args.refresh_patches and args.apply:
        parser.error("refresh and apply are mutually exclusive")
    PATCHES.mkdir(exist_ok=True)
    for entry in json.loads(CONFIG.read_text()):
        with tempfile.TemporaryDirectory(prefix="kontor-crypto-vendor-") as directory:
            pristine = archive(entry, Path(directory))
            vendor = ROOT / "core/vendor" / entry["vendor_directory"]
            patch = PATCHES / entry["patch"]
            if args.refresh_patches:
                patch.write_text(make_patch(pristine, vendor))
            if patch.stat().st_size:
                subprocess.run(["git", "apply", "--whitespace=error", str(patch)],
                               cwd=pristine, check=True)
            if args.apply:
                shutil.copytree(pristine, vendor, dirs_exist_ok=True)
                # Remove obsolete files as well, so --apply reproduces exactly.
                for name in files(vendor).keys() - files(pristine).keys():
                    (vendor / name).unlink()
            expected, actual = files(pristine), files(vendor)
            changed = [str(name) for name in sorted(expected.keys() | actual.keys())
                       if expected.get(name) != actual.get(name)]
            if changed:
                raise RuntimeError(f"{entry['name']}: vendor differs from pristine plus patch: {changed}")
            expected_metadata, actual_metadata = file_metadata(pristine), file_metadata(vendor)
            changed_metadata = [str(name) for name in sorted(expected_metadata.keys() | actual_metadata.keys())
                                if expected_metadata.get(name) != actual_metadata.get(name)]
            if changed_metadata:
                raise RuntimeError(f"{entry['name']}: vendor file type/executable mode differs: {changed_metadata}")
            print(f"{entry['name']} {entry['version']}: source digest and patched tree verified")


if __name__ == "__main__":
    main()
