"""Inspect Rust objects with the LLVM reader shipped with the pinned compiler."""

from functools import lru_cache
import json
from pathlib import Path
import subprocess

TOOLCHAIN = "1.99.1"


@lru_cache(maxsize=1)
def executable():
    rustc = Path(subprocess.check_output(
        ["rustup", "which", "--toolchain", TOOLCHAIN, "rustc"], text=True).strip())
    compiler = subprocess.check_output([str(rustc), "-Vv"], text=True)
    host = next(line[6:] for line in compiler.splitlines() if line.startswith("host: "))
    path = rustc.parent.parent / "lib/rustlib" / host / "bin/llvm-nm"
    if not path.is_file():
        raise RuntimeError(f"missing pinned llvm-nm; run rustup component add --toolchain {TOOLCHAIN} llvm-tools-preview")
    return path


def inspect(arguments):
    command = [str(executable()), *map(str, arguments)]
    result = subprocess.run(command, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(f"symbol inspection failed ({result.returncode}): {command}\n{result.stderr}")
    return result.stdout


def object_records(path):
    reader = executable().with_name("llvm-readobj")
    command = [str(reader), "--elf-output-style=JSON", "--sections", "--symbols", str(path)]
    result = subprocess.run(command, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(f"object inspection failed ({result.returncode}): {command}\n{result.stderr}")
    try:
        records = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"invalid object inspection output: {path}") from error
    if not isinstance(records, list):
        raise RuntimeError(f"invalid object inspection records: {path}")
    return records


def archive_member_bytes(path, record):
    label = record["FileSummary"]["File"]
    archive_prefix = f"{path}("
    if not label.startswith(archive_prefix) or not label.endswith(")"):
        raise RuntimeError(f"object is not an archive member: {label}")
    member = label[len(archive_prefix):-1]
    return archive_member(path, member)


def archive_members(path):
    command = [str(executable().with_name("llvm-ar")), "t", str(path)]
    result = subprocess.run(command, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(f"archive listing failed: {command}\n{result.stderr}")
    members = result.stdout.splitlines()
    if not members or len(members) != len(set(members)):
        raise RuntimeError(f"archive has missing or duplicate member names: {path}")
    return members


def archive_member(path, member):
    command = [str(executable().with_name("llvm-ar")), "p", str(path), member]
    result = subprocess.run(command, capture_output=True)
    if result.returncode:
        raise RuntimeError(f"archive member inspection failed: {command}\n{result.stderr.decode(errors='replace')}")
    return result.stdout


def section_bytes(path, record, section):
    label = record["FileSummary"]["File"]
    if label.startswith(f"{path}(") and label.endswith(")"):
        contents = archive_member_bytes(path, record)
        start = section["Offset"]
        end = start + section["Size"]
        if end > len(contents):
            raise RuntimeError(f"section extends beyond archive member: {label}")
        return contents[start:end]
    if label != str(path):
        raise RuntimeError(f"object reader changed input identity: {label}")
    with Path(path).open("rb") as source:
        source.seek(section["Offset"])
        contents = source.read(section["Size"])
    if len(contents) != section["Size"]:
        raise RuntimeError(f"section extends beyond object: {path}")
    return contents
