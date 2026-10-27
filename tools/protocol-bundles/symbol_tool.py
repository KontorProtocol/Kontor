"""Inspect Rust objects with the LLVM reader shipped with the pinned compiler."""

from functools import lru_cache
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
