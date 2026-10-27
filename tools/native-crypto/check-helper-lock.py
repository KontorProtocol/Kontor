#!/usr/bin/env python3
"""Keep standalone helper tests on the native build dependency versions."""

from pathlib import Path
import tomllib


ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "core/vendor/kontor-native-build"


def read(path):
    return tomllib.loads(path.read_text())


def main():
    core = read(ROOT / "core/Cargo.lock")["package"]
    helper = read(HELPER / "Cargo.lock")["package"]
    core_cc = [p for p in core if p["name"] == "cc"]
    helper_cc = [p for p in helper if p["name"] == "cc"]
    assert len(core_cc) == len(helper_cc) == 1, "expected one cc version per graph"
    version = core_cc[0]["version"]
    assert helper_cc[0]["version"] == version, "helper and core cc versions differ"
    assert read(HELPER / "Cargo.toml")["dependencies"]["cc"] == f"={version}", (
        "helper must pin the core cc version exactly"
    )
    for package in helper:
        identity = {key: package.get(key) for key in ("name", "version", "source", "checksum")}
        assert any(all(p.get(k) == v for k, v in identity.items()) for p in core), (
            f"helper dependency absent from core lock: {identity}"
        )
    for name in ("blst", "ring", "secp256k1-sys"):
        packages = [p for p in core if p["name"] == name]
        assert len(packages) == 1 and "source" not in packages[0], f"{name} must be vendored"
        assert "kontor-native-build" in packages[0]["dependencies"], f"{name} lost helper"
    print(f"Helper lock matches core native build dependencies (cc {version})")


if __name__ == "__main__":
    main()
