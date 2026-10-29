#!/usr/bin/env python3
"""Build an exact-source native stack test artifact with pinned compiler settings."""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True

from capture_resource_control import ensure_no_cargo_config, selected_binary
from resource_evidence import load_json_strict, sha256
from resource_manifest import MANIFEST, ROOT, build_manifest


def source_revision():
    head = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    dirty = subprocess.run(
        ["git", "-C", str(ROOT), "status", "--porcelain"],
        check=True, capture_output=True, text=True,
    ).stdout
    if dirty:
        raise ValueError("resource build requires a clean source checkout")
    return head


def pinned_environment(manifest):
    policy = manifest["build_policy"]["compile_env"]
    environment = os.environ.copy()
    for name in tuple(environment):
        if ((name.startswith("CARGO_") and name != "CARGO_HOME")
                or (name.startswith("RUST") and name != "RUSTUP_HOME")):
            environment.pop(name)
    cargo_home = Path(environment.get("CARGO_HOME") or Path.home() / ".cargo")
    if not cargo_home.is_absolute():
        raise ValueError("resource Cargo home must be absolute")
    environment["CARGO_HOME"] = str(cargo_home.resolve())
    for name, value in policy.items():
        if value is None:
            environment.pop(name, None)
        else:
            environment[name] = value
    actual = {name: environment.get(name) for name in policy}
    if actual != policy:
        raise ValueError("resource compiler environment differs from manifest")
    return environment, actual, cargo_home.resolve()


def build(profile, output_dir):
    if profile not in {"dev", "release"}:
        raise ValueError("unsupported native stack build profile")
    if output_dir.is_relative_to(ROOT):
        raise ValueError("resource build output must be outside the source checkout")
    manifest = build_manifest()
    if load_json_strict(MANIFEST) != manifest:
        raise ValueError("resource manifest differs from pinned source")
    head = source_revision()
    if output_dir.exists() and any(output_dir.iterdir()):
        raise ValueError("resource build output directory is not empty")
    output_dir.mkdir(parents=True, exist_ok=True)
    environment, compile_env, cargo_home = pinned_environment(manifest)
    core = ROOT / "core"
    config_candidates = ensure_no_cargo_config(core, cargo_home)
    rustc = subprocess.run(
        ["rustc", "-vV"], cwd=core, env=environment,
        check=True, capture_output=True, text=True,
    ).stdout
    if not rustc.startswith(f"rustc {manifest['build_policy']['rustc_release']} "):
        raise ValueError("resource build uses a different Rust toolchain")
    metadata_path = output_dir / "cargo-metadata.json"
    with metadata_path.open("xb") as output:
        subprocess.run(
            ["cargo", "metadata", "--format-version", "1", "--locked"],
            cwd=core, env=environment, check=True, stdout=output,
        )
    metadata = load_json_strict(metadata_path)
    if metadata.get("workspace_root") != str(core):
        raise ValueError("resource build Cargo workspace differs from source checkout")
    command = ["cargo", "test", "-p", "indexer", "--lib", "--locked",
               "-j2", "--no-run", "--message-format=json"]
    if profile == "release":
        command.append("--release")
    artifacts_path = output_dir / "cargo-artifacts.jsonl"
    stderr_path = output_dir / "cargo-build.log"
    with artifacts_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        subprocess.run(command, cwd=core, env=environment, check=True,
                       stdout=stdout, stderr=stderr)
    binary, artifact = selected_binary(artifacts_path, metadata)
    if ensure_no_cargo_config(core, cargo_home) != config_candidates:
        raise ValueError("resource Cargo config search path changed during build")
    if source_revision() != head or load_json_strict(MANIFEST) != build_manifest():
        raise ValueError("resource source changed during build")
    report = {
        "schema_version": 1,
        "source_sha": head,
        "manifest_sha256": sha256(MANIFEST),
        "lockfile_sha256": sha256(core / "Cargo.lock"),
        "profile": profile,
        "rustc_verbose": rustc,
        "compile_env": compile_env,
        "cargo_command": command,
        "cargo_cwd": str(core),
        "cargo_artifacts_sha256": sha256(artifacts_path),
        "cargo_metadata_sha256": sha256(metadata_path),
        "cargo_build_log_sha256": sha256(stderr_path),
        "binary_path": str(binary),
        "binary_sha256": sha256(binary),
        "indexer_artifact_features": artifact["features"],
        "cargo_home": str(cargo_home),
        "cargo_config_candidates": config_candidates,
    }
    report_path = output_dir / "resource-build-attestation.json"
    with report_path.open("x") as output:
        json.dump(report, output, sort_keys=True, indent=2)
        output.write("\n")
    return report_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("dev", "release"), required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    path = build(args.profile, args.output_dir.resolve())
    print(json.dumps({"attestation_path": str(path), "sha256": sha256(path)},
                     sort_keys=True))


if __name__ == "__main__":
    main()
