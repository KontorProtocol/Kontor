#!/usr/bin/env python3
"""Build an exact-source native stack test artifact with pinned compiler settings."""

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True

from capture_resource_control import (ensure_no_cargo_config,
                                      fastnum_build_record, native_tool_records,
                                      selected_binary)
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


def pinned_environment(manifest, output_dir):
    policy = manifest["build_policy"]["compile_env"]
    cargo_home = Path(os.environ.get("CARGO_HOME") or Path.home() / ".cargo")
    rustup_home = Path(os.environ.get("RUSTUP_HOME") or Path.home() / ".rustup")
    if not cargo_home.is_absolute() or not rustup_home.is_absolute():
        raise ValueError("resource Cargo and Rustup homes must be absolute")
    cargo_home = cargo_home.resolve()
    rustup_home = rustup_home.resolve()
    builder_home = Path.home().resolve()
    target_dir = output_dir / "target"
    home_dir = output_dir / "home"
    tmp_dir = output_dir / "tmp"
    home_dir.mkdir(exist_ok=True)
    tmp_dir.mkdir(exist_ok=True)
    path = os.pathsep.join(dict.fromkeys((str(cargo_home / "bin"),
                                         str(builder_home / ".cargo/bin"),
                                         "/usr/bin", "/bin", "/usr/local/bin",
                                         "/opt/homebrew/bin")))
    environment = {"PATH": path, "HOME": str(home_dir), "TMPDIR": str(tmp_dir),
                   "CARGO_HOME": str(cargo_home), "RUSTUP_HOME": str(rustup_home),
                   "CARGO_INCREMENTAL": "0", "LC_ALL": "C", "LANG": "C",
                   "TZ": "UTC", "SOURCE_DATE_EPOCH": "0"}
    for name, value in policy.items():
        if value is None:
            environment.pop(name, None)
        else:
            environment[name] = value
    actual = {name: environment.get(name) for name in policy}
    if actual != policy:
        raise ValueError("resource compiler environment differs from manifest")
    environment["CARGO_TARGET_DIR"] = str(target_dir)
    tools = native_tool_records(environment)
    environment.update({"CC": tools["cc"]["selected_path"],
                        "CXX": tools["c++"]["selected_path"],
                        "AR": tools["ar"]["selected_path"],
                        "CMAKE_C_COMPILER": tools["cc"]["selected_path"],
                        "CMAKE_CXX_COMPILER": tools["c++"]["selected_path"],
                        "CFLAGS": "", "CXXFLAGS": "", "CPPFLAGS": "",
                        "LDFLAGS": "", "ARFLAGS": ""})
    if set(environment) != set(manifest["build_policy"]["native_environment_keys"]):
        raise ValueError("native build environment differs from pinned allowlist")
    return environment, actual, cargo_home, tools, builder_home


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
    environment, compile_env, cargo_home, native_tools, builder_home = pinned_environment(
        manifest, output_dir)
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
    if metadata.get("target_directory") != environment["CARGO_TARGET_DIR"]:
        raise ValueError("resource build Cargo target directory differs from fresh target")
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
    fastnum_source, fastnum_out_dir = fastnum_build_record(artifacts_path, metadata)
    fastnum_policy = manifest["build_policy"]["fastnum_generated"]
    source_archive = output_dir / "fastnum-build.rs"
    if sha256(fastnum_source) != manifest["build_policy"]["fastnum_build_script_sha256"]:
        raise ValueError("fastnum build script differs from pinned source")
    shutil.copyfile(fastnum_source, source_archive)
    fastnum_generated = {}
    for name, expected in fastnum_policy.items():
        source = fastnum_out_dir / name
        if source.read_text() != expected:
            raise ValueError(f"effective fastnum setting differs: {name}")
        archive = output_dir / f"fastnum-{name}"
        shutil.copyfile(source, archive)
        fastnum_generated[name] = {"path": archive.name, "sha256": sha256(archive)}
    if ensure_no_cargo_config(core, cargo_home) != config_candidates:
        raise ValueError("resource Cargo config search path changed during build")
    if native_tool_records(environment) != native_tools:
        raise ValueError("native build tool changed during build")
    if source_revision() != head or load_json_strict(MANIFEST) != build_manifest():
        raise ValueError("resource source changed during build")
    report = {
        "schema_version": 3,
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
        "builder_home": str(builder_home),
        "build_output_dir": str(output_dir),
        "build_environment": environment,
        "native_tools": native_tools,
        "fastnum_source_path": str(fastnum_source),
        "fastnum_out_dir": str(fastnum_out_dir),
        "fastnum_build_script": {"path": source_archive.name,
                                 "sha256": sha256(source_archive)},
        "fastnum_generated": fastnum_generated,
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
