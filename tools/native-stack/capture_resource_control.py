#!/usr/bin/env python3
"""Capture the native stack guard control and pinned fiber source evidence."""

import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True

from capture_fiber_source import capture as capture_fiber_source
from resource_evidence import (check_guard_control, load_json_strict,
                               no_duplicate_keys, no_nonfinite_constants, sha256)
from resource_manifest import MANIFEST, ROOT, build_manifest


def ensure_no_cargo_config(core, cargo_home):
    candidates = []
    directory = core.resolve()
    while True:
        candidates.extend((directory / ".cargo/config.toml",
                           directory / ".cargo/config"))
        if directory == directory.parent:
            break
        directory = directory.parent
    home = cargo_home.resolve()
    candidates.extend((home / "config.toml", home / "config"))
    unique = list(dict.fromkeys(candidates))
    present = [path for path in unique if path.exists() or path.is_symlink()]
    if present:
        raise ValueError("unreviewed Cargo config source: " +
                         ", ".join(str(path) for path in present))
    return [str(path) for path in unique]


def native_tool_records(environment):
    records = {}
    for name in ("cargo", "rustc", "cc", "c++", "ar", "cmake", "make", "perl",
                 "pkg-config", "python3"):
        selected = shutil.which(name, path=environment["PATH"])
        if selected is None:
            if name in ("cargo", "rustc", "cc", "c++", "ar"):
                raise ValueError(f"required native build tool is missing: {name}")
            continue
        path = Path(selected)
        resolved = path.resolve(strict=True)
        records[name] = {"selected_path": str(path), "resolved_path": str(resolved),
                         "sha256": sha256(resolved)}
    return records


def validate_native_tool_records(records, search_path):
    permitted = {"cargo", "rustc", "cc", "c++", "ar", "cmake", "make",
                 "perl", "pkg-config", "python3"}
    required = {"cargo", "rustc", "cc", "c++", "ar"}
    if (not isinstance(records, dict) or not required <= set(records)
            or not set(records) <= permitted):
        raise ValueError("native tool record set differs from policy")
    search_dirs = set(search_path.split(os.pathsep))
    for name, record in records.items():
        if (not isinstance(record, dict)
                or set(record) != {"selected_path", "resolved_path", "sha256"}
                or any(not isinstance(value, str) for value in record.values())):
            raise ValueError("native tool record has an invalid schema")
        selected = Path(record["selected_path"])
        resolved = Path(record["resolved_path"])
        if (not selected.is_absolute() or selected.name != name
                or str(selected.parent) not in search_dirs
                or not resolved.is_absolute()
                or not re.fullmatch(r"[0-9a-f]{64}", record["sha256"])):
            raise ValueError("native tool record differs from search path")


def selected_binary(artifacts_path, metadata):
    lines = artifacts_path.read_text().splitlines()
    if not lines or any(not line.strip() for line in lines):
        raise ValueError("Cargo artifact stream is incomplete")
    records = [json.loads(line, object_pairs_hook=no_duplicate_keys,
                          parse_constant=no_nonfinite_constants) for line in lines]
    if not all(isinstance(record, dict) for record in records):
        raise ValueError("Cargo artifact stream contains a non-object message")
    indexers = [package for package in metadata["packages"]
                if package.get("name") == "indexer"]
    if len(indexers) != 1:
        raise ValueError("Cargo metadata lacks one indexer package")
    selected = [record for record in records
                if record.get("reason") == "compiler-artifact"
                and record.get("package_id") == indexers[0]["id"]
                and isinstance(record.get("target"), dict)
                and record.get("target", {}).get("name") == "indexer"
                and record.get("target", {}).get("kind") == ["lib"]
                and isinstance(record.get("profile"), dict)
                and record.get("profile", {}).get("test") is True
                and record.get("executable")]
    finished = [record for record in records if record.get("reason") == "build-finished"]
    if (len(selected) != 1 or len(finished) != 1
            or finished[0].get("success") is not True
            or records[-1] != finished[0]):
        raise ValueError("Cargo output lacks one successful indexer test artifact")
    binary = Path(selected[0]["executable"])
    if not binary.is_absolute() or not binary.is_file() or not binary.name.startswith("indexer-"):
        raise ValueError("selected Cargo test artifact is missing")
    return binary.resolve(), selected[0]


def fastnum_build_record(artifacts_path, metadata):
    packages = [package for package in metadata["packages"]
                if package.get("name") == "fastnum" and package.get("version") == "0.7.5"]
    if len(packages) != 1:
        raise ValueError("Cargo metadata lacks one pinned fastnum package")
    package = packages[0]
    records = [json.loads(line, object_pairs_hook=no_duplicate_keys,
                          parse_constant=no_nonfinite_constants)
               for line in artifacts_path.read_text().splitlines()]
    builds = [record for record in records
              if record.get("reason") == "build-script-executed"
              and record.get("package_id") == package["id"]]
    libraries = [record for record in records
                 if record.get("reason") == "compiler-artifact"
                 and record.get("package_id") == package["id"]
                 and record.get("target", {}).get("kind") == ["lib"]]
    if len(builds) != 1 or len(libraries) != 1:
        raise ValueError("Cargo lacks one fastnum build script and library artifact")
    source = Path(package["manifest_path"]).parent / "build.rs"
    out_dir = Path(builds[0]["out_dir"])
    if (not source.is_absolute() or not out_dir.is_absolute()
            or not out_dir.is_relative_to(Path(metadata["target_directory"]))):
        raise ValueError("fastnum build source or output path is outside Cargo closure")
    return source, out_dir


def validate_native_environment(report, manifest, metadata, historical=False):
    environment = report["build_environment"]
    output_dir = Path(report["build_output_dir"])
    builder_home = Path(report["builder_home"])
    workspace = Path(metadata["workspace_root"])
    if (not output_dir.is_absolute() or output_dir.is_relative_to(workspace)
            or not builder_home.is_absolute() or not workspace.is_absolute()
            or not isinstance(environment, dict)
            or set(environment) != set(manifest["build_policy"]["native_environment_keys"])
            or any(not isinstance(value, str) for value in environment.values())):
        raise ValueError("native build environment has an invalid allowlist")
    cargo_home = Path(report["cargo_home"])
    rustup_home = Path(environment["RUSTUP_HOME"])
    if not rustup_home.is_absolute():
        raise ValueError("native Rustup home is not absolute")
    expected_path = os.pathsep.join(dict.fromkeys((str(cargo_home / "bin"),
                                                   str(builder_home / ".cargo/bin"),
                                                   "/usr/bin", "/bin",
                                                   "/usr/local/bin",
                                                   "/opt/homebrew/bin")))
    expected = {"PATH": expected_path, "HOME": str(output_dir / "home"),
                "TMPDIR": str(output_dir / "tmp"),
                "CARGO_HOME": str(cargo_home),
                "CARGO_TARGET_DIR": str(output_dir / "target"),
                "CARGO_INCREMENTAL": "0", "LC_ALL": "C", "LANG": "C",
                "TZ": "UTC", "SOURCE_DATE_EPOCH": "0",
                "CFLAGS": "", "CXXFLAGS": "", "CPPFLAGS": "",
                "LDFLAGS": "", "ARFLAGS": ""}
    expected.update({name: value for name, value in
                     manifest["build_policy"]["compile_env"].items()
                     if value is not None})
    if any(environment.get(name) != value for name, value in expected.items()):
        raise ValueError("native build environment differs from pinned settings")
    native_tools = report["native_tools"]
    validate_native_tool_records(native_tools, environment["PATH"])
    if not historical and (builder_home != Path.home().resolve()
                           or native_tools != native_tool_records(environment)):
        raise ValueError("live native build tool identity differs from attestation")
    if (environment["CC"] != native_tools["cc"]["selected_path"]
            or environment["CXX"] != native_tools["c++"]["selected_path"]
            or environment["AR"] != native_tools["ar"]["selected_path"]
            or environment["CMAKE_C_COMPILER"] != environment["CC"]
            or environment["CMAKE_CXX_COMPILER"] != environment["CXX"]
            or metadata.get("target_directory") != environment["CARGO_TARGET_DIR"]):
        raise ValueError("native compiler or fresh Cargo target differs from policy")


def validate_build_attestation(path, artifacts_path, metadata_path, source_sha,
                               manifest, binary, artifact,
                               manifest_sha256=None, core_root=None,
                               binary_sha256=None):
    report = load_json_strict(path)
    expected_keys = {
        "schema_version", "source_sha", "manifest_sha256", "lockfile_sha256",
        "profile", "rustc_verbose", "compile_env", "cargo_command",
        "cargo_cwd", "cargo_artifacts_sha256", "cargo_metadata_sha256",
        "cargo_build_log_sha256", "binary_path", "binary_sha256",
        "indexer_artifact_features", "cargo_home", "cargo_config_candidates",
    }
    generated_policy = manifest["build_policy"].get("fastnum_generated")
    native_policy = manifest["build_policy"].get("native_environment_keys")
    if generated_policy is not None:
        expected_keys.update({"fastnum_source_path", "fastnum_out_dir",
                              "fastnum_build_script", "fastnum_generated"})
    if native_policy is not None:
        expected_keys.update({"builder_home", "build_output_dir",
                              "build_environment", "native_tools"})
    if not isinstance(report, dict) or set(report) != expected_keys:
        raise ValueError("resource build attestation has an invalid schema")
    profile = report["profile"]
    command = ["cargo", "test", "-p", "indexer", "--lib", "--locked",
               "-j2", "--no-run", "--message-format=json"]
    if profile == "release":
        command.append("--release")
    if profile not in {"dev", "release"} or report["cargo_command"] != command:
        raise ValueError("resource build command or profile differs from policy")
    cargo_profile = artifact["profile"]
    expected_profile = (("0", True, True) if profile == "dev"
                        else ("3", False, False))
    if (cargo_profile.get("opt_level"), cargo_profile.get("debug_assertions"),
            cargo_profile.get("overflow_checks")) != expected_profile:
        raise ValueError("resource Cargo artifact profile differs from build command")
    expected_manifest_sha256 = manifest_sha256 or sha256(MANIFEST)
    expected_core = core_root or ROOT / "core"
    expected_binary_sha256 = binary_sha256 or sha256(binary)
    if native_policy is not None:
        target_dir = Path(report["build_output_dir"]) / "target"
        profile_dir = "release" if profile == "release" else "debug"
        if not Path(report["binary_path"]).is_relative_to(
                target_dir / profile_dir / "deps"):
            raise ValueError("resource test executable is outside fresh target")
    cargo_home = Path(report["cargo_home"])
    if not cargo_home.is_absolute():
        raise ValueError("resource Cargo home is not absolute")
    if core_root is None:
        candidates = ensure_no_cargo_config(expected_core, cargo_home)
        if report["cargo_config_candidates"] != candidates:
            raise ValueError("resource Cargo config search path changed")
    elif (not isinstance(report["cargo_config_candidates"], list)
          or not report["cargo_config_candidates"]
          or any(not Path(candidate).is_absolute()
                 for candidate in report["cargo_config_candidates"])):
        raise ValueError("historical Cargo config search paths are incomplete")
    expected_schema = (3 if native_policy is not None else
                       2 if generated_policy is not None else 1)
    if (report["schema_version"] != expected_schema
            or report["source_sha"] != source_sha
            or report["manifest_sha256"] != expected_manifest_sha256
            or report["lockfile_sha256"] != manifest["artifacts"]["core_lockfile"]["sha256"]
            or report["compile_env"] != manifest["build_policy"]["compile_env"]
            or report["cargo_cwd"] != str(expected_core)
            or report["cargo_artifacts_sha256"] != sha256(artifacts_path)
            or report["cargo_metadata_sha256"] != sha256(metadata_path)
            or report["binary_path"] != str(binary)
            or report["binary_sha256"] != expected_binary_sha256
            or report["indexer_artifact_features"] != artifact["features"]
            or artifact["features"] != manifest["build_policy"]["resolved_indexer_test_features"]):
        raise ValueError("resource build attestation differs from source or Cargo artifact")
    build_log = path.parent / "cargo-build.log"
    if not build_log.is_file() or report["cargo_build_log_sha256"] != sha256(build_log):
        raise ValueError("resource build stderr log differs from attestation")
    rustc = report["rustc_verbose"]
    if (not isinstance(rustc, str)
            or not rustc.startswith(f"rustc {manifest['build_policy']['rustc_release']} ")
            or not any(line.startswith("host: ") for line in rustc.splitlines())):
        raise ValueError("resource Rust compiler identity differs from policy")
    metadata = load_json_strict(metadata_path)
    if native_policy is not None:
        validate_native_environment(report, manifest, metadata,
                                    historical=core_root is not None)
    if generated_policy is not None:
        source, out_dir = fastnum_build_record(
            artifacts_path, metadata)
        if (report["fastnum_source_path"] != str(source)
                or report["fastnum_out_dir"] != str(out_dir)
                or set(report["fastnum_generated"]) != set(generated_policy)):
            raise ValueError("fastnum Cargo output paths differ from attestation")
        source_entry = report["fastnum_build_script"]
        entries = [source_entry, *report["fastnum_generated"].values()]
        if (source_entry != {"path": "fastnum-build.rs",
                             "sha256": manifest["build_policy"]["fastnum_build_script_sha256"]}
                or len({entry["path"] for entry in entries}) != len(entries)):
            raise ValueError("fastnum source archive entry differs from policy")
        for name, expected in generated_policy.items():
            entry = report["fastnum_generated"][name]
            if entry["path"] != f"fastnum-{name}":
                raise ValueError("fastnum generated archive path differs")
            archived = path.parent / entry["path"]
            if (not archived.is_file() or sha256(archived) != entry["sha256"]
                    or archived.read_text() != expected):
                raise ValueError("fastnum generated compiler setting differs")
        source_archive = path.parent / source_entry["path"]
        if not source_archive.is_file() or sha256(source_archive) != source_entry["sha256"]:
            raise ValueError("fastnum build script archive differs")
    return report, build_log


def run_bounded_process(command, timeout_seconds, env=None):
    started = time.time_ns()
    child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             start_new_session=True, env=env)
    timed_out = False
    try:
        output, _ = child.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            output, _ = child.communicate(timeout=5)
        except subprocess.TimeoutExpired as error:
            # A descendant can escape the process group while retaining stdout.
            output = error.output or b""
            child.stdout.close()
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
    return child, started, time.time_ns(), output, timed_out


def capture(artifacts_path, metadata_path, build_attestation_path, source_sha,
            evidence_dir, timeout_seconds):
    if sys.platform not in ("linux", "darwin"):
        raise ValueError("guard control capture is not implemented on this platform")
    os_name = "macos" if sys.platform == "darwin" else "linux"
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise ValueError("source revision is not a Git SHA-1")
    manifest = build_manifest()
    if load_json_strict(MANIFEST) != manifest:
        raise ValueError("resource manifest differs from pinned source")
    manifest_sha256 = sha256(MANIFEST)
    head = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    if head != source_sha:
        raise ValueError("requested source revision differs from checkout HEAD")
    dirty = subprocess.run(
        ["git", "-C", str(ROOT), "status", "--porcelain"],
        check=True, capture_output=True, text=True,
    ).stdout
    if dirty:
        raise ValueError("source checkout is not clean")
    metadata = load_json_strict(metadata_path)
    if metadata.get("workspace_root") != str(ROOT / "core"):
        raise ValueError("Cargo metadata workspace differs from source checkout")
    binary, artifact = selected_binary(artifacts_path, metadata)
    attestation, build_log = validate_build_attestation(
        build_attestation_path, artifacts_path, metadata_path, source_sha,
        manifest, binary, artifact)
    fastnum_source, fastnum_out_dir = fastnum_build_record(artifacts_path, metadata)
    if sha256(fastnum_source) != attestation["fastnum_build_script"]["sha256"]:
        raise ValueError("fastnum build script changed after attested build")
    for name, entry in attestation["fastnum_generated"].items():
        if sha256(fastnum_out_dir / name) != entry["sha256"]:
            raise ValueError("fastnum generated setting changed after attested build")
    binary_sha256 = sha256(binary)
    artifacts_sha256 = sha256(artifacts_path)
    metadata_sha256 = sha256(metadata_path)
    attestation_sha256 = sha256(build_attestation_path)
    build_log_sha256 = sha256(build_log)
    if evidence_dir.exists() and any(evidence_dir.iterdir()):
        raise ValueError("capture output directory is not empty")
    evidence_dir.mkdir(parents=True, exist_ok=True)
    fastnum_files = {"build_script": attestation["fastnum_build_script"],
                     **attestation["fastnum_generated"]}
    inputs = [(artifacts_path, "cargo-artifacts.jsonl"),
              (metadata_path, "cargo-metadata.json"),
              (build_attestation_path, "resource-build-attestation.json"),
              (build_log, "cargo-build.log")]
    inputs.extend((build_attestation_path.parent / entry["path"], entry["path"])
                  for entry in fastnum_files.values())
    for source, name in inputs:
        with (evidence_dir / name).open("xb") as destination, source.open("rb") as original:
            shutil.copyfileobj(original, destination)
    if (sha256(evidence_dir / "cargo-artifacts.jsonl") != artifacts_sha256
            or sha256(evidence_dir / "cargo-metadata.json") != metadata_sha256
            or sha256(evidence_dir / "resource-build-attestation.json") != attestation_sha256
            or sha256(evidence_dir / "cargo-build.log") != build_log_sha256):
        raise ValueError("Cargo build input changed during evidence archive")
    for entry in fastnum_files.values():
        if sha256(evidence_dir / entry["path"]) != entry["sha256"]:
            raise ValueError("fastnum compiler setting changed during evidence archive")
    raw_path = evidence_dir / "guard-control.log"
    fragment_path = evidence_dir / "resource-control-capture.json"
    failure_path = evidence_dir / "resource-control-failure.json"
    test_name = (manifest["guard_control_runner"]["macos_test_name"]
                 if os_name == "macos" else manifest["guard_control_runner"]["test_name"])
    command = [str(binary), "--exact", test_name,
               "--ignored", "--nocapture"]
    child, started, ended, output, timed_out = run_bounded_process(command, timeout_seconds)
    with raw_path.open("xb") as raw:
        raw.write(output)
    page_size = os.sysconf("SC_PAGE_SIZE")
    guard_control = {
        "process": {
            "pid": child.pid, "command": command,
            "started_unix_ns": started, "ended_unix_ns": ended,
            "exit_code": child.returncode if child.returncode >= 0 else None,
            "signal": -child.returncode if child.returncode < 0 else None,
            "timed_out": timed_out,
            "complete": not timed_out and child.returncode == 0,
            "test_harness_passed": not timed_out and child.returncode == 0,
        },
        "raw_log": {"path": raw_path.name, "sha256": sha256(raw_path)},
    }
    report_view = {
        "host": {"os": os_name}, "binary_path": str(binary),
        "binary_sha256": binary_sha256, "source_sha": source_sha,
        "configurations": {
            mode: {"engine": {"page_size_bytes": page_size},
                   "process_log": {"path": f"{mode}-workload.jsonl"}}
            for mode in ("reduced", "production")
        },
        "guard_control": guard_control,
    }
    try:
        if sha256(binary) != binary_sha256:
            raise ValueError("selected Cargo test artifact changed during capture")
        if load_json_strict(MANIFEST) != build_manifest() or sha256(MANIFEST) != manifest_sha256:
            raise ValueError("resource source or manifest changed during capture")
        final_head = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        final_dirty = subprocess.run(
            ["git", "-C", str(ROOT), "status", "--porcelain"],
            check=True, capture_output=True, text=True,
        ).stdout
        if final_head != source_sha or final_dirty:
            raise ValueError("source checkout changed during capture")
        check_guard_control(report_view, manifest, evidence_dir)
        sources = capture_fiber_source(evidence_dir / "cargo-metadata.json", evidence_dir)
    except Exception as error:
        with failure_path.open("x") as destination:
            json.dump({"error": str(error), "guard_control": guard_control},
                      destination, indent=2, sort_keys=True)
            destination.write("\n")
        raise
    fragment = {
        "manifest_sha256": manifest_sha256,
        "source_sha": source_sha,
        "binary_path": str(binary),
        "binary_sha256": binary_sha256,
        "cargo_artifact": artifact,
        "cargo_artifacts": {"path": "cargo-artifacts.jsonl",
                            "sha256": artifacts_sha256},
        "cargo_metadata": {"path": "cargo-metadata.json",
                           "sha256": metadata_sha256},
        "build_attestation": {"path": "resource-build-attestation.json",
                              "sha256": attestation_sha256},
        "build_log": {"path": "cargo-build.log",
                      "sha256": build_log_sha256},
        "fastnum_files": fastnum_files,
        "guard_control": guard_control,
        "wasmtime_source_files": sources,
    }
    with fragment_path.open("x") as destination:
        json.dump(fragment, destination, indent=2, sort_keys=True)
        destination.write("\n")
    return fragment_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo-artifacts", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--build-attestation", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=90)
    args = parser.parse_args()
    if args.timeout_seconds <= 0 or args.timeout_seconds > 600:
        parser.error("timeout must be between 1 and 600 seconds")
    path = capture(args.cargo_artifacts, args.metadata, args.build_attestation,
                   args.source_sha, args.evidence_dir, args.timeout_seconds)
    print(json.dumps({"capture_path": str(path), "sha256": sha256(path)}, sort_keys=True))


if __name__ == "__main__":
    main()
