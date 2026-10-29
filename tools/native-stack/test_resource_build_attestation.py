"""Reject source and compiler setting drift in resource build attestations."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from build_resource_test import pinned_environment
from capture_resource_control import (ensure_no_cargo_config,
                                      validate_build_attestation)
from resource_evidence import sha256
from resource_manifest import MANIFEST, ROOT, build_manifest


class ResourceBuildAttestationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.artifacts = self.root / "cargo-artifacts.jsonl"
        self.metadata = self.root / "cargo-metadata.json"
        self.build_log = self.root / "cargo-build.log"
        self.binary = self.root / "indexer-test"
        fastnum_source = self.root / "registry/fastnum-0.7.5/build.rs"
        fastnum_source.parent.mkdir(parents=True)
        fastnum_out = self.root / "target/debug/build/fastnum-test/out"
        fastnum_out.mkdir(parents=True)
        records = [
            {"reason": "build-script-executed", "package_id": "fastnum-package",
             "out_dir": str(fastnum_out)},
            {"reason": "compiler-artifact", "package_id": "fastnum-package",
             "target": {"kind": ["lib"]}},
        ]
        metadata = {"target_directory": str(self.root / "target"),
                    "packages": [{"name": "fastnum", "version": "0.7.5",
                                  "id": "fastnum-package",
                                  "manifest_path": str(fastnum_source.parent / "Cargo.toml")}]}
        for path, data in ((self.artifacts, ("\n".join(json.dumps(row) for row in records)
                                             + "\n").encode()),
                           (self.metadata, (json.dumps(metadata) + "\n").encode()),
                           (self.build_log, b"compiler stderr\n"),
                           (self.binary, b"test executable\n")):
            path.write_bytes(data)
        self.attestation = self.root / "resource-build-attestation.json"
        self.cargo_home = self.root / "cargo-home"
        self.cargo_home.mkdir()
        self.manifest = json.loads(json.dumps(build_manifest()))
        with patch.dict(os.environ, {"CARGO_HOME": str(self.cargo_home)}):
            build_environment, _, _, native_tools = pinned_environment(
                self.manifest, self.root)
        fastnum_source.write_text("fn main() {}\n")
        self.manifest["build_policy"]["fastnum_build_script_sha256"] = sha256(fastnum_source)
        source_archive = self.root / "fastnum-build.rs"
        source_archive.write_bytes(fastnum_source.read_bytes())
        generated = {}
        for name, expected in self.manifest["build_policy"]["fastnum_generated"].items():
            archive = self.root / f"fastnum-{name}"
            archive.write_text(expected)
            generated[name] = {"path": archive.name, "sha256": sha256(archive)}
        self.source_sha = "a" * 40
        self.artifact = {"features": ["testing"], "profile": {
            "opt_level": "0", "debug_assertions": True, "overflow_checks": True}}
        self.report = {
            "schema_version": 3,
            "source_sha": self.source_sha,
            "manifest_sha256": sha256(MANIFEST),
            "lockfile_sha256": self.manifest["artifacts"]["core_lockfile"]["sha256"],
            "profile": "dev",
            "rustc_verbose": "rustc 1.99.1 (test)\nhost: aarch64-unknown-linux-gnu\n",
            "compile_env": self.manifest["build_policy"]["compile_env"],
            "cargo_command": ["cargo", "test", "-p", "indexer", "--lib",
                              "--locked", "-j2", "--no-run", "--message-format=json"],
            "cargo_cwd": str(ROOT / "core"),
            "cargo_artifacts_sha256": sha256(self.artifacts),
            "cargo_metadata_sha256": sha256(self.metadata),
            "cargo_build_log_sha256": sha256(self.build_log),
            "binary_path": str(self.binary),
            "binary_sha256": sha256(self.binary),
            "indexer_artifact_features": ["testing"],
            "cargo_home": str(self.cargo_home),
            "cargo_config_candidates": ensure_no_cargo_config(ROOT / "core",
                                                                self.cargo_home),
            "build_output_dir": str(self.root),
            "build_environment": build_environment,
            "native_tools": native_tools,
            "fastnum_source_path": str(fastnum_source),
            "fastnum_out_dir": str(fastnum_out),
            "fastnum_build_script": {"path": source_archive.name,
                                     "sha256": sha256(source_archive)},
            "fastnum_generated": generated,
        }

    def validate(self):
        self.attestation.write_text(json.dumps(self.report, sort_keys=True) + "\n")
        return validate_build_attestation(
            self.attestation, self.artifacts, self.metadata, self.source_sha,
            self.manifest, self.binary, self.artifact)

    def test_accepts_exact_build_identity(self):
        report, build_log = self.validate()
        self.assertEqual(report, self.report)
        self.assertEqual(build_log, self.build_log)

    def test_rejects_formatter_and_feature_drift(self):
        baseline = json.loads(json.dumps(self.report))
        for mutation in ("fastnum", "command", "features", "toolchain", "profile"):
            with self.subTest(mutation=mutation):
                self.report = json.loads(json.dumps(baseline))
                if mutation == "fastnum":
                    self.report["compile_env"][
                        "RUST_FASTNUM_FMT_EXPONENTIAL_LOWER_THRESHOLD"] = "1"
                elif mutation == "command":
                    self.report["cargo_command"] = self.report["cargo_command"] + [
                        "--features", "testing"]
                elif mutation == "features":
                    self.report["indexer_artifact_features"] = []
                elif mutation == "profile":
                    self.report["profile"] = "release"
                else:
                    self.report["rustc_verbose"] = "rustc 1.98.0 (test)\nhost: aarch64-unknown-linux-gnu\n"
                with self.assertRaises(ValueError):
                    self.validate()

    def test_rejects_changed_build_log(self):
        self.validate()
        self.build_log.write_bytes(b"changed compiler stderr\n")
        with self.assertRaises(ValueError):
            self.validate()

    def test_rejects_changed_generated_formatter_constant(self):
        self.validate()
        (self.root / "fastnum-exponential_format_threshold.rs").write_text(
            "const FMT_MAX_INTEGER_PADDING: usize = 1;")
        with self.assertRaises(ValueError):
            self.validate()

    def test_rejects_native_compiler_or_flag_drift(self):
        baseline = json.loads(json.dumps(self.report))
        for mutation in ("compiler", "flags", "tool_hash", "target"):
            with self.subTest(mutation=mutation):
                self.report = json.loads(json.dumps(baseline))
                if mutation == "compiler":
                    self.report["build_environment"]["CC"] = "/tmp/other-cc"
                elif mutation == "flags":
                    self.report["build_environment"]["CFLAGS"] = "-DSQLITE_MAX_COLUMN=1"
                elif mutation == "tool_hash":
                    self.report["native_tools"]["cc"]["sha256"] = "0" * 64
                else:
                    self.report["build_environment"]["CARGO_TARGET_DIR"] = "/tmp/old-target"
                with self.assertRaises(ValueError):
                    self.validate()

    def test_rejects_cargo_config_injected_formatter_or_flags(self):
        core = self.root / "project/core"
        core.mkdir(parents=True)
        config = core / ".cargo/config.toml"
        config.parent.mkdir()
        for content in (
            '[env]\nRUST_FASTNUM_FMT_EXPONENTIAL_LOWER_THRESHOLD = { value = "1", force = true }\n',
            '[target.aarch64-unknown-linux-gnu]\nrustflags = ["-C", "target-cpu=native"]\n',
            '[profile.release]\nopt-level = 1\n',
        ):
            with self.subTest(content=content):
                config.write_text(content)
                with self.assertRaisesRegex(ValueError, "unreviewed Cargo config source"):
                    ensure_no_cargo_config(core, self.cargo_home)
        config.unlink()
        global_config = self.cargo_home / "config"
        global_config.write_text('[env]\nRUST_FASTNUM_FMT_MAX_INTEGER_PADDING = "4"\n')
        with self.assertRaisesRegex(ValueError, "unreviewed Cargo config source"):
            ensure_no_cargo_config(core, self.cargo_home)

    def test_rejects_config_appearing_after_build(self):
        self.validate()
        config = self.cargo_home / "config.toml"
        config.write_text('[env]\nRUST_FASTNUM_FMT_MAX_INTEGER_PADDING = "4"\n')
        with self.assertRaisesRegex(ValueError, "unreviewed Cargo config source"):
            self.validate()

    def test_unsets_formatter_variables_for_build(self):
        with patch.dict(os.environ, {
            "RUST_FASTNUM_FMT_EXPONENTIAL_LOWER_THRESHOLD": "1",
            "RUST_FASTNUM_FMT_EXPONENTIAL_UPPER_THRESHOLD": "2",
            "RUST_FASTNUM_FMT_MAX_INTEGER_PADDING": "3",
            "RUSTC": "false",
            "RUSTFLAGS": "-C target-cpu=native",
            "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS": "-C target-cpu=native",
            "CARGO_PROFILE_TEST_OPT_LEVEL": "3",
            "RUSTC_BOOTSTRAP": "1",
            "CC": "/tmp/other-cc", "CFLAGS": "-DSQLITE_MAX_COLUMN=1",
            "LIBSQL_DEV": "1", "SQLITE_MAX_VARIABLE_NUMBER": "1",
            "PKG_CONFIG_PATH": "/tmp/untrusted", "CPATH": "/tmp/untrusted",
            "AWS_LC_SYS_CFLAGS": "-DOTHER", "ZSTD_SYS_USE_PKG_CONFIG": "1",
        }):
            environment, actual, cargo_home, _ = pinned_environment(
                self.manifest, self.root)
        for name in (
            "RUST_FASTNUM_FMT_EXPONENTIAL_LOWER_THRESHOLD",
            "RUST_FASTNUM_FMT_EXPONENTIAL_UPPER_THRESHOLD",
            "RUST_FASTNUM_FMT_MAX_INTEGER_PADDING",
            "RUSTC", "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS",
            "CARGO_PROFILE_TEST_OPT_LEVEL", "RUSTC_BOOTSTRAP",
        ):
            self.assertNotIn(name, environment)
            if name in actual:
                self.assertIsNone(actual[name])
        self.assertEqual(environment["RUSTFLAGS"], "")
        self.assertEqual(actual["RUSTFLAGS"], "")
        self.assertEqual(environment["RUSTC_WRAPPER"], "")
        self.assertTrue(cargo_home.is_absolute())
        self.assertEqual(environment["CFLAGS"], "")
        self.assertNotEqual(environment["CC"], "/tmp/other-cc")
        for name in ("LIBSQL_DEV", "SQLITE_MAX_VARIABLE_NUMBER", "PKG_CONFIG_PATH",
                     "CPATH", "AWS_LC_SYS_CFLAGS", "ZSTD_SYS_USE_PKG_CONFIG"):
            self.assertNotIn(name, environment)


if __name__ == "__main__":
    unittest.main()
