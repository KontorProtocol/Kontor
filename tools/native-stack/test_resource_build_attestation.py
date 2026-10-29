"""Reject source and compiler setting drift in resource build attestations."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from build_resource_test import pinned_environment
from capture_resource_control import validate_build_attestation
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
        for path, data in ((self.artifacts, b"artifact\n"),
                           (self.metadata, b"metadata\n"),
                           (self.build_log, b"compiler stderr\n"),
                           (self.binary, b"test executable\n")):
            path.write_bytes(data)
        self.attestation = self.root / "resource-build-attestation.json"
        self.manifest = build_manifest()
        self.source_sha = "a" * 40
        self.artifact = {"features": ["testing"], "profile": {
            "opt_level": "0", "debug_assertions": True, "overflow_checks": True}}
        self.report = {
            "schema_version": 1,
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

    def test_unsets_formatter_variables_for_build(self):
        with patch.dict(os.environ, {
            "RUST_FASTNUM_FMT_EXPONENTIAL_LOWER_THRESHOLD": "1",
            "RUST_FASTNUM_FMT_EXPONENTIAL_UPPER_THRESHOLD": "2",
            "RUST_FASTNUM_FMT_MAX_INTEGER_PADDING": "3",
            "RUSTC": "false",
            "RUSTFLAGS": "-C target-cpu=native",
        }):
            environment, actual = pinned_environment(self.manifest)
        for name in (
            "RUST_FASTNUM_FMT_EXPONENTIAL_LOWER_THRESHOLD",
            "RUST_FASTNUM_FMT_EXPONENTIAL_UPPER_THRESHOLD",
            "RUST_FASTNUM_FMT_MAX_INTEGER_PADDING",
            "RUSTC", "RUSTFLAGS",
        ):
            self.assertNotIn(name, environment)
            self.assertIsNone(actual[name])


if __name__ == "__main__":
    unittest.main()
