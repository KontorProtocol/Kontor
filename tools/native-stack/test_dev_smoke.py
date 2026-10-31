import json
from pathlib import Path
import tempfile
import unittest

import compare
import dev_smoke


def fixture(root, artifact, cell):
    directory = root / artifact
    directory.mkdir()
    binary = "/target/debug/deps/indexer-example"
    features = {"production": sorted(compare.PRODUCTION_FEATURES), "qualification": sorted(compare.QUALIFICATION_FEATURES)}
    for graph, log in compare.FEATURE_LOGS.items():
        (directory / log).write_text(",".join(features[graph]) + "\n")
    cargo = [
        {"reason": "compiler-artifact", "target": {"name": "indexer", "kind": ["lib"]},
         "profile": {"test": True, "debug_assertions": True}, "executable": binary},
        {"reason": "compiler-artifact", "target": {"name": "wasmtime", "kind": ["lib"]},
         "package_id": f"git+https://github.com/wilfreddenton/wasmtime?rev={compare.FORK_REVISION}#wasmtime@51.0.0-kontor.2",
         "features": features["qualification"]},
        {"reason": "build-finished", "success": True},
    ]
    (directory / "cargo.json").write_text("".join(json.dumps(entry) + "\n" for entry in cargo))
    tests = {}
    for index, name in enumerate(dev_smoke.TESTS):
        tests[name] = f"test-{index}.log"
        (directory / tests[name]).write_text(f"test {name} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 100 filtered out; finished in 0.1s\n")
    report = {
        "schema_version": 1, "cell": cell[0], "source_sha": "a" * 40,
        "lockfile_sha256": "b" * 64, "wasmtime_revision": compare.FORK_REVISION,
        "binary": binary, "binary_sha256": "c" * 64, "cargo_log": "cargo.json",
        "rustc_version_verbose": f"rustc 1.99.1\nhost: {cell[1]}\n",
        "wasmtime_features": features, "feature_logs": compare.FEATURE_LOGS, "tests": tests,
        "log_sha256": {p.name: dev_smoke.sha256_file(p) for p in directory.iterdir()},
    }
    (directory / "smoke.json").write_text(json.dumps(report))
    return directory, report


class SmokeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for artifact, cell in dev_smoke.CELLS.items():
            fixture(self.root, artifact, cell)

    def validate(self):
        return dev_smoke.validate_set(self.root, "a" * 40, "b" * 64)

    def test_complete_smoke_set(self):
        self.assertEqual(len(self.validate()), 3)

    def test_missing_cell_and_test_are_rejected(self):
        directory = self.root / "native-smoke-ubuntu-24.04"
        directory.rename(self.root / "unexpected-cell")
        with self.assertRaises(ValueError):
            self.validate()
        (self.root / "unexpected-cell").rename(directory)
        report = json.loads((directory / "smoke.json").read_text())
        report["tests"].pop(dev_smoke.TESTS[0])
        (directory / "smoke.json").write_text(json.dumps(report))
        with self.assertRaises(ValueError):
            self.validate()

    def test_stale_source_lock_and_log_tampering_are_rejected(self):
        for source, lock in (("d" * 40, "b" * 64), ("a" * 40, "d" * 64)):
            with self.assertRaises(ValueError):
                dev_smoke.validate_set(self.root, source, lock)
        path = self.root / "native-smoke-ubuntu-24.04" / "test-0.log"
        path.write_text(path.read_text() + "tampered\n")
        with self.assertRaises(ValueError):
            self.validate()

    def test_zero_ignored_wrong_failed_and_duplicate_tests_are_rejected(self):
        name = dev_smoke.TESTS[0]
        valid = f"test {name} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n"
        for raw in ("", valid.replace("1 passed", "0 passed"), valid.replace("0 ignored", "1 ignored"),
                    valid.replace(name, "different_test"), valid.replace("0 failed", "1 failed"), valid + valid):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                dev_smoke.validate_test(raw, name)

    def test_wrong_profile_compiler_and_build_failure_are_rejected(self):
        directory = self.root / "native-smoke-ubuntu-24.04"
        path = directory / "smoke.json"
        original = path.read_text()
        for key, value in (("binary", "/target/release/deps/indexer-example"),
                           ("rustc_version_verbose", "rustc 1.99.1\nhost: aarch64-apple-darwin\n"),
                           ("binary_sha256", "invalid")):
            report = json.loads(original)
            report[key] = value
            path.write_text(json.dumps(report))
            with self.assertRaises(ValueError):
                self.validate()
        path.write_text(original)
        cargo = directory / "cargo.json"
        original_cargo = cargo.read_text()
        cargo.write_text(original_cargo.replace('"debug_assertions": true', '"debug_assertions": false'))
        with self.assertRaises(ValueError):
            self.validate()
        cargo.write_text(original_cargo)
        cargo.write_text(cargo.read_text().replace('"success": true', '"success": false'))
        with self.assertRaises(ValueError):
            self.validate()


if __name__ == "__main__":
    unittest.main()
