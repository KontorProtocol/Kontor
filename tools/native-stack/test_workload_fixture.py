import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "workload_fixture", Path(__file__).with_name("workload_fixture.py")
)
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


class FixtureInputTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.bundle = self.root / "fixture"
        self.bundle.mkdir()
        self.manifest = self.bundle / "manifest.json"
        self.manifest.write_text('{"schema_version":1}')
        self.reader = fixture.FixtureReader(self.manifest)

    def reference(self, name, data):
        (self.bundle / name).write_bytes(data)
        return {"path": name, "sha256": hashlib.sha256(data).hexdigest()}

    def test_nested_duplicates_and_non_json_numbers_are_rejected(self):
        for document in (
            b'{"nested":{"gas":1,"gas":2}}',
            b'{"gas":NaN}',
            b'{"gas":Infinity}',
            b'{"gas":-Infinity}',
            b'{"gas":1e309}',
            b'{"gas":0.5}',
            '{"gas":1}'.encode("utf-16"),
            b'{"gas":1} trailing',
        ):
            with self.subTest(document=document), self.assertRaises(fixture.FixtureError):
                fixture.parse_document(document, "test")

    def test_file_reference_requires_exact_fields_and_digest(self):
        reference = self.reference("report.json", b'{"gas":7}')
        self.assertEqual(self.reader.read_document(reference, "report"), {"gas": 7})
        for bad in (
            {"path": reference["path"]},
            dict(reference, ignored=True),
            dict(reference, sha256="0" * 64),
            dict(reference, sha256=reference["sha256"].upper()),
        ):
            with self.subTest(reference=bad), self.assertRaises(fixture.FixtureError):
                self.reader.read_reference(bad, "report")
        (self.bundle / "report.json").write_bytes(b'{"gas":8}')
        with self.assertRaises(fixture.FixtureError):
            self.reader.read_reference(reference, "report")

    def test_paths_cannot_escape_fixture_directory(self):
        outside = self.root / "outside"
        outside.write_bytes(b"outside")
        (self.bundle / "link").symlink_to(outside)
        for name in ("../outside", str(outside), "link", "./manifest.json", "a//b", "a\\b", ""):
            with self.subTest(path=name), self.assertRaises(fixture.FixtureError):
                self.reader.read_reference({"path": name, "sha256": "0" * 64}, "input")

    def test_copy_checks_bytes_and_never_overwrites_an_existing_reset(self):
        data = b"sqlite fixture bytes\0" * 100000
        reference = self.reference("snapshot.db", data)
        first = self.root / "first.db"
        second = self.root / "second.db"
        self.reader.copy_verified(reference, first, "snapshot")
        self.reader.copy_verified(reference, second, "snapshot")
        self.assertEqual(first.read_bytes(), data)
        self.assertEqual(second.read_bytes(), data)
        first.write_bytes(b"trial changes")
        self.assertEqual(second.read_bytes(), data)
        self.assertEqual((self.bundle / "snapshot.db").read_bytes(), data)
        with self.assertRaises(FileExistsError):
            self.reader.copy_verified(reference, first, "snapshot")
        self.assertEqual(first.read_bytes(), b"trial changes")
        mismatch = self.root / "bad.db"
        with self.assertRaises(fixture.FixtureError):
            self.reader.copy_verified(dict(reference, sha256="0" * 64), mismatch, "snapshot")
        self.assertFalse(mismatch.exists())

    def test_integer_bounds_do_not_accept_boolean_or_float(self):
        self.assertEqual(fixture.unsigned((1 << 64) - 1, 64, "gas"), (1 << 64) - 1)
        for value in (True, False, -1, 1 << 64, 1.0, "1", None):
            with self.subTest(value=value), self.assertRaises(fixture.FixtureError):
                fixture.unsigned(value, 64, "gas")

    def test_manifest_identity_is_the_original_document_bytes(self):
        self.assertEqual(self.reader.manifest, {"schema_version": 1})
        self.assertEqual(
            self.reader.manifest_sha256,
            hashlib.sha256(self.manifest.read_bytes()).hexdigest(),
        )
        self.manifest.write_text(json.dumps({"schema_version": 2}))
        self.assertEqual(self.reader.manifest, {"schema_version": 1})


if __name__ == "__main__":
    unittest.main()
