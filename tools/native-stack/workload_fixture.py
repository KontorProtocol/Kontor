"""Strict input loading for the S2 workload correctness harness.

These helpers establish document and file identity. They do not establish
manifest semantics, runtime compatibility, or qualification success.
"""

import hashlib
import json
import re
from pathlib import Path, PurePosixPath


class FixtureError(ValueError):
    pass


def exact_fields(value, fields, where):
    if not isinstance(value, dict):
        raise FixtureError(f"{where}: expected an object")
    missing = set(fields) - value.keys()
    extra = value.keys() - set(fields)
    if missing or extra:
        raise FixtureError(
            f"{where}: missing fields {sorted(missing)}, extra fields {sorted(extra)}"
        )


def unsigned(value, bits, where):
    # bool is an int subclass in Python, but is not a JSON integer quantity.
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise FixtureError(f"{where}: expected u{bits}")
    return value


def hex_string(value, byte_count, where):
    if not isinstance(value, str) or re.fullmatch(
        rf"[0-9a-f]{{{byte_count * 2}}}", value
    ) is None:
        raise FixtureError(f"{where}: expected {byte_count} bytes of lowercase hex")
    return value


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise FixtureError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value):
    raise FixtureError(f"non-JSON numeric constant: {value}")


def _reject_float(value):
    raise FixtureError(f"floating-point quantities are not permitted: {value}")


def parse_document(data, where):
    try:
        # Decode explicitly: fixture bytes are UTF-8, not whichever UTF-16/32
        # encoding json.loads can infer from a byte sequence.
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_float=_reject_float,
        )
    except (UnicodeError, ValueError, RecursionError) as error:
        raise FixtureError(f"{where}: {error}") from error


class FixtureReader:
    def __init__(self, manifest_path):
        self.manifest_path = Path(manifest_path).resolve(strict=True)
        self.root = self.manifest_path.parent
        self.manifest_bytes = self.manifest_path.read_bytes()
        self.manifest_sha256 = hashlib.sha256(self.manifest_bytes).hexdigest()
        self.manifest = parse_document(self.manifest_bytes, self.manifest_path.name)

    def _reference(self, reference, where):
        exact_fields(reference, {"path", "sha256"}, where)
        expected = hex_string(reference["sha256"], 32, f"{where}.sha256")
        name = reference["path"]
        if not isinstance(name, str) or not name or "\\" in name or "\0" in name:
            raise FixtureError(f"{where}.path: expected a relative POSIX file path")
        path = PurePosixPath(name)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in name.split("/")):
            raise FixtureError(f"{where}.path: path must be canonical and relative")
        try:
            resolved = (self.root / name).resolve(strict=True)
            resolved.relative_to(self.root)
        except (OSError, ValueError, RuntimeError) as error:
            raise FixtureError(f"{where}.path: missing file or fixture-directory escape") from error
        if not resolved.is_file():
            raise FixtureError(f"{where}.path: expected a regular file")
        return resolved, expected

    def read_reference(self, reference, where):
        path, expected = self._reference(reference, where)
        try:
            data = path.read_bytes()
        except OSError as error:
            raise FixtureError(f"{where}: cannot read {reference['path']}") from error
        if hashlib.sha256(data).hexdigest() != expected:
            raise FixtureError(f"{where}: SHA-256 mismatch for {reference['path']}")
        return data

    def read_document(self, reference, where):
        # Parse the same bytes that were hashed; do not reopen a changed file.
        return parse_document(self.read_reference(reference, where), where)

    def verify_reference(self, reference, where):
        path, expected = self._reference(reference, where)
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != expected:
            raise FixtureError(f"{where}: SHA-256 mismatch for {reference['path']}")

    def copy_verified(self, reference, destination, where):
        """Copy large snapshots while hashing the actual bytes being copied."""
        source, expected = self._reference(reference, where)
        destination = Path(destination)
        digest = hashlib.sha256()
        created = False
        try:
            with source.open("rb") as reader, destination.open("xb") as writer:
                created = True
                for chunk in iter(lambda: reader.read(1024 * 1024), b""):
                    digest.update(chunk)
                    writer.write(chunk)
            if digest.hexdigest() != expected:
                raise FixtureError(f"{where}: SHA-256 mismatch for {reference['path']}")
        except BaseException:
            # A partial or mismatched copy must never become a replay snapshot.
            # Do not delete an existing destination that we refused to overwrite.
            if created:
                destination.unlink(missing_ok=True)
            raise
