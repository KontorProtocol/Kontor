"""Compatibility calls into Rust object tooling until the builder migration."""

from pathlib import Path

from provenance import _request

TOOLCHAIN = "1.99.1"


def _object(operation, **values):
    return _request(dict(operation=operation, working_directory=str(Path.cwd()), **values),
                    command="inspect-object")


def executable():
    return Path(_object("executable"))


def inspect(arguments):
    return _object("inspect", arguments=list(map(str, arguments)))


def object_records(path):
    return _object("object_records", path=str(path))


def archive_members(path):
    return _object("archive_members", path=str(path))


def archive_member(path, member):
    return bytes.fromhex(_object("archive_member", path=str(path), member=member))


def section_bytes(path, record, section):
    return bytes.fromhex(_object("section_bytes", path=str(path), record=record, section=section))


def compiler_debug_metadata(path, linked=False):
    return _object("compiler_debug_metadata", path=str(path), linked=linked)
