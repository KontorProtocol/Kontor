"""Shared strict input, thread-capacity and guard checks for S2 case captures."""

import hashlib
import json
import subprocess
from decimal import Decimal, InvalidOperation
from functools import lru_cache
from pathlib import Path

from resource_manifest import ROOT, THREAD_CATEGORIES


def canonical_decimal_amount(value, label):
    require(isinstance(value, str) and 0 < len(value) <= 128,
            f"{label}: invalid balance amount")
    try:
        amount = Decimal(value)
    except InvalidOperation as error:
        raise ValueError(f"{label}: invalid balance amount") from error
    require(amount.is_finite() and abs(amount.as_tuple().exponent) <= 128,
            f"{label}: invalid balance amount")
    if amount.is_zero():
        return "0"
    encoded = format(amount, "f")
    return encoded.rstrip("0").rstrip(".") if "." in encoded else encoded


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def no_nonfinite_constants(value):
    raise ValueError(f"non-finite JSON constant: {value}")


def load_json_strict(path):
    return json.loads(path.read_text(), object_pairs_hook=no_duplicate_keys,
                      parse_constant=no_nonfinite_constants)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_evidence(directory, entry):
    require(set(entry) == {"path", "sha256"}, "raw log identity is incomplete")
    relative = Path(entry["path"])
    require(not relative.is_absolute() and ".." not in relative.parts, "raw log escapes evidence directory")
    path = directory / relative
    require(path.resolve().is_relative_to(directory.resolve()),
            "raw log resolves outside evidence directory")
    require(path.is_file(), f"missing raw log {relative}")
    require(sha256(path) == entry["sha256"], f"raw log hash mismatch: {relative}")


@lru_cache(maxsize=1)
def _rust_tool():
    with subprocess.Popen(
        [str(ROOT / "tools/kontor"), "tool-path"], cwd=ROOT,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    ) as child:
        stdout, stderr = child.communicate()
        if child.returncode:
            raise ValueError(f"Rust resource validator bootstrap failed: {stderr}")
    return stdout.strip()


def _rust_check(request):
    with subprocess.Popen(
        [_rust_tool(), "verify-stack-evidence"], cwd=ROOT,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    ) as child:
        stdout, stderr = child.communicate(json.dumps(request, allow_nan=False))
        if child.returncode:
            raise ValueError(f"Rust resource evidence failed: {stderr}")
    return json.loads(stdout)


def thread_capacities(runtime, mode, page_size, os_name, process_id):
    _rust_check({"operation": "resource_threads", "runtime": runtime,
                 "mode": mode, "page_size": page_size,
                 "os_name": os_name, "process_id": process_id})
    # Existing callers receive references to their observations, not JSON copies.
    return {category: [thread for thread in runtime["thread_observations"]
                       if thread["thread_category"] == category]
            for category in THREAD_CATEGORIES}


def check_guard_control(report, manifest, directory):
    _rust_check({"operation": "resource_guard", "report": report,
                 "manifest": manifest, "directory": str(directory.resolve())})
