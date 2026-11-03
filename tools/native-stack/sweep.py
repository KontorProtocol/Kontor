"""Compatibility calls for the Rust stack transcript validator."""

from functools import lru_cache
import json
from pathlib import Path
import subprocess


REPORT_PREFIX = "KONTOR_STACK_REPORT:"
SUMMARY_PREFIX = "KONTOR_STACK_SWEEP_SUMMARY:"
CACHE_MODE = "warm_compiled_cache"
IDENTITY_FIELDS = {"role", "sample_index", "sample_id"}
SWEEP_FIELDS = IDENTITY_FIELDS | {"cache_mode", "fixture_contracts", "reset", "call_hook_installed"}


@lru_cache(maxsize=1)
def _tool():
    root = Path(__file__).resolve().parents[2]
    with subprocess.Popen([str(root / "tools/kontor"), "tool-path"], cwd=root,
                          stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True) as child:
        stdout, stderr = child.communicate()
        if child.returncode:
            raise ValueError(f"Rust stack validator bootstrap failed: {stderr}")
    return stdout.strip()


def _run(request):
    with subprocess.Popen([_tool(), "verify-stack-evidence"], stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True) as child:
        stdout, stderr = child.communicate(json.dumps(request))
        if child.returncode:
            raise ValueError(stderr.strip())
    return json.loads(stdout)


def parse_transcript(raw, kind, role):
    return tuple(_run({"operation": "parse_sweep", "raw": raw, "kind": kind, "role": role}))


def validate_pair(worker, worker_summary, control, control_summary):
    _run({"operation": "sweep_pair", "worker": worker, "worker_summary": worker_summary,
          "control": control, "control_summary": control_summary})
