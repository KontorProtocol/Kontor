#!/usr/bin/env python3
"""Preserve evidence from failed macOS CI tests, including absent crash reports."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time


REPORT_ROOTS = {
    "user": Path.home() / "Library/Logs/DiagnosticReports",
    "system": Path("/Library/Logs/DiagnosticReports"),
}


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def snapshot(roots):
    files = {}
    errors = []
    for label, root in roots.items():
        try:
            root.stat()
        except OSError as error:
            errors.append(f"{root}: {error}")
            continue
        for directory, _, names in os.walk(
            root, onerror=lambda error: errors.append(str(error)), followlinks=False
        ):
            for name in names:
                path = Path(directory) / name
                try:
                    if path.is_symlink() or not path.is_file():
                        continue
                    stat = path.stat()
                    key = str(Path(label) / path.relative_to(root))
                    files[key] = {"mtime_ns": stat.st_mtime_ns, "size": stat.st_size}
                except OSError as error:
                    errors.append(f"{path}: {error}")
    return {"files": files, "errors": errors}


def prepare(output, roots):
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "baseline.json", snapshot(roots))
    write_json(output / "run.json", {
        "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "commit": os.environ.get("GITHUB_SHA"),
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "report_roots": {label: str(root) for label, root in roots.items()},
    })


def collect_reports(output, roots, wait_seconds=30, interval=2):
    errors = set()
    try:
        baseline = json.loads((output / "baseline.json").read_text())["files"]
    except (OSError, ValueError, KeyError) as error:
        # A broken baseline must not cause historical runner reports to be uploaded.
        baseline = snapshot(roots)["files"]
        errors.add(f"Cannot read baseline; tracking reports from collection start: {error}")
    copied = {}
    deadline = time.monotonic() + wait_seconds
    while True:
        current = snapshot(roots)
        errors.update(current["errors"])
        for key, metadata in current["files"].items():
            if metadata == baseline.get(key) or metadata == copied.get(key):
                continue
            label, relative = key.split("/", 1)
            source = roots[label] / relative
            destination = output / "reports" / key
            try:
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
                copied[key] = metadata
            except OSError as error:
                errors.add(f"Cannot copy {source}: {error}")
        # Keep polling even after the first report: reporters can write asynchronously
        # and several test processes may crash before cargo exits.
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(interval, remaining))
    write_json(output / "reports.json", {
        "wait_seconds": wait_seconds,
        "copied": copied,
        "final_snapshot": current,
        "collection_errors": sorted(errors),
    })
    return len(copied)


def capture_command(path, command, timeout=30):
    with path.open("w") as log:
        log.write(f"Command: {command!r}\n")
        log.flush()
        try:
            result = subprocess.run(
                command, stdout=log, stderr=subprocess.STDOUT, timeout=timeout,
                check=False,
            )
            log.write(f"\nExit status: {result.returncode}\n")
        except (OSError, subprocess.TimeoutExpired) as error:
            log.write(f"\nCollection error: {error}\n")


def run_logged(output, command):
    output.parent.mkdir(parents=True, exist_ok=True)
    # A pipe can remain open in orphaned descendants after cargo exits. A regular
    # file lets us stop following output when cargo itself finishes.
    with output.open("wb") as log, output.open("rb") as reader:
        with subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT) as process:
            while process.poll() is None:
                data = reader.read(65536)
                if data:
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                else:
                    time.sleep(0.05)
            # Bound the final drain, even if surviving children keep writing.
            remaining = output.stat().st_size - reader.tell()
            while remaining > 0:
                data = reader.read(min(remaining, 65536))
                if not data:
                    break
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()
                remaining -= len(data)
            return process.returncode if process.returncode >= 0 else 128 - process.returncode


def collect(output, roots):
    output.mkdir(parents=True, exist_ok=True)
    count = collect_reports(output, roots)
    predicate = (
        'process == "ReportCrash" OR process == "diagnosticd" '
        'OR process BEGINSWITH "integration" OR process BEGINSWITH "kontor" '
        'OR process == "bitcoind" OR eventMessage CONTAINS "mach_msg"'
    )
    capture_command(output / "system.log", [
        "sudo", "-n", "/usr/bin/log", "show", "--last", "10m",
        "--style", "compact", "--info", "--debug", "--predicate", predicate,
    ])
    commands = {
        "os.txt": ["sw_vers"],
        "kernel.txt": ["uname", "-a"],
        "crash-reporter-settings.txt": ["defaults", "read", "com.apple.CrashReporter"],
        "core-settings.txt": ["sysctl", "kern.coredump", "kern.corefile"],
        "processes.txt": ["ps", "-axo", "pid,ppid,stat,comm"],
        "disabled-system-services.txt": ["launchctl", "print-disabled", "system"],
        "disabled-user-services.txt": ["launchctl", "print-disabled", f"gui/{os.getuid()}"],
    }
    for name, command in commands.items():
        capture_command(output / name, command, timeout=5)
    message = f"Captured {count} new or changed macOS diagnostic report(s)."
    if not count:
        message += " No crash report found; inspect reports.json and system.log for collection details."
        print(f"::warning::{message}")
    (output / "summary.txt").write_text(message + "\n")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as file:
            file.write(f"### macOS crash diagnostics\n\n{message}\n\n"
                       "Test output, report inventories, collection errors, and system diagnostics "
                       "are in the macos-crash-reports artifact for this attempt.\n")
    print(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "collect", "run"])
    parser.add_argument("output", type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.action == "run":
        if not args.command:
            parser.error("run requires a command")
        sys.exit(run_logged(args.output, args.command))
    elif args.action == "prepare":
        prepare(args.output, REPORT_ROOTS)
    else:
        collect(args.output, REPORT_ROOTS)


if __name__ == "__main__":
    main()
