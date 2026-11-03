#!/usr/bin/env python3
"""Compatibility entry point for Rust node archive verification."""

import argparse
from pathlib import Path
import subprocess

from build import ROOT
from provenance import _request
from recipes import EXECUTOR_LINK_SETS

TARGETS = {'x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu', 'aarch64-apple-darwin'}
OWNERSHIP = {'common-reference-ownership.json', 'node-input-ownership.json', 'input-ownership.json',
             'input-local-ownership.json', 'final-ownership.json'}


class VerificationError(ValueError, RuntimeError):
    """Preserve both historical validation exception families for remaining callers."""


def _verify(request):
    try:
        return _request(request, command='verify-node-archive')
    except RuntimeError as error:
        raise VerificationError(str(error)) from error


def sources(directory, report, root, kind, *, tool_root=None):
    return _verify(dict(operation='sources', directory=str(directory.absolute()), report=report,
                        root=str(root.absolute()), kind=kind,
                        tool_root=str(tool_root.absolute()) if tool_root is not None else None))


def compare(directory, root, profiles, upstream_status, link_set=None):
    return _verify(dict(operation='compare', directory=str(directory.absolute()), root=str(root.absolute()),
                        profiles=profiles, upstream_status=upstream_status, link_set=link_set))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--profiles', choices=('release', 'full'), required=True)
    parser.add_argument('--upstream-status', required=True)
    parser.add_argument('--link-set', choices=sorted(EXECUTOR_LINK_SETS), default='managed-node')
    args = parser.parse_args()
    subprocess.run([str(ROOT / 'tools/kontor'), 'compare-node', '--directory', str(args.directory.absolute()),
                    '--output', str(args.output.absolute()), '--profiles', args.profiles,
                    '--upstream-status', args.upstream_status, '--link-set', args.link_set], cwd=ROOT, check=True)


if __name__ == '__main__':
    main()
