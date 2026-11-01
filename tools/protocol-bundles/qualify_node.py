#!/usr/bin/env python3
"""Build and execute the real retained-node integration checks."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from build import ROOT, digest, write_json
from recipes import EXECUTOR_GRAPHS
from symbol_tool import TOOLCHAIN


CASES = {"native-genesis", "genesis-resume", "read-only-views", "committee",
         "malformed-recognition", "lifecycle-rollback-replay", "opaque-session-rejection",
         "transaction-recognition", "publication", "fees-and-deposits", "deterministic-failures",
         "simulation-inspection", "transaction-rollback-replay"}

def execute_node(report_path):
    directory = report_path.parent
    success = directory / "node-execution.json"
    success.unlink(missing_ok=True)
    report_hash = digest(report_path)
    report = json.loads(report_path.read_text())
    node = report['node']
    expected_graphs = list(EXECUTOR_GRAPHS)
    if [graph['graph'] for graph in report['graphs']] != expected_graphs or not node['qualification_command']:
        raise RuntimeError('node build does not contain the required qualification graphs')
    executable = Path(node['installed']['path'])
    if digest(executable) != node['executable_sha256'] or node['installed']['sha256'] != node['executable_sha256']:
        raise RuntimeError('installed node differs from the audited executable')
    stdout = directory / 'node-execution.stdout.json'
    stderr = directory / 'node-execution.stderr.log'
    started = time.monotonic()
    with stdout.open('w') as out, stderr.open('w') as err:
        result = subprocess.run([str(executable), 'qualify-executors'], stdout=out, stderr=err, timeout=300)
    if result.returncode:
        raise RuntimeError(f'node execution failed ({result.returncode}): {stderr}')
    observations = json.loads(stdout.read_text())
    if [item['graph'] for item in observations['executors']] != expected_graphs:
        raise RuntimeError('node execution omitted a retained graph')
    first, second = observations['executors']
    if first['observations'] != second['observations']:
        raise RuntimeError('retained executor observations disagree')
    if observations.get('schema') != 1 or set(observations['cases']) != CASES or len(observations['cases']) != len(CASES):
        raise RuntimeError('node execution case set changed')
    if digest(executable) != node['executable_sha256'] or digest(report_path) != report_hash:
        raise RuntimeError('node executable or build report changed during execution')
    evidence = {'schema': 1, 'target': report['target'], 'profile': report['profile'],
                'node_build_sha256': digest(report_path), 'executable_sha256': digest(executable),
                'stdout_sha256': digest(stdout), 'stderr_sha256': digest(stderr),
                'cases': observations['cases'], 'graphs': expected_graphs,
                'seconds': time.monotonic() - started, 'matching_observations': True}
    write_json(success, evidence)
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--profile', choices=('release', 'dev'), default='release')
    parser.add_argument('--offline', action='store_true')
    args = parser.parse_args()
    output = args.output.resolve()
    env = dict(os.environ, RUSTUP_TOOLCHAIN=TOOLCHAIN)
    compiler = subprocess.check_output(['rustup', 'run', TOOLCHAIN, 'rustc', '-Vv'], env=env, text=True)
    target = next(line.removeprefix('host: ') for line in compiler.splitlines() if line.startswith('host: '))
    report = output / target / args.profile / 'executors/node-build.json'
    (report.parent / 'node-execution.json').unlink(missing_ok=True)
    command = [sys.executable, str(ROOT / 'tools/protocol-bundles/build.py'), '--build-node',
               '--node-qualification', '--install-node', str(output / 'kontor'), '--output', str(output),
               '--profile', args.profile, '--target', target]
    if args.offline:
        command.append('--offline')
    subprocess.run(command, cwd=ROOT, env=env, check=True)
    print(json.dumps(execute_node(report)), flush=True)


if __name__ == '__main__':
    main()
