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
from recipes import EXECUTOR_LINK_SETS, executor_graphs
from semantic_baseline import verify as verify_semantics
from symbol_tool import TOOLCHAIN


CASES = {"native-genesis", "genesis-resume", "read-only-views", "committee", "registration-observer-capability",
         "execution-definition-factory-mapping",
         "malformed-recognition", "lifecycle-rollback-replay", "opaque-session-rejection",
         "transaction-recognition", "publication", "fees-and-deposits", "deterministic-failures",
         "simulation-inspection", "transaction-rollback-replay", "pending-host-callback-cancellation",
         "host-callback-failure-panic", "held-cursor-cancellation", "node-wide-capacity-shutdown",
         "export-panic-classification", "required-storage-contract-before-construction",
         "atomic-migration-and-retry", "migration-input-snapshot-and-work",
         "production-migration-registry-isolation", "reactor-canonical-history"}


def verify_storage_contracts(observations, link_set=None):
    expected = [f'{graph}:{mutation}' for graph in executor_graphs(link_set)
                for mutation in ('missing', 'unknown', 'changed', 'multiple')]
    if observations.get('storage_contracts') != {'rejected_before_construction': expected}:
        raise RuntimeError('storage contract construction checks missing or incomplete')

def execute_node(report_path, link_set=None):
    directory = report_path.parent
    success = directory / "node-execution.json"
    success.unlink(missing_ok=True)
    report_hash = digest(report_path)
    report = json.loads(report_path.read_text())
    node = report['node']
    if report.get('link_set') != link_set:
        raise RuntimeError('node build uses another executor link set')
    expected_graphs = list(executor_graphs(link_set))
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
    verify_storage_contracts(observations, link_set)
    semantic_baseline = verify_semantics(observations, ROOT, expected_graphs)
    if digest(executable) != node['executable_sha256'] or digest(report_path) != report_hash:
        raise RuntimeError('node executable or build report changed during execution')
    evidence = {'schema': 1, 'target': report['target'], 'profile': report['profile'], 'link_set': link_set,
                'node_build_sha256': digest(report_path), 'executable_sha256': digest(executable),
                'stdout_sha256': digest(stdout), 'stderr_sha256': digest(stderr),
                'cases': observations['cases'], 'graphs': expected_graphs,
                'seconds': time.monotonic() - started, 'matching_observations': True,
                'semantic_baseline': semantic_baseline}
    write_json(success, evidence)
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--profile', choices=('release', 'dev'), default='release')
    parser.add_argument('--offline', action='store_true')
    parser.add_argument('--link-set', choices=sorted(EXECUTOR_LINK_SETS), default='k4-node')
    args = parser.parse_args()
    output = args.output.resolve()
    env = dict(os.environ, RUSTUP_TOOLCHAIN=TOOLCHAIN)
    compiler = subprocess.check_output(['rustup', 'run', TOOLCHAIN, 'rustc', '-Vv'], env=env, text=True)
    target = next(line.removeprefix('host: ') for line in compiler.splitlines() if line.startswith('host: '))
    report_directory = output / target / args.profile / 'executors'
    if args.link_set:
        report_directory /= args.link_set
    report = report_directory / 'node-build.json'
    (report.parent / 'node-execution.json').unlink(missing_ok=True)
    command = [sys.executable, str(ROOT / 'tools/protocol-bundles/build.py'), '--build-node',
               '--node-qualification', '--install-node', str(output / 'kontor'), '--output', str(output),
               '--profile', args.profile, '--target', target]
    if args.offline:
        command.append('--offline')
    if args.link_set:
        command.extend(['--link-set', args.link_set])
    subprocess.run(command, cwd=ROOT, env=env, check=True)
    print(json.dumps(execute_node(report, args.link_set)), flush=True)


if __name__ == '__main__':
    main()
