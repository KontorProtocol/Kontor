#!/usr/bin/env python3
"""Build and execute the real retained-node integration checks."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import time

from build import ROOT, digest, write_json
from provenance import _request
from recipes import CONSENSUS_GRAPHS, EXECUTOR_LINK_SETS, executor_graphs
from semantic_baseline import verify as verify_semantics
from symbol_tool import TOOLCHAIN
from transition_evidence import verify_transition, verify_recovery, verify_authorization, verify_join


CASES = {"native-genesis", "genesis-resume", "read-only-views", "committee", "registration-observer-capability",
         "execution-definition-factory-mapping",
         "malformed-recognition", "lifecycle-rollback-replay", "opaque-session-rejection",
         "transaction-recognition", "publication", "fees-and-deposits", "deterministic-failures",
         "simulation-inspection", "transaction-rollback-replay", "pending-host-callback-cancellation",
         "host-callback-failure-panic", "held-cursor-cancellation", "node-wide-capacity-shutdown",
         "export-panic-classification", "required-storage-contract-before-construction",
         "atomic-migration-and-retry", "migration-input-snapshot-and-work",
         "production-migration-registry-isolation", "retained-canonical-history-adapters"}


CERTIFIED_CHECKS = {
    "engine_free_recovery", "interrupted_replay_matches_uninterrupted", "live_closure_driver",
    "automatic_finality_replay", "owned_replacement_rollback", "bounded_work_plan",
    "replay_plan_publication_atomic", "local_reorg_is_not_authority", "owned_batch_stages",
    "owned_block_stage", "closure_publication_atomic", "next_height_after_closure",
    "ack_after_durable_input", "interrupted_append_rolled_back", "finalization_without_volatile_cache",
    "original_and_one_augmentation", "reopen_verified",
}


def verify_certified_history(observations, link_set, root=ROOT):
    _request(dict(operation="certified", observations=observations, link_set=link_set,
                  root=str(root.absolute())), command="verify-node-evidence")


def verify_storage_contracts(observations, link_set=None):
    _request(dict(operation="storage", observations=observations, link_set=link_set),
             command="verify-node-evidence")


def verify_managed_startup(observations, link_set):
    _request(dict(operation="startup", observations=observations, link_set=link_set),
             command="verify-node-evidence")


def baseline_graphs(link_set):
    return _request(dict(operation="baseline_graphs", link_set=link_set),
                    command="verify-node-evidence")


def verify_executor_observations(observations, link_set):
    _request(dict(operation="executors", observations=observations, link_set=link_set),
             command="verify-node-evidence")


def execute_transition(executable, directory, root=ROOT):
    stdout = directory / 'node-transition.stdout.json'
    stderr = directory / 'node-transition.stderr.log'
    with stdout.open('w') as out, stderr.open('w') as err:
        result = subprocess.run([str(executable), 'qualify-protocol-transition', '--cluster'],
                                stdout=out, stderr=err, timeout=390)
    if result.returncode:
        raise RuntimeError(f'node transition failed ({result.returncode}): {stderr}')
    verify_transition(json.loads(stdout.read_text()), root)
    return {'stdout_sha256': digest(stdout), 'stderr_sha256': digest(stderr)}


def execute_join(executable, directory):
    stdout = directory / 'node-join.stdout.json'
    stderr = directory / 'node-join.stderr.log'
    with stdout.open('w') as out, stderr.open('w') as err:
        result = subprocess.run([str(executable), 'qualify-protocol-transition', '--join'],
                                stdout=out, stderr=err, timeout=360)
    if result.returncode:
        raise RuntimeError(f'node join failed ({result.returncode}): {stderr}')
    verify_join(json.loads(stdout.read_text()))
    return {'stdout_sha256': digest(stdout), 'stderr_sha256': digest(stderr)}


def execute_recovery(executable, directory):
    stdout = directory / 'node-recovery.stdout.json'
    stderr = directory / 'node-recovery.stderr.log'
    with stdout.open('w') as out, stderr.open('w') as err:
        result = subprocess.run([str(executable), 'qualify-protocol-transition', '--recovery'],
                                stdout=out, stderr=err, timeout=420)
    if result.returncode:
        raise RuntimeError(f'node recovery failed ({result.returncode}): {stderr}')
    verify_recovery(json.loads(stdout.read_text()))
    return {'stdout_sha256': digest(stdout), 'stderr_sha256': digest(stderr)}


def execute_authorization(executable, directory):
    stdout = directory / 'node-authorization.stdout.json'
    stderr = directory / 'node-authorization.stderr.log'
    with stdout.open('w') as out, stderr.open('w') as err:
        result = subprocess.run([str(executable), 'qualify-protocol-transition', '--authorized-replay'],
                                stdout=out, stderr=err, timeout=420)
    if result.returncode:
        raise RuntimeError(f'node authorization failed ({result.returncode}): {stderr}')
    verify_authorization(json.loads(stdout.read_text()))
    return {'stdout_sha256': digest(stdout), 'stderr_sha256': digest(stderr)}


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
    expected_consensus = list(CONSENSUS_GRAPHS) if link_set == 'managed-node' else []
    if [graph['graph'] for graph in report.get('consensus_graphs', [])] != expected_consensus:
        raise RuntimeError('node build does not contain the required consensus graphs')
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
    verify_executor_observations(observations, link_set)
    if observations.get('schema') != 1 or set(observations['cases']) != CASES or len(observations['cases']) != len(CASES):
        raise RuntimeError('node execution case set changed')
    verify_storage_contracts(observations, link_set)
    verify_certified_history(observations, link_set)
    verify_managed_startup(observations, link_set)
    semantic_baseline = verify_semantics(observations, ROOT, baseline_graphs(link_set))
    transition = execute_transition(executable, directory) if link_set == 'managed-node' else None
    recovery = execute_recovery(executable, directory) if link_set == 'managed-node' else None
    authorization = execute_authorization(executable, directory) if link_set == 'managed-node' else None
    join = execute_join(executable, directory) if link_set == 'managed-node' else None
    if digest(executable) != node['executable_sha256'] or digest(report_path) != report_hash:
        raise RuntimeError('node executable or build report changed during execution')
    evidence = {'schema': 1, 'target': report['target'], 'profile': report['profile'], 'link_set': link_set,
                'node_build_sha256': digest(report_path), 'executable_sha256': digest(executable),
                'stdout_sha256': digest(stdout), 'stderr_sha256': digest(stderr),
                'cases': observations['cases'], 'graphs': expected_graphs,
                'seconds': time.monotonic() - started, 'matching_observations': True,
                'semantic_baseline': semantic_baseline}
    if transition is not None:
        evidence['transition'] = transition
        evidence['recovery'] = recovery
        evidence['authorization'] = authorization
        evidence['join'] = join
    write_json(success, evidence)
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--profile', choices=('release', 'dev'), default='release')
    parser.add_argument('--offline', action='store_true')
    parser.add_argument('--link-set', choices=sorted(EXECUTOR_LINK_SETS), default='managed-node')
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
    command = [str(ROOT / 'tools/kontor'), 'protocol-bundles', '--build-node',
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
