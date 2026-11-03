#!/usr/bin/env python3
"""Build and execute the real retained-node integration checks."""

import argparse
from pathlib import Path
import subprocess

from build import ROOT
from provenance import _request
from recipes import EXECUTOR_LINK_SETS


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


def _execute_check(check, executable, directory, root=ROOT):
    return _request(dict(operation="check", root=str(root.absolute()), working_directory=str(Path.cwd()),
                         executable=str(executable.absolute()), directory=str(directory.absolute()),
                         check=check), command="run-node-qualification")


def execute_transition(executable, directory, root=ROOT):
    return _execute_check("transition", executable, directory, root)


def execute_recovery(executable, directory):
    return _execute_check("recovery", executable, directory)


def execute_authorization(executable, directory):
    return _execute_check("authorization", executable, directory)


def execute_join(executable, directory):
    return _execute_check("join", executable, directory)


def execute_node(report_path, link_set=None):
    try:
        return _request(dict(operation="node", root=str(ROOT), report=str(report_path.absolute()), working_directory=str(Path.cwd()),
                             link_set=link_set), command="run-node-qualification")
    except RuntimeError as error:
        if "historical semantic comparison differs" in str(error):
            raise ValueError(str(error)) from error
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--profile', choices=('release', 'dev'), default='release')
    parser.add_argument('--offline', action='store_true')
    parser.add_argument('--link-set', choices=sorted(EXECUTOR_LINK_SETS), default='managed-node')
    args = parser.parse_args()
    command = [str(ROOT / 'tools/kontor'), 'qualify-node', '--output', str(args.output.resolve()),
               '--profile', args.profile, '--link-set', args.link_set]
    if args.offline:
        command.append('--offline')
    subprocess.run(command, cwd=ROOT, check=True)


if __name__ == '__main__':
    main()
