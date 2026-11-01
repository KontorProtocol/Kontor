#!/usr/bin/env python3
"""Verify explicit platform coverage and compare actual linked-node execution."""

import argparse
import json
from pathlib import Path

from build import ROOT, digest, write_json
from provenance import fingerprint, package_sources, repository_sources
from qualify_node import CASES, verify_storage_contracts
from recipes import EXECUTOR_LINK_SETS, executor_graphs, graph_root, identity
from semantic_baseline import verify as verify_semantics
from symbol_tool import TOOLCHAIN
from type_boundary import verify_report as verify_interface_report

TARGETS = {'x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu', 'aarch64-apple-darwin'}
OWNERSHIP = {'common-reference-ownership.json', 'node-input-ownership.json', 'input-ownership.json',
             'input-local-ownership.json', 'final-ownership.json'}


def read(path):
    return json.loads(path.read_text())


def require(condition, message):
    if not condition:
        raise ValueError(message)


def file_hash(path, expected):
    require(digest(path) == expected, f'evidence hash mismatch: {path}')


def sources(directory, report, root, kind, *, tool_root=None):
    data = read(directory / 'source-inputs.json')
    require(fingerprint(data) == report['source_inputs_sha256'], f'{kind} source inventory hash mismatch')
    # These Python files inspect evidence; neither the compiler nor the runtime
    # invokes them. A comparator fix must not force unchanged executors to rebuild.
    def build_inputs(items):
        return {name: value for name, value in items.items()
                if not (name.startswith('tools/protocol-bundles/')
                        and (Path(name).name.startswith('test_') or Path(name).name == 'compare_node.py'))}
    require(build_inputs(data['qualification_sources']) == build_inputs(repository_sources(root, kind)),
            f'{kind} source inventory differs from checked-out qualification inputs')
    if tool_root is not None and tool_root != root:
        expected_tools = package_sources(tool_root / 'tools/protocol-bundles', root=tool_root)
        def tool_inputs(items):
            return {name: value for name, value in items.items()
                    if not Path(name).name.startswith('test_') and Path(name).name != 'compare_node.py'}
        require('build_tools' in data and tool_inputs(data['build_tools']) == tool_inputs(expected_tools),
                'executor current build-tool inventory differs')
    local = [package for package in data['packages'] if package['package'].startswith('path+file://<repository>/')]
    require(local, f'{kind} repository package inventory missing')
    for package in local:
        relative = package['package'].removeprefix('path+file://<repository>/').split('#', 1)[0]
        directory = root / relative
        require(directory.resolve().is_relative_to(root.resolve()), 'repository package path escapes checkout')
        # Docker deliberately excludes documentation and Git ignore files.
        def compiled_files(items):
            return {name: value for name, value in items.items()
                    if Path(name).suffix != '.md' and Path(name).name != '.gitignore'}
        require(compiled_files(package['files']) == compiled_files(package_sources(directory, root=root.resolve())),
                f'{kind} local package source differs: {relative}')
    inherited = data['inherited_manifests_and_configuration']
    graph_directory = 'node' if kind == 'node' else report['identity']['directory']
    manifest = f"protocol-bundles/{graph_directory}/Cargo.toml"
    manifests = [Path(name) for name in inherited if name.endswith('/' + manifest)]
    require(len(manifests) == 1, 'repository graph manifest missing or ambiguous')
    require(inherited[str(manifests[0])] == digest(root / manifest), 'repository graph manifest changed')
    # Wasmtime also has crates/core/Cargo.toml. Anchor the inherited workspace
    # to this graph's recorded checkout, which can differ between CI platforms.
    workspace = manifests[0].parents[2] / 'core/Cargo.toml'
    require(inherited.get(str(workspace)) == digest(root / 'core/Cargo.toml'), 'inherited core workspace changed')
    recorded_root = manifests[0].parents[2]
    recorded = {str(Path(name).relative_to(recorded_root)): value
                for name, value in inherited.items() if Path(name).is_relative_to(recorded_root)}
    for relative, expected in recorded.items():
        file_hash(root / relative, expected)
    # Also reject newly added configuration that the old build never saw.
    directories = {Path(manifest).parent}
    directories.update(Path(package['package'].removeprefix('path+file://<repository>/').split('#', 1)[0])
                       for package in local)
    ancestors = {parent for directory in directories for parent in (directory, *directory.parents)}
    for parent in ancestors:
        for name in ('Cargo.toml', '.cargo/config', '.cargo/config.toml'):
            path = parent / name
            if (root / path).is_file():
                require(recorded.get(str(path)) == digest(root / path), f'inherited repository input changed: {path}')


def load_cell(path, root, link_set=None):
    directory = path.parent
    execution = read(path)
    require(execution['schema'] == 1 and execution['matching_observations'] is True, 'invalid execution result')
    build_path = directory / 'node-build.json'
    file_hash(build_path, execution['node_build_sha256'])
    build = read(build_path)
    require(build.get('link_set') == execution.get('link_set') == link_set, 'executor link set mismatch')
    recipes = executor_graphs(link_set)
    cell = (build['target'], build['profile'])
    require(cell == (execution['target'], execution['profile']), 'execution/build cell mismatch')
    node = build['node']
    require(node['qualification_command'] is True, 'node lacks qualification command')
    require(execution['executable_sha256'] == node['executable_sha256'] == node['installed']['sha256'],
            'execution/installed binary mismatch')
    stdout = directory / 'node-execution.stdout.json'
    file_hash(stdout, execution['stdout_sha256'])
    file_hash(directory / 'node-execution.stderr.log', execution['stderr_sha256'])
    observations = read(stdout)
    require(observations['schema'] == 1, 'unknown observation schema')
    require(set(observations['cases']) == CASES and len(observations['cases']) == len(CASES), 'case set changed')
    require(observations['cases'] == execution['cases'], 'case record differs from raw output')
    verify_storage_contracts(observations, link_set)
    graphs = list(recipes)
    require(execution['graphs'] == graphs and [item['graph'] for item in observations['executors']] == graphs,
            'missing or duplicate execution graph')
    require([item['graph'] for item in build['graphs']] == graphs, 'missing or duplicate build graph')
    require(observations['executors'][0]['observations'] == observations['executors'][1]['observations'],
            'within-node observations disagree')
    require(execution['semantic_baseline'] == verify_semantics(observations, root, graphs),
            'historical semantic comparison record differs')
    compiler = dict(line.split(': ', 1) for line in build['compiler'].splitlines() if ': ' in line)
    require(compiler['release'] == TOOLCHAIN and compiler['host'] == cell[0], 'wrong compiler or host')
    require(build['toolchain_inputs']['compiler'] == build['compiler'], 'compiler records disagree')
    node_dir = directory / 'node'
    sources(node_dir, node, root, 'node')
    file_hash(root / 'protocol-bundles/node/Cargo.lock', node['lock_sha256'])
    file_hash(node_dir / 'build.log', node['build_log_sha256'])
    file_hash(node_dir / 'link-spec.json', node['link_spec_sha256'])
    file_hash(node_dir / 'root-objects.json', node['root_codegen_sha256'])
    file_hash(root / 'tools/protocol-bundles/node-rustc-wrapper.py', node['wrapper_sha256'])
    spec = read(node_dir / 'link-spec.json')
    require(spec.get('link_set') == link_set, 'node link specification uses another link set')
    require(spec['features'] == ['protocol-qualification'] and spec['lock_sha256'] == node['lock_sha256']
            and spec['source_inputs_sha256'] == node['source_inputs_sha256'], 'node link inputs disagree')
    require(read(node_dir / 'root-objects.json')['spec_sha256'] == node['link_spec_sha256'], 'stale root objects')
    require(set(node['ownership']) == OWNERSHIP, 'missing ownership audit')
    for name, expected in node['ownership'].items():
        file_hash(node_dir / name, expected)
    require([item['graph'] for item in spec['graphs']] == graphs, 'link graph set changed')
    for graph, linked in zip(build['graphs'], spec['graphs'], strict=True):
        name = graph['graph']
        expected_identity = identity(root, name, recipes)
        require(graph['identity'] == expected_identity, f'{name} graph identity changed')
        require(graph['lock_sha256'] == expected_identity['lock_sha256']
                and graph['manifest_sha256'] == expected_identity['manifest_sha256'], f'{name} lock/manifest mismatch')
        require(linked['build_inputs_sha256'] == fingerprint(graph), f'{name} link graph inputs differ')
        require(read(directory / name / 'build-inputs.json') == graph, f'{name} graph report differs')
        sources(directory / name, graph, graph_root(root, recipes[name]), 'executor', tool_root=root)
        file_hash(directory / name / 'build.log', graph['build_log_sha256'])
        file_hash(root / 'tools/protocol-bundles/rustc-wrapper.py', graph['wrapper_sha256'])
    verify_interface_report(node_dir / 'type-boundary', node['interface_checks'], build['graphs'], cell[0])
    return cell, observations, {key: compiler[key] for key in ('release', 'commit-hash', 'LLVM version')}


def compare(directory, root, profiles, upstream_status, link_set=None):
    require(upstream_status == 'success', f'upstream qualification did not succeed: {upstream_status}')
    require(profiles in ('release', 'full'), 'unknown qualification profile policy')
    executor_graphs(link_set)
    expected = {(target, profile) for target in TARGETS
                for profile in (('release',) if profiles == 'release' else ('dev', 'release'))}
    found = {}
    reference = None
    compiler_reference = None
    for path in sorted(directory.rglob('node-execution.json')):
        cell, observations, compiler = load_cell(path, root, link_set)
        require(cell in expected and cell not in found, f'unexpected or duplicate cell: {cell}')
        if reference is None:
            reference, compiler_reference = observations, compiler
        require(observations == reference, f'cross-platform execution differs: {cell}')
        require(compiler == compiler_reference, f'compiler version differs: {cell}')
        found[cell] = {'execution_sha256': digest(path), 'report': str(path)}
    require(set(found) == expected, f'missing required cells: {sorted(expected - set(found))}')
    return {'schema': 1, 'status': 'passed', 'policy': profiles, 'upstream_status': upstream_status,
            'link_set': link_set,
            'cells': [{'target': cell[0], 'profile': cell[1], **found[cell]} for cell in sorted(found)],
            'matching_observations': True, 'observations_sha256': fingerprint(reference),
            'compiler': compiler_reference}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--profiles', choices=('release', 'full'), required=True)
    parser.add_argument('--upstream-status', required=True)
    parser.add_argument('--link-set', choices=sorted(EXECUTOR_LINK_SETS), default='k4-node')
    args = parser.parse_args()
    args.output.unlink(missing_ok=True)
    try:
        result = compare(args.directory, ROOT, args.profiles, args.upstream_status, args.link_set)
    except Exception as error:
        write_json(args.output, {'schema': 1, 'status': 'failed', 'policy': args.profiles,
                                'upstream_status': args.upstream_status, 'error': str(error)})
        raise
    write_json(args.output, result)
    print(json.dumps(result), flush=True)


if __name__ == '__main__':
    main()
