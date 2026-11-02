"""Bind an unreleased managed protocol to its coordinator and independent consensus graph.

The K4 reference remains untouched. Writing a managed reference is explicit and
is only permitted while assembling an unreleased protocol. Released definitions
must be retained with their source and dependency graphs.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tomllib

from coordinator_definition import canonical, reference as coordinator_reference
from provenance import consensus_sources, local_source_files

DESTINATION = 'core/indexer/src/protocol/coordinator/managed/definitions/first.json'
REFERENCE_DIRECTORY = 'core/indexer/src/protocol/coordinator/managed/definitions/'
GRAPH = 'protocol-bundles/consensus-first/Cargo.toml'
TOOL = 'tools/protocol-bundles/managed_definition.py'
BUILD_INPUTS = (
    TOOL,
    'tools/protocol-bundles/provenance.py',
    'tools/protocol-bundles/node-rustc-wrapper.py',
    'tools/protocol-bundles/recipes.py',
)


def graph_reference(root, metadata, lock):
    root = root.resolve()
    packages = {item['id']: item for item in metadata['packages']}
    nodes = {item['id']: item for item in metadata['resolve']['nodes']}
    graph_root = metadata['resolve']['root']
    package = packages[graph_root]
    if (package['name'] != 'kontor-consensus-first' or package.get('source') is not None
            or Path(package['manifest_path']).resolve(strict=True) != root / GRAPH):
        raise ValueError('managed definition requires the consensus-first graph')
    selected = set()
    pending = [graph_root]
    while pending:
        item = pending.pop()
        if item not in selected:
            selected.add(item)
            pending.extend(dep['pkg'] for dep in nodes[item]['deps'])
    checksums = {(item['name'], item['version'], item.get('source')): item.get('checksum')
                 for item in lock['package']}
    sources = consensus_sources(root)

    def identity(package):
        source = package.get('source')
        if source is None:
            manifest = Path(package['manifest_path']).resolve(strict=True)
            source = manifest.relative_to(root).as_posix()
            for path in local_source_files(manifest.parent, root):
                sources[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        return f"{package['name']}@{package['version']}:{source}"

    identities = {item: identity(packages[item]) for item in selected}
    dependencies = []
    for item in sorted(selected, key=identities.get):
        package = packages[item]
        key = (package['name'], package['version'], package.get('source'))
        if key not in checksums:
            raise ValueError(f'resolved consensus dependency absent from lock: {key}')
        if str(package.get('source', '')).startswith('registry+') and not checksums[key]:
            raise ValueError(f'consensus registry dependency lacks checksum: {key}')
        dependencies.append({
            'package': identities[item], 'checksum': checksums[key],
            'features': sorted(nodes[item]['features']),
            'dependencies': sorted(({
                'name': dep['name'], 'package': identities[dep['pkg']],
                'kinds': sorted(dep.get('dep_kinds', []), key=canonical),
            } for dep in nodes[item]['deps']), key=canonical),
        })
    return {'root': identities[graph_root],
            'sources': sources, 'dependencies': dependencies}


def reference(root, node_metadata, node_lock, graph_metadata, graph_lock):
    root = root.resolve()
    coordinator = json.loads(coordinator_reference(root, node_metadata, node_lock))
    # Generated references are outputs, not recursively hashed source inputs.
    coordinator['sources'] = {name: digest for name, digest in coordinator['sources'].items()
                              if not name.startswith(REFERENCE_DIRECTORY)}
    for name in BUILD_INPUTS:
        path = root / name
        path.resolve(strict=True).relative_to(root)
        coordinator['sources'][name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return canonical({'schema': 1, 'policy': 'kontor/managed-consensus-v1; locked all-target closure',
                      'coordinator': coordinator,
                      'consensus': graph_reference(root, graph_metadata, graph_lock)})


def verify(root, node_metadata, node_lock, graph_metadata, graph_lock):
    expected = reference(root, node_metadata, node_lock, graph_metadata, graph_lock)
    if (root / DESTINATION).read_bytes() != expected:
        raise ValueError('managed consensus reference differs; never overwrite a released definition')
    return {'bytes': len(expected), 'consensus_definition': hashlib.sha256(
        b'kontor/consensus-definition/v1\0' + expected).hexdigest()}


def metadata(root, manifest):
    return json.loads(subprocess.check_output([
        'cargo', 'metadata', '--locked', '--offline', '--format-version=1',
        '--manifest-path', str(root / manifest)], cwd=root))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    parser.add_argument('--node-metadata', type=Path)
    parser.add_argument('--graph-metadata', type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    node_manifest = 'protocol-bundles/node/Cargo.toml'
    node = json.loads(args.node_metadata.read_bytes()) if args.node_metadata else metadata(root, node_manifest)
    graph = json.loads(args.graph_metadata.read_bytes()) if args.graph_metadata else metadata(root, GRAPH)
    node_lock = tomllib.loads((root / node_manifest).with_name('Cargo.lock').read_text())
    graph_lock = tomllib.loads((root / GRAPH).with_name('Cargo.lock').read_text())
    if args.write:
        destination = root / DESTINATION
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(reference(root, node, node_lock, graph, graph_lock))
    print(json.dumps(verify(root, node, node_lock, graph, graph_lock)))


if __name__ == '__main__':
    main()
