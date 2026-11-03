"""Record node and pinned consensus runtime build provenance, independently of protocol identity.

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
    'core/kontor-build/src/bin/kontor-node-rustc.rs',
    'tools/protocol-bundles/recipes.py',
)


def graph_manifest(label):
    if label != 'first':
        raise ValueError('unknown managed consensus graph')
    return f'protocol-bundles/consensus-{label}/Cargo.toml'


def destination(label):
    graph_manifest(label)
    return REFERENCE_DIRECTORY + label + '.json'


def graph_reference(root, metadata, lock, label='first'):
    root = root.resolve()
    packages = {item['id']: item for item in metadata['packages']}
    nodes = {item['id']: item for item in metadata['resolve']['nodes']}
    graph_root = metadata['resolve']['root']
    package = packages[graph_root]
    if (package['name'] != 'kontor-consensus-' + label or package.get('source') is not None
            or Path(package['manifest_path']).resolve(strict=True) != root / graph_manifest(label)):
        raise ValueError(f'managed definition requires the consensus-{label} graph')
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


def reference(root, node_metadata, node_lock, graph_metadata, graph_lock, label='first'):
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
                      'consensus': graph_reference(root, graph_metadata, graph_lock, label)})


def verify(root, node_metadata, node_lock, graph_metadata, graph_lock, label='first'):
    expected = reference(root, node_metadata, node_lock, graph_metadata, graph_lock, label)
    if (root / destination(label)).read_bytes() != expected:
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
    parser.add_argument('--graph', choices=('first',), default='first')
    parser.add_argument('--node-metadata', type=Path)
    parser.add_argument('--graph-metadata', type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    node_manifest = 'protocol-bundles/node/Cargo.toml'
    selected_graph = graph_manifest(args.graph)
    node = json.loads(args.node_metadata.read_bytes()) if args.node_metadata else metadata(root, node_manifest)
    graph = json.loads(args.graph_metadata.read_bytes()) if args.graph_metadata else metadata(root, selected_graph)
    node_lock = tomllib.loads((root / node_manifest).with_name('Cargo.lock').read_text())
    graph_lock = tomllib.loads((root / selected_graph).with_name('Cargo.lock').read_text())
    if args.write:
        output = root / destination(args.graph)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(reference(root, node, node_lock, graph, graph_lock, args.graph))
    print(json.dumps(verify(root, node, node_lock, graph, graph_lock, args.graph)))


if __name__ == '__main__':
    main()
