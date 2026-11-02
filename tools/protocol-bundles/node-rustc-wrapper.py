#!/usr/bin/env python3
"""Supply separately staged execution and consensus graphs to the node compiler."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def prepare(compiler, arguments, spec):
    if Path(compiler).resolve() != Path(spec['compiler']).resolve():
        raise RuntimeError('node wrapper requires the pinned compiler')
    arguments = list(arguments)
    if '--crate-name' not in arguments:
        return arguments, None
    name = arguments[arguments.index('--crate-name') + 1]
    if name not in ('indexer', 'kontor'):
        return arguments, None
    link_set = spec.get('link_set')
    expected = {
        'legacy-qualification': [('executor', 'first'), ('executor', 'second')],
        'k4-node': [('executor', 'first'), ('executor', 'observer')],
        'managed-node': [('executor', 'first'), ('executor', 'observer'),
                         ('consensus', 'first'), ('consensus', 'second')],
    }
    selected = [(graph.get('role', 'executor'), graph['graph']) for graph in spec['graphs']]
    if link_set is not None:
        if link_set not in expected or selected != expected[link_set]:
            raise RuntimeError('node link set does not match its independent libraries')
    if any(role not in ('executor', 'consensus') for role, _ in selected):
        raise RuntimeError('unknown independent library role')
    if link_set in ('k4-node', 'managed-node'):
        arguments.extend(['--cfg', 'kontor_observer'])
    if link_set == 'managed-node':
        arguments.extend(['--cfg', 'kontor_managed'])
    for graph in spec['graphs']:
        if digest(graph['facade']) != graph['facade_sha256']:
            raise RuntimeError('retained facade changed before node compilation')
        arguments.extend(['-L', 'dependency=' + graph['link_inputs']])
        if name == 'indexer':
            role = graph.get('role', 'executor')
            arguments.extend(['--extern', 'kontor_' + role + '_' + graph['graph'] + '=' + graph['facade']])
    if name != 'kontor':
        return arguments, None
    out_dir = Path(arguments[arguments.index('--out-dir') + 1])
    extra = None
    for index, value in enumerate(arguments):
        if value == '-C' and arguments[index + 1].startswith('extra-filename='):
            extra = arguments[index + 1].removeprefix('extra-filename=')
        elif value.startswith('-Cextra-filename='):
            extra = value.removeprefix('-Cextra-filename=')
    if extra is None:
        raise RuntimeError('missing node codegen artifact identity')
    arguments.append('-Csave-temps')
    return arguments, (out_dir, name + extra + '.*.rcgu.o')


def attestation_environment(arguments, spec):
    if spec.get('link_set') != 'managed-node':
        return {}
    record = spec.get('attestation')
    if (not isinstance(record, dict) or record.get('schema') != 1
            or record.get('link_set') != 'managed-node'
            or len(record.get('graphs', [])) != 4):
        raise RuntimeError('managed node requires its builder attestation')
    for actual, library in zip(record['graphs'], spec['graphs']):
        for key in ('role', 'graph', 'facade_sha256', 'build_inputs_sha256'):
            if actual.get(key) != library[key]:
                raise RuntimeError('builder attestation differs from linked input')
    if '--target' not in arguments or arguments[arguments.index('--target') + 1] != record['target']:
        raise RuntimeError('builder attestation target differs from compiler target')
    return {'KONTOR_NODE_ATTESTATION': json.dumps(record, sort_keys=True, separators=(',', ':')),
            'KONTOR_NODE_TARGET': record['target']}

def main():
    spec_path = Path(os.environ['KONTOR_NODE_LINK_SPEC'])
    spec_hash = digest(spec_path)
    spec = json.loads(spec_path.read_text())
    compiler, *original = sys.argv[1:]
    arguments, capture = prepare(compiler, original, spec)
    if capture is not None:
        directory, pattern = capture
        for path in directory.glob(pattern):
            path.unlink()
    # Cargo passes inheritable jobserver descriptors to its compiler. Closing
    # them here loses rustc's access to the shared compilation budget.
    environment = dict(os.environ)
    environment.pop('KONTOR_NODE_ATTESTATION', None)
    environment.pop('KONTOR_NODE_TARGET', None)
    if '--crate-name' in original and original[original.index('--crate-name') + 1] in ('indexer', 'kontor'):
        environment.update(attestation_environment(original, spec))
    result = subprocess.run([compiler, *arguments], close_fds=False, env=environment)
    if result.returncode:
        raise SystemExit(result.returncode)
    if capture is not None:
        objects = [{'path': str(path), 'sha256': digest(path)}
                   for path in sorted(directory.glob(pattern))]
        if not objects:
            raise RuntimeError('node compiler did not retain codegen objects')
        Path(spec['root_objects']).write_text(json.dumps({
            'spec_sha256': spec_hash, 'objects': objects, 'compiler': compiler,
            'arguments': arguments, 'working_directory': os.getcwd(),
        }) + '\n')


if __name__ == '__main__':
    main()
