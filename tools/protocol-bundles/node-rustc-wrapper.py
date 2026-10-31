#!/usr/bin/env python3
"""Supply separately staged executors to the node's compiler invocations."""

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
    for graph in spec['graphs']:
        if digest(graph['facade']) != graph['facade_sha256']:
            raise RuntimeError('retained facade changed before node compilation')
        arguments.extend(['-L', 'dependency=' + graph['link_inputs']])
        if name == 'indexer':
            arguments.extend(['--extern', 'kontor_executor_' + graph['graph'] + '=' + graph['facade']])
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
    result = subprocess.run([compiler, *arguments])
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
