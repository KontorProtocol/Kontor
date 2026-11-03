#!/usr/bin/env python3
"""Record the node's actual driver call and its selected linker backend."""

import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def executable(name):
    found = shutil.which(name)
    if found is None:
        raise RuntimeError(f'linker executable unavailable: {name}')
    invocation = Path(found).absolute()
    resolved = invocation.resolve(strict=True)
    return {'invocation_path': str(invocation), 'path': str(resolved), 'sha256': digest(resolved)}


def expand(arguments, depth=0):
    if depth > 4:
        raise RuntimeError('nested linker response files exceed supported depth')
    result = []
    for argument in arguments:
        if argument.startswith('@'):
            result.extend(expand(shlex.split(Path(argument[1:]).read_text()), depth + 1))
        else:
            result.append(argument)
    return result


def backend(driver, arguments):
    # Ask the same driver while rustc's temporary inputs still exist. Clang's
    # plan names ld directly; GCC names collect2, whose program search must also
    # receive Rust's -B paths and selected -fuse-ld variant.
    if os.environ.get('COLLECT_LD_OVERRIDE'):
        raise RuntimeError('COLLECT_LD_OVERRIDE is not supported by linker qualification')
    expanded = expand(arguments)
    if any(arg.startswith(('-specs', '--specs', '-wrapper')) for arg in expanded):
        raise RuntimeError('custom compiler specs/wrappers need explicit linker qualification')
    command = [driver, '-###', *arguments]
    plan = subprocess.run(command, capture_output=True, text=True, check=True)
    commands = []
    for line in plan.stderr.splitlines():
        try:
            words = shlex.split(line)
        except ValueError:
            continue
        if words and Path(words[0]).name in ('collect2', 'ld', 'ld.lld', 'ld.gold', 'ld.bfd',
                                             'ld64.lld', 'lld', 'rust-lld', 'mold', 'ld.mold'):
            commands.append(words)
    if len(commands) != 1:
        raise RuntimeError('driver did not identify exactly one supported linker command')
    selected = commands[0][0]
    query = None
    if Path(selected).name == 'collect2':
        search = []
        variant = None
        index = 0
        while index < len(expanded):
            arg = expanded[index]
            if arg == '-B':
                index += 1
                if index == len(expanded):
                    raise RuntimeError('missing linker search directory')
                search.extend(['-B', expanded[index]])
            elif arg.startswith('-B'):
                search.append(arg)
            elif arg.startswith('-fuse-ld='):
                variant = arg.split('=', 1)[1]
            index += 1
        if variant is not None and variant not in ('bfd', 'gold', 'lld', 'mold'):
            raise RuntimeError('unsupported GCC linker variant')
        name = 'ld' if variant is None else 'ld.' + variant
        query = [driver, *search, '-print-prog-name=' + name]
        selected = subprocess.check_output(query, text=True).strip()
    return executable(selected), {
        'method': 'compiler-driver-plan', 'command': command,
        'stdout': plan.stdout, 'stderr': plan.stderr, 'backend_query': query,
    }


def validate(record, spec_hash, output_hash):
    if (record.get('schema') != 1 or record.get('spec_sha256') != spec_hash
            or record.get('output_sha256') != output_hash):
        raise RuntimeError('linker record does not match the node build')
    for name in ('driver', 'backend'):
        tool = record.get(name, {})
        if (set(tool) != {'invocation_path', 'path', 'sha256'}
                or not all(isinstance(tool[key], str) and Path(tool[key]).is_absolute()
                           for key in ('invocation_path', 'path'))
                or not isinstance(tool['sha256'], str) or len(tool['sha256']) != 64
                or any(character not in '0123456789abcdef' for character in tool['sha256'])):
            raise RuntimeError('linker executable provenance is incomplete')
    arguments = record.get('arguments')
    expanded = record.get('expanded_arguments')
    selection = record.get('selection', {})
    if (not isinstance(arguments, list) or not all(isinstance(arg, str) for arg in arguments)
            or not isinstance(expanded, list) or not all(isinstance(arg, str) for arg in expanded)
            or expanded.count('-o') != 1 or expanded[-1] == '-o'
            or not isinstance(record.get('working_directory'), str)
            or not Path(record['working_directory']).is_absolute()
            or selection.get('method') != 'compiler-driver-plan'
            or selection.get('command') != [record['driver']['invocation_path'], '-###', *arguments]
            or not isinstance(selection.get('stderr'), str) or not selection['stderr']):
        raise RuntimeError('linker invocation provenance is incomplete')
    output = Path(expanded[expanded.index('-o') + 1])
    if not output.is_absolute():
        output = Path(record['working_directory']) / output
    if str(output) != record.get('output'):
        raise RuntimeError('linker invocation targets another output')


def main():
    spec_path = Path(os.environ['KONTOR_NODE_LINK_SPEC'])
    spec = json.loads(spec_path.read_text())
    arguments = sys.argv[1:]
    driver = executable(os.environ['KONTOR_REAL_LINKER'])
    selected, selection = backend(driver['invocation_path'], arguments)
    expanded = expand(arguments)
    if expanded.count('-o') != 1:
        raise RuntimeError('linker output path missing or ambiguous')
    output = Path(expanded[expanded.index('-o') + 1]).absolute()
    result = subprocess.run([driver['invocation_path'], *arguments], close_fds=False)
    if result.returncode:
        raise SystemExit(result.returncode)
    for tool in (driver, selected):
        if digest(tool['path']) != tool['sha256']:
            raise RuntimeError('linker tool changed during invocation')
    record = {'schema': 1, 'spec_sha256': digest(spec_path), 'driver': driver,
              'arguments': arguments, 'expanded_arguments': expanded,
              'working_directory': os.getcwd(), 'backend': selected, 'selection': selection,
              'output': str(output), 'output_sha256': digest(output)}
    Path(spec['linker_record']).write_text(json.dumps(record, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
