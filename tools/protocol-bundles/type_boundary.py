"""Compile interface controls against the actual retained executor libraries."""

import json
from pathlib import Path
import subprocess

from provenance import fingerprint, sha


PROBES = {
    'structural-factories': (None, '''use first::Factory as First;
use second::Factory as Second;
pub fn first_into_second(value: First) -> Second { value }
pub fn second_into_first(value: Second) -> First { value }
'''),
    'wasmtime-engine': ('E0308', '''use first_wasmtime::Engine as First;
use second_wasmtime::Engine as Second;
pub fn cross_graph(value: First) -> Second { value }
'''),
    'tokio-handle': ('E0308', '''use first_tokio::runtime::Handle as First;
use second_tokio::runtime::Handle as Second;
pub fn cross_graph(value: First) -> Second { value }
'''),
    'first-private-runtime': ('E0603', '''use first::runtime::Runtime;
pub fn unselected_runtime(value: Runtime) { drop(value); }
'''),
    'second-private-runtime': ('E0603', '''use second::runtime::Runtime;
pub fn unselected_runtime(value: Runtime) { drop(value); }
'''),
}


def check_diagnostics(returncode, text, expected):
    diagnostics = [json.loads(line) for line in text.splitlines() if line.strip()]
    errors = [item for item in diagnostics if item.get('level') == 'error']
    codes = {item['code']['code'] for item in errors if item.get('code')}
    if expected is None:
        valid = returncode == 0 and not errors
    else:
        valid = returncode != 0 and codes == {expected}
    if not valid:
        raise RuntimeError(f'interface control failed: expected {expected or "success"}, exit={returncode}, codes={codes}')


def inputs_for(graphs, check_files):
    if [graph['graph'] for graph in graphs] not in (['first', 'second'], ['first', 'observer']):
        raise RuntimeError('interface controls require both production graphs')
    arguments = []
    inputs = {}
    for name, graph in zip(('first', 'second'), graphs, strict=True):
        libraries = {name: Path(graph['facade'])}
        for dependency in ('wasmtime', 'tokio'):
            candidates = [item for item in graph['artifacts']
                          if Path(item['path']).name.startswith(f'lib{dependency}-')]
            if len(candidates) != 1:
                raise RuntimeError(f'ambiguous {name} {dependency} artifact')
            libraries[f'{name}_{dependency}'] = Path(candidates[0]['path'])
        recorded = {item['path']: item['sha256'] for item in graph['artifacts']}
        for alias, path in libraries.items():
            if str(path) not in recorded or (check_files and sha(path) != recorded[str(path)]):
                raise RuntimeError(f'interface library changed: {path}')
            arguments.extend(['--extern', f'{alias}={path}'])
            inputs[alias] = recorded[str(path)]
        arguments.extend(['-L', f"dependency={graph['link_inputs']}"])
    return arguments, inputs


def verify_report(directory, binding, graphs, target):
    report_path = directory / 'result.json'
    if sha(report_path) != binding['report_sha256'] or binding['controls'] != list(PROBES):
        raise RuntimeError('interface report binding changed')
    report = json.loads(report_path.read_text())
    if (report['schema'] != 1 or report['status'] != 'passed' or report['target'] != target
            or report['graph_inputs'] != {graph['graph']: fingerprint(graph) for graph in graphs}
            or report['libraries'] != inputs_for(graphs, False)[1]
            or set(report['controls']) != set(PROBES)):
        raise RuntimeError('interface report inputs changed')
    for name, (expected, source) in PROBES.items():
        control = report['controls'][name]
        source_path = directory / f'{name}.rs'
        log = directory / f'{name}.log'
        if (source_path.read_text() != source or sha(source_path) != control['source_sha256']
                or sha(log) != control['diagnostics_sha256'] or control['expected_error'] != expected):
            raise RuntimeError('interface source or diagnostic binding changed')
        check_diagnostics(control['returncode'], log.read_text(), expected)


def verify(graphs, target, env, output):
    directory = output / 'type-boundary'
    directory.mkdir(exist_ok=True)
    report_path = directory / 'result.json'
    report_path.unlink(missing_ok=True)
    arguments, inputs = inputs_for(graphs, True)
    controls = {}
    for name, (expected, source) in PROBES.items():
        path = directory / f'{name}.rs'
        path.write_text(source)
        command = [env['RUSTC'], '--edition=2024', '--target', target, '--crate-type=lib',
                   '--crate-name', name.replace('-', '_'), '--emit=metadata', '--error-format=json',
                   '-Cpanic=unwind', *arguments, str(path), '-o', str(directory / f'{name}.rmeta')]
        result = subprocess.run(command, env=env, text=True, capture_output=True, timeout=60)
        log = directory / f'{name}.log'
        log.write_text(result.stderr)
        check_diagnostics(result.returncode, result.stderr, expected)
        controls[name] = {'expected_error': expected, 'returncode': result.returncode,
                          'source_sha256': sha(path), 'diagnostics_sha256': sha(log)}
    result = {'schema': 1, 'status': 'passed', 'target': target, 'libraries': inputs,
              'graph_inputs': {graph['graph']: fingerprint(graph) for graph in graphs},
              'controls': controls}
    report_path.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    return {'report_sha256': sha(report_path), 'controls': list(controls)}
