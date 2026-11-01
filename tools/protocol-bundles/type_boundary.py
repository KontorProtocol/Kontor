"""Compile interface controls against the actual independently built libraries."""

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

CONSENSUS_PROBES = {
    'typed-adapter': (None, '''use first::api::{EnginePoll, Response, Validator};
use first::Engine;
use second::api::Validator as SecondValidator;
use std::time::Duration;
pub fn adapt(value: Validator) -> SecondValidator {
    SecondValidator { public_key: value.public_key, voting_power: value.voting_power }
}

pub fn drive(engine: &mut Engine) {
    if let Ok(EnginePoll::Event(event)) = engine.poll() {
        if let Some(token) = event.reply {
            let _ = engine.respond(token, Response::HistoryMinHeight(1));
        }
    }
    let _ = engine.request_stop();
    let _ = engine.wait_stopped(Duration::ZERO);
}
'''),
    'distinct-validator': ('E0308', '''use first::api::Validator as First;
use second::api::Validator as Second;
pub fn cross_graph(value: First) -> Second { value }
'''),
    'distinct-engine': ('E0308', '''use first::Engine as First;
use second::Engine as Second;
pub fn cross_graph(value: First) -> Second { value }
'''),
    'tokio-handle': PROBES['tokio-handle'],
    'first-private-consensus': ('E0603', '''use first::consensus::Ctx;
pub fn private_context(value: Ctx) { drop(value); }
'''),
    'second-private-owner': ('E0603', '''use second::owner::Owner;
pub fn private_owner(value: Owner) { drop(value); }
'''),
    'control-thread-owner': ('E0277', '''use first::Engine;
pub fn require_send<T: Send>() {}
pub fn move_owner() { require_send::<Engine>(); }
'''),
}


ADAPTER_TESTS = [
    f'managed::adapter::{graph}::tests::{test}'
    for graph in ('first', 'second')
    for test in ('height_parameters_preserve_committee_order_and_all_timeouts',
                 'event_keeps_generation_rounds_and_canonical_payload',
                 'local_failure_is_not_reclassified_as_a_peer_fault')
] + ['managed::adapter::tests::publication_rejection_returns_the_original_buffer_for_retry']


def probes_for(graphs):
    consensus = [graph.get('identity', {}).get('kind') == 'consensus' for graph in graphs]
    if any(consensus):
        if not all(consensus) or [graph['graph'] for graph in graphs] != ['first', 'second']:
            raise RuntimeError('consensus interface controls require both consensus graphs')
        return CONSENSUS_PROBES
    return PROBES


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
    dependencies = ('tokio',) if probes_for(graphs) is CONSENSUS_PROBES else ('wasmtime', 'tokio')
    for name, graph in zip(('first', 'second'), graphs, strict=True):
        libraries = {name: Path(graph['facade'])}
        for dependency in dependencies:
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
    probes = probes_for(graphs)
    report_path = directory / 'result.json'
    if sha(report_path) != binding['report_sha256'] or binding['controls'] != list(probes):
        raise RuntimeError('interface report binding changed')
    report = json.loads(report_path.read_text())
    if (report['schema'] != 1 or report['status'] != 'passed' or report['target'] != target
            or report['graph_inputs'] != {graph['graph']: fingerprint(graph) for graph in graphs}
            or report['libraries'] != inputs_for(graphs, False)[1]
            or set(report['controls']) != set(probes)):
        raise RuntimeError('interface report inputs changed')
    for name, (expected, source) in probes.items():
        control = report['controls'][name]
        source_path = directory / f'{name}.rs'
        log = directory / f'{name}.log'
        if (source_path.read_text() != source or sha(source_path) != control['source_sha256']
                or sha(log) != control['diagnostics_sha256'] or control['expected_error'] != expected):
            raise RuntimeError('interface source or diagnostic binding changed')
        check_diagnostics(control['returncode'], log.read_text(), expected)


def verify(graphs, target, env, output):
    probes = probes_for(graphs)
    directory = output / 'type-boundary'
    directory.mkdir(exist_ok=True)
    report_path = directory / 'result.json'
    report_path.unlink(missing_ok=True)
    arguments, inputs = inputs_for(graphs, True)
    controls = {}
    for name, (expected, source) in probes.items():
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


def verify_node_adapter(root, graphs, target, env, output):
    if probes_for(graphs) is not CONSENSUS_PROBES:
        raise RuntimeError('node adapter checks require consensus graphs')
    directory = output / 'node-adapter'
    directory.mkdir(exist_ok=True)
    source = directory / 'adapter.rs'
    module = root / 'core/indexer/src/protocol/coordinator/managed'
    # An out-of-line #[path] module changes Rust's child-module search root.
    # Bind the two actual adapter files explicitly without importing unrelated
    # coordinator services into this small executable.
    source.write_text('mod managed {\n' + ''.join(
        f'#[path = {json.dumps(str(module / (name + ".rs")))}]\npub(crate) mod {name};\n'
        for name in ('types', 'adapter')) + '}\n')
    arguments, libraries = inputs_for(graphs, True)
    for graph in graphs:
        arguments.extend(['--extern', f"kontor_consensus_{graph['graph']}={graph['facade']}"])
    binary = directory / 'adapter-tests'
    command = [env['RUSTC'], '--edition=2024', '--target', target, '--test',
               '--crate-name', 'node_adapter', '-Cpanic=unwind', *arguments, str(source), '-o', str(binary)]
    compiled = subprocess.run(command, env=env, text=True, capture_output=True, timeout=120)
    compiler_log = directory / 'compile.log'
    compiler_log.write_text(compiled.stdout + compiled.stderr)
    if compiled.returncode != 0:
        raise RuntimeError(f'actual node adapter failed to compile: {compiler_log}')
    tested = subprocess.run([str(binary), '--test-threads=1'], env=env, text=True,
                            capture_output=True, timeout=30)
    log = directory / 'test.log'
    log.write_text(tested.stdout + tested.stderr)
    if not adapter_tests_passed(tested.returncode, tested.stdout):
        raise RuntimeError(f'actual node adapter tests failed or did not execute: {log}')
    return {'tests': ADAPTER_TESTS, 'source_sha256': sha(source), 'binary_sha256': sha(binary),
            'compiler_log_sha256': sha(compiler_log), 'test_log_sha256': sha(log),
            'libraries': libraries, 'graph_inputs': {graph['graph']: fingerprint(graph) for graph in graphs}}


def adapter_tests_passed(returncode, output):
    return (returncode == 0
            and f'test result: ok. {len(ADAPTER_TESTS)} passed; 0 failed; 0 ignored;' in output
            and all(f'test {name} ... ok' in output for name in ADAPTER_TESTS))
