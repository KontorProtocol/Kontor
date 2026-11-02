"""Compare actual retained execution with the preserved historical semantic oracle."""

import hashlib
import json


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def project(observation):
    transactions = observation['transactions']
    executions = transactions['executions']
    if len(executions) != 3 or any(value != executions[0] for value in executions):
        raise ValueError('historical comparison requires matching simulation, rollback and commit')
    return {
        'inputs': {key: transactions[key] for key in ('raw_sha256', 'counter_sha256', 'proxy_sha256')},
        'observations': {
            **{key: observation[key] for key in ('genesis', 'active_set', 'missing_function',
                                                'committee', 'malformed_transaction', 'lifecycle')},
            'recognition': transactions['recognition'], 'transaction': executions[-1],
        },
    }


def verify(observations, root, expected_graphs=('first', 'second')):
    path = root / 'tools/protocol-bundles/semantic-baseline.json'
    expected = json.loads(path.read_text())
    if expected['schema'] != 1:
        raise ValueError('unknown historical semantic baseline schema')
    fixtures = expected['provenance']['fixture_sources']
    if set(fixtures) != {'core/indexer/src/protocol_qualification/fixture.rs',
                         'tools/protocol-bundles/historical_semantics.rs'}:
        raise ValueError('historical semantic fixture source set changed')
    if digest(path.with_suffix('.log')) != expected['provenance']['log_sha256']:
        raise ValueError('historical semantic oracle log changed')
    for relative, checksum in fixtures.items():
        source = root / relative
        if not source.resolve().is_relative_to(root.resolve()) or digest(source) != checksum:
            raise ValueError(f'historical semantic fixture changed: {relative}')
    graphs = observations['executors']
    if tuple(expected_graphs) not in (('first', 'second'), ('first', 'observer')):
        raise ValueError('unknown historical comparison graph set')
    if [graph['graph'] for graph in graphs] != list(expected_graphs):
        raise ValueError('historical comparison requires both actual retained graphs')
    for graph in graphs:
        actual = project(graph['observations'])
        for section in ('inputs', 'observations'):
            if actual[section] != expected[section]:
                differing = [key for key in expected[section]
                             if actual[section].get(key) != expected[section][key]]
                raise ValueError(f"historical semantic comparison differs for {graph['graph']}: {section}/{differing}")
    return {'baseline_sha256': digest(path), 'historical_source': expected['historical_source'],
            'historical_base': expected['provenance']['historical_base'],
            'matching_observations': True, 'graphs': list(expected_graphs)}
