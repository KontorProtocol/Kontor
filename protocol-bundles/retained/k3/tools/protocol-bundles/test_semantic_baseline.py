import copy
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from build import ROOT
from semantic_baseline import verify


def sample_observation():
    """Synthetic comparator input, never evidence of execution."""
    baseline = json.loads((ROOT / 'tools/protocol-bundles/semantic-baseline.json').read_text())
    observed = baseline['observations']
    return {**{key: value for key, value in observed.items()
               if key not in ('recognition', 'transaction')},
            'gas': 17, 'state': 'same',
            'transactions': {**baseline['inputs'], 'recognition': observed['recognition'],
                             'executions': [copy.deepcopy(observed['transaction']) for _ in range(3)]}}


class HistoricalSemantics(unittest.TestCase):
    def setUp(self):
        self.observations = {'executors': [{'graph': name, 'observations': sample_observation()}
                                          for name in ('first', 'second')]}

    def test_matches_preserved_oracle(self):
        self.assertTrue(verify(self.observations, ROOT)['matching_observations'])

    def test_identical_regression_in_both_graphs_is_rejected(self):
        for graph in self.observations['executors']:
            graph['observations']['missing_function']['Err'][1] = 'different error'
        with self.assertRaisesRegex(ValueError, 'historical semantic comparison differs'):
            verify(self.observations, ROOT)

    def test_replay_or_missing_graph_cannot_pass(self):
        for kind in ('missing', 'duplicate', 'rollback', 'incomplete'):
            observed = copy.deepcopy(self.observations)
            if kind == 'missing':
                observed['executors'].pop()
            elif kind == 'duplicate':
                observed['executors'][1]['graph'] = 'first'
            else:
                executions = observed['executors'][0]['observations']['transactions']['executions']
                if kind == 'incomplete':
                    executions.pop()
                else:
                    executions[1]['usage'][0] += 1
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                verify(observed, ROOT)

    def test_fixture_and_raw_log_are_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'tools/protocol-bundles/semantic-baseline.json'
            baseline = json.loads((ROOT / path.relative_to(root)).read_text())
            for relative in [*baseline['provenance']['fixture_sources'],
                             'tools/protocol-bundles/semantic-baseline.json',
                             'tools/protocol-bundles/semantic-baseline.log']:
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, destination)
            verify(self.observations, root)
            for relative in [*baseline['provenance']['fixture_sources'],
                             'tools/protocol-bundles/semantic-baseline.log']:
                source = root / relative
                original = source.read_bytes()
                source.write_bytes(original + b'changed')
                with self.subTest(relative=relative), self.assertRaises(ValueError):
                    verify(self.observations, root)
                source.write_bytes(original)
            baseline['provenance']['fixture_sources'] = {}
            path.write_text(json.dumps(baseline))
            with self.assertRaisesRegex(ValueError, 'source set changed'):
                verify(self.observations, root)


if __name__ == '__main__':
    unittest.main()
