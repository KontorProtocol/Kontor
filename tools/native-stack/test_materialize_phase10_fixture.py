"""Historical fixture expansion and raw identity checks."""

import tempfile
import unittest
from pathlib import Path

from materialize_phase10_fixture import RAW_SIZE, materialize
from resource_evidence_v2 import HISTORICAL_BUNDLE_SHA256


class HistoricalFixtureTests(unittest.TestCase):
    def test_pinned_capture_expands_to_exact_historical_bundle(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "resource-chain-capture.json"
            result = materialize(output)
            self.assertEqual(result["size"], RAW_SIZE)
            self.assertEqual(result["sha256"], HISTORICAL_BUNDLE_SHA256)
            self.assertEqual(output.stat().st_size, RAW_SIZE)
            with self.assertRaisesRegex(ValueError, "already exists"):
                materialize(output)


if __name__ == "__main__":
    unittest.main()
