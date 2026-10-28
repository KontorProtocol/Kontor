import importlib.util
import unittest
from pathlib import Path


SPEC = importlib.util.spec_from_file_location("native_stack_qualify", Path(__file__).with_name("qualify.py"))
qualify = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(qualify)


class QualifyTests(unittest.TestCase):
    def test_single_recursion_case_does_not_require_reentry(self):
        result = {
            "kind": "paid_recurse",
            "boundary": "first_failure",
            "last_success": 3,
            "first_failure": 4,
            "first_failure_outcome": "stack_overflow",
        }
        self.assertTrue(qualify.acceptable_results([result]))

    def test_selected_reentry_still_requires_exact_boundary(self):
        result = {
            "kind": "paid_reenter",
            "boundary": "first_failure",
            "last_success": 62,
            "first_failure": 63,
            "first_failure_outcome": "invocation_limit",
        }
        self.assertFalse(qualify.acceptable_results([result]))
        result["last_success"] = 63
        result["first_failure"] = 64
        self.assertTrue(qualify.acceptable_results([result]))


if __name__ == "__main__":
    unittest.main()
