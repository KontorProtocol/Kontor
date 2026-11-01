import json
import unittest

from type_boundary import check_diagnostics


class Diagnostics(unittest.TestCase):
    def error(self, code):
        return json.dumps({'level': 'error', 'code': {'code': code}})

    def test_expected_type_or_privacy_errors(self):
        check_diagnostics(0, '', None)
        check_diagnostics(1, self.error('E0308'), 'E0308')
        check_diagnostics(1, self.error('E0603'), 'E0603')

    def test_missing_dependency_is_not_a_successful_negative_control(self):
        for text in (self.error('E0463'), self.error('E0308') + '\n' + self.error('E0463')):
            with self.assertRaises(RuntimeError):
                check_diagnostics(1, text, 'E0308')

    def test_success_or_crash_cannot_satisfy_expected_rejection(self):
        for status, text in ((0, ''), (-9, ''), (0, self.error('E0308'))):
            with self.assertRaises(RuntimeError):
                check_diagnostics(status, text, 'E0308')


if __name__ == '__main__':
    unittest.main()
