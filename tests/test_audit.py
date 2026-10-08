import copy
import json
import unittest
from pathlib import Path
from src.audit import audit_policies, compare_policies, validate_policy

ROOT = Path(__file__).resolve().parents[1] / 'examples'


class PolicyAuditTests(unittest.TestCase):
    def setUp(self):
        self.expected = json.loads((ROOT / 'baseline.json').read_text())
        self.actual = json.loads((ROOT / 'observed.json').read_text())

    def test_flags_broad_allow(self):
        rules = [f['rule'] for f in audit_policies(self.actual)]
        self.assertIn('ANY_TO_ANY', rules)
        self.assertIn('ALL_SERVICES', rules)
        self.assertIn('NO_LOGGING', rules)

    def test_default_deny_not_flagged(self):
        self.assertEqual(audit_policies([self.expected[1]]), [])

    def test_drift_detected(self):
        drift = compare_policies(self.expected, self.actual)
        self.assertEqual(drift['unexpected'], [30])
        self.assertEqual(drift['changed'][0]['id'], 10)
        self.assertIn('service', drift['changed'][0]['fields'])

    def test_identical_has_no_drift(self):
        self.assertEqual(compare_policies(self.expected, self.expected), {'missing': [], 'unexpected': [], 'changed': []})

    def test_rejects_invalid_network(self):
        item = copy.deepcopy(self.expected[0])
        item['source'] = ['not-an-ip']
        with self.assertRaises(ValueError):
            validate_policy(item)

    def test_rejects_duplicate_ids(self):
        with self.assertRaises(ValueError):
            audit_policies([self.expected[0], self.expected[0]])

    def test_disabled_allow_ignored(self):
        item = copy.deepcopy(self.actual[-1])
        item['enabled'] = False
        self.assertEqual(audit_policies([item]), [])


if __name__ == '__main__':
    unittest.main()
