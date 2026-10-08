import unittest

from src.audit import audit_policies
from src.object_resolution import (
    ResolutionError, normalize_fortios_policy, resolve_addresses, resolve_services,
)


class ResolutionTests(unittest.TestCase):
    def test_nested_address_groups(self):
        addresses = [{"name": "net", "type": "ipmask", "subnet": "192.0.2.0 255.255.255.0"}]
        groups = [{"name": "inner", "member": [{"name": "net"}]},
                  {"name": "outer", "member": [{"name": "inner"}]}]
        self.assertEqual(resolve_addresses(["outer"], addresses, groups), ["192.0.2.0/24"])

    def test_address_cycle_rejected(self):
        groups = [{"name": "a", "member": [{"name": "b"}]},
                  {"name": "b", "member": [{"name": "a"}]}]
        with self.assertRaises(ResolutionError):
            resolve_addresses(["a"], [], groups)

    def test_unresolved_address_rejected(self):
        with self.assertRaises(ResolutionError):
            resolve_addresses(["unknown"], [], [])

    def test_unsupported_address_type_rejected(self):
        with self.assertRaises(ResolutionError):
            resolve_addresses(["fqdn"], [{"name": "fqdn", "type": "fqdn", "fqdn": "example.test"}], [])

    def test_nested_service_groups(self):
        groups = [{"name": "web", "member": [{"name": "HTTPS"}]},
                  {"name": "nested", "member": [{"name": "web"}]}]
        self.assertEqual(resolve_services(["nested"], [{"name": "HTTPS"}], groups), ["HTTPS"])

    def test_service_cycle_rejected(self):
        groups = [{"name": "a", "member": [{"name": "b"}]},
                  {"name": "b", "member": [{"name": "a"}]}]
        with self.assertRaises(ResolutionError):
            resolve_services(["a"], [], groups)

    def test_group_resolved_broad_allow_is_flagged(self):
        policy = {
            "policyid": 42, "name": "Lab wide access", "action": "accept",
            "status": "enable", "logtraffic": "disable",
            "srcaddr": [{"name": "any-group"}],
            "dstaddr": [{"name": "all"}],
            "service": [{"name": "all-services"}],
        }
        normalized = normalize_fortios_policy(
            policy, [], [{"name": "any-group", "member": [{"name": "all"}]}],
            [], [{"name": "all-services", "member": [{"name": "ALL"}]}],
        )
        rules = {item["rule"] for item in audit_policies([normalized])}
        self.assertEqual(rules, {"ANY_TO_ANY", "ALL_SERVICES", "NO_LOGGING"})

    def test_duplicate_objects_rejected(self):
        with self.assertRaises(ResolutionError):
            resolve_addresses(["a"], [{"name": "a", "subnet": "192.0.2.1/32"},
                                      {"name": "a", "subnet": "192.0.2.2/32"}], [])


if __name__ == "__main__":
    unittest.main()
