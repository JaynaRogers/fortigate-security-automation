"""Mocked tests: no network or FortiGate credentials required."""
import unittest
from unittest.mock import Mock

from src.fortios_api import fetch_firewall_policies, summarize_raw_policies


class FortiosApiTests(unittest.TestCase):
    def test_reads_with_bearer_token_and_vdom(self):
        session = Mock()
        response = Mock()
        response.json.return_value = {"status": "success", "results": [{"policyid": 10}]}
        session.get.return_value = response
        result = fetch_firewall_policies("https://fw.example.test", "fake-token", "root", session)
        self.assertEqual(result, [{"policyid": 10}])
        kwargs = session.get.call_args.kwargs
        self.assertEqual(kwargs["params"], {"vdom": "root"})
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer fake-token")
        self.assertTrue(kwargs["verify"])
        self.assertFalse(kwargs["allow_redirects"])
        self.assertEqual(session.get.call_count, 1)

    def test_refuses_http(self):
        with self.assertRaises(ValueError):
            fetch_firewall_policies("http://fw.example.test", "fake", session=Mock())

    def test_refuses_url_credentials(self):
        with self.assertRaises(ValueError):
            fetch_firewall_policies("https://user:pass@fw.example.test", "fake", session=Mock())

    def test_rejects_invalid_response(self):
        session = Mock()
        session.get.return_value.json.return_value = {"results": {}}
        with self.assertRaises(ValueError):
            fetch_firewall_policies("https://fw.example.test", "fake", session=session)

    def test_rejects_unsuccessful_response(self):
        session = Mock()
        session.get.return_value.json.return_value = {"status": "error", "results": []}
        with self.assertRaises(ValueError):
            fetch_firewall_policies("https://fw.example.test", "fake", session=session)

    def test_summarizes_unresolved_objects(self):
        summary = summarize_raw_policies([{"policyid": 3, "srcaddr": [{"name": "all"}],
                                           "dstaddr": [{"name": "web"}],
                                           "service": [{"name": "HTTPS"}]}])
        self.assertEqual(summary[0]["srcaddr"], ["all"])
        self.assertEqual(summary[0]["service"], ["HTTPS"])


if __name__ == "__main__":
    unittest.main()
