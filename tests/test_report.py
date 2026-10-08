"""Offline report generation and HTML escaping tests."""
import unittest

from src.report import assess, render_html


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.baseline = [
            {"id": 1, "name": "web", "source": ["192.0.2.0/24"],
             "destination": ["198.51.100.1/32"], "service": ["HTTPS"],
             "action": "accept", "logging": True, "enabled": True}
        ]

    def test_summary_and_remediation(self):
        observed = [{**self.baseline[0], "service": ["ALL"], "logging": False}]
        report = assess(self.baseline, observed)
        self.assertEqual(report["summary"]["findings"], 2)
        self.assertEqual(report["summary"]["changed_policies"], 1)
        self.assertTrue(all(item["remediation"] for item in report["findings"]))

    def test_report_escapes_dynamic_text(self):
        observed = [{**self.baseline[0], "id": 9, "name": "<script>alert(1)</script>",
                     "source": ["0.0.0.0/0"], "destination": ["0.0.0.0/0"]}]
        html = render_html(assess(self.baseline, observed))
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_empty_findings_report(self):
        report = assess(self.baseline, self.baseline)
        html = render_html(report)
        self.assertIn("No findings", html)
        self.assertEqual(report["summary"]["findings"], 0)

    def test_drift_is_reported(self):
        observed = self.baseline + [{**self.baseline[0], "id": 2}]
        report = assess(self.baseline, observed)
        self.assertEqual(report["drift"]["unexpected"], [2])
        self.assertIn("unexpected", render_html(report))


if __name__ == "__main__":
    unittest.main()
