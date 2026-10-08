"""Generate a standalone, escaped HTML security report from synthetic policy data."""
import argparse
from collections import Counter
from datetime import datetime, timezone
from html import escape
import json
from pathlib import Path

from src.audit import audit_policies, compare_policies

REMEDIATION = {
    "ANY_TO_ANY": "Restrict source and destination scopes to approved networks.",
    "ALL_SERVICES": "Replace ALL with explicitly required services and ports.",
    "NO_LOGGING": "Enable appropriate traffic logging for permitted connections.",
}
SEVERITIES = ("high", "medium", "low")


def assess(expected, observed):
    """Return deterministic, offline findings and policy drift."""
    findings = audit_policies(observed)
    drift = compare_policies(expected, observed)
    counts = Counter(item["severity"] for item in findings)
    return {
        "summary": {
            "policies_reviewed": len(observed),
            "findings": len(findings),
            "high": counts["high"],
            "medium": counts["medium"],
            "low": counts["low"],
            "missing_policies": len(drift["missing"]),
            "unexpected_policies": len(drift["unexpected"]),
            "changed_policies": len(drift["changed"]),
        },
        "findings": [
            {**finding, "remediation": REMEDIATION.get(finding["rule"], "Review policy scope.")}
            for finding in findings
        ],
        "drift": drift,
    }


def render_html(assessment):
    """Escape all dynamic content; render an offline, dependency-free report."""
    summary = assessment["summary"]
    cells = "".join(
        '<div class="metric"><span>' + escape(label.replace("_", " ").title()) +
        '</span><strong>' + str(value) + '</strong></div>'
        for label, value in summary.items()
    )
    rows = "".join(
        "<tr><td>" + escape(str(finding["id"])) + "</td><td>" +
        escape(finding["severity"].upper()) + "</td><td>" +
        escape(finding["rule"]) + "</td><td>" +
        escape(finding["detail"]) + "</td><td>" +
        escape(finding["remediation"]) + "</td></tr>"
        for finding in assessment["findings"]
    )
    if not rows:
        rows = '<tr><td colspan="5">No findings in the supplied sample.</td></tr>'
    drift = escape(json.dumps(assessment["drift"], indent=2))
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Firewall Security Assessment</title>
<style>
:root{font-family:system-ui,-apple-system,sans-serif;color:#182538;background:#f3f6fb}
body{max-width:1100px;margin:36px auto;padding:0 22px}
header{border-bottom:3px solid #1d4ed8;padding-bottom:18px;margin-bottom:26px}
h1{margin:0 0 8px}p{line-height:1.5;color:#526179}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:22px 0}
.metric{background:white;border:1px solid #dae2ee;border-radius:10px;padding:16px}
.metric span{display:block;font-size:13px;color:#526179}
.metric strong{font-size:30px;display:block;margin-top:6px}
section{background:white;border:1px solid #dae2ee;border-radius:12px;padding:20px;margin:20px 0;overflow:auto}
table{border-collapse:collapse;width:100%;font-size:14px}
th,td{text-align:left;padding:12px;border-bottom:1px solid #e5eaf2;vertical-align:top}
th{background:#edf3ff}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f7fb;padding:16px;border-radius:8px}
footer{font-size:13px;color:#526179;padding:16px 0}
</style></head><body>
<header><h1>Firewall Security Assessment</h1>
<p>Offline policy analysis · Synthetic sample data · No firewall connectivity</p></header>
<h2>Assessment overview</h2><div class="grid">""" + cells + """</div>
<section><h2>Policy risk findings</h2>
<table><thead><tr><th>Policy</th><th>Severity</th><th>Rule</th><th>Finding</th><th>Recommended action</th></tr></thead>
<tbody>""" + rows + """</tbody></table></section>
<section><h2>Configuration drift</h2><pre>""" + drift + """</pre></section>
<footer>Reference assessment only. Simplified policy model; no device changes or live data.</footer>
</body></html>"""


def main():
    parser = argparse.ArgumentParser(description="Offline firewall security HTML report")
    parser.add_argument("--baseline", type=Path, default=Path("examples/baseline.json"))
    parser.add_argument("--observed", type=Path, default=Path("examples/observed.json"))
    parser.add_argument("--output", type=Path, default=Path("output/security-assessment.html"))
    args = parser.parse_args()
    baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
    observed = json.loads(args.observed.read_text(encoding="utf-8"))
    report = render_html(assess(baseline, observed))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report, encoding="utf-8")
    print(f"Created offline security report: {args.output}")


if __name__ == "__main__":
    main()
