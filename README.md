# FortiGate Security Automation

Offline reference project demonstrating firewall policy risk detection, configuration drift analysis, and safe validation workflows. Built for network security engineering and architecture review.

## Capabilities

- Parse a **simplified FortiGate-style JSON policy model** (not a native FortiOS configuration parser).
- Detect broad any-to-any allow rules, all-service allows, and disabled logging on enabled allow rules.
- Compare expected and observed policy sets by policy ID, reporting missing, unexpected, and field-level differences.
- Reject malformed CIDRs and duplicate policy IDs.
- Test all behavior in CI without device access or credentials.

## Architecture

```text
Synthetic baseline policies ------\
                                    -> Validation -> Risk audit + drift report
Synthetic observed policies ------/
                                                |
                                                v
                                        Human review (no writes)
```

## Quick start

Requires Python 3.10+ and only the standard library.

```bash
python -m src.audit
python -m unittest discover -s tests -v
```

## Security and scope

This repository uses fictional policy data and RFC 5737 documentation IP ranges. It does not connect to FortiGate devices, change firewall policies, contain customer configurations, or store credentials. The policy schema is intentionally simplified; production FortiOS policy parsing would require address-group resolution, service objects, interface zones, policy ordering, schedules, VIP/NAT handling, and VDOM awareness. Findings are review signals, not proof of exploitability.

## Roadmap

1. Add a read-only FortiOS REST API adapter using local credentials and mocked API tests.
2. Resolve address/service groups and analyze rule order.
3. Add explicit exceptions with expiration and ownership metadata.
4. Export structured findings in SARIF or JSON for CI and security review.
5. Model controlled change proposals with approval and audit trails, without enabling device writes by default.

## License

MIT.
