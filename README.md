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

## Read-only FortiOS REST API integration

The optional adapter retrieves raw FortiOS policy objects via `GET /api/v2/cmdb/firewall/policy` and writes a local JSON summary. It does not send write requests or automatically convert address and service objects into CIDRs.

```bash
python -m pip install -r requirements.txt
export FORTIOS_URL="https://fortigate.example.test"
export FORTIOS_TOKEN="your-read-only-api-token"
python -m src.fortios_api --vdom root
```

The default output is `output/fortios-policies.json`, excluded by `.gitignore`. Treat exported policies as sensitive. Use a least-privilege REST API administrator with read-only firewall policy access and a valid TLS certificate; certificate verification is enforced. The offline policy auditor operates on a separate simplified schema; raw FortiOS address/service object names are **not** treated as fully resolved risk findings.

The API adapter has mocked tests and does not require device access in CI.

## Offline FortiOS object resolution

`src/object_resolution.py` expands nested firewall address groups and service groups using supplied FortiOS-style object dictionaries. Supported addresses are IPv4/IPv6 `ipmask` objects; unsupported address types (including FQDN and IP ranges), unknown objects, empty groups, duplicate names, and recursive groups raise explicit errors rather than silently producing incomplete findings.

`normalize_fortios_policy(...)` converts a policy and its supplied object collections to the simplified model used by `src.audit.audit_policies`. Only the literal `ALL` service is treated as all services; named custom services are not assumed to represent their port/protocol definitions. This is **offline resolution only**: the read-only live API adapter currently retrieves policies but does not fetch address/service object inventories or perform automatic live policy assessment. NAT, zones, policy ordering, schedules, IPv6 policy tables, and complex FortiOS address types remain out of scope.
