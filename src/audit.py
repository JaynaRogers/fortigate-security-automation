"""Offline FortiGate-style policy audit and drift analysis; no device connectivity."""
import ipaddress
import json
from pathlib import Path


def _networks(values):
    if not isinstance(values, list) or not values:
        raise ValueError('Source/destination must be a nonempty list')
    return [ipaddress.ip_network(value, strict=False) for value in values]


def validate_policy(policy):
    required = {'id', 'name', 'source', 'destination', 'service', 'action', 'logging', 'enabled'}
    if not required.issubset(policy):
        raise ValueError(f'Missing policy fields: {sorted(required - set(policy))}')
    _networks(policy['source'])
    _networks(policy['destination'])
    if policy['action'] not in {'accept', 'deny'}:
        raise ValueError('Unsupported policy action')
    if not isinstance(policy['service'], list) or not policy['service']:
        raise ValueError('Service must be a nonempty list')
    if not isinstance(policy['logging'], bool) or not isinstance(policy['enabled'], bool):
        raise ValueError('Logging and enabled must be boolean')
    return policy


def audit_policies(policies):
    findings = []
    ids = set()
    for policy in policies:
        validate_policy(policy)
        ident = policy['id']
        if ident in ids:
            raise ValueError(f'Duplicate policy ID: {ident}')
        ids.add(ident)
        if not policy['enabled']:
            continue
        src = _networks(policy['source'])
        dst = _networks(policy['destination'])
        if policy['action'] == 'accept':
            if any(network.prefixlen == 0 for network in src) and any(network.prefixlen == 0 for network in dst):
                findings.append({'id': ident, 'severity': 'high', 'rule': 'ANY_TO_ANY', 'detail': 'Broad allow from any source to any destination'})
            if 'ALL' in policy['service']:
                findings.append({'id': ident, 'severity': 'medium', 'rule': 'ALL_SERVICES', 'detail': 'Allow rule includes all services'})
            if not policy['logging']:
                findings.append({'id': ident, 'severity': 'medium', 'rule': 'NO_LOGGING', 'detail': 'Allow rule does not log traffic'})
    return sorted(findings, key=lambda item: (item['id'], item['rule']))


def compare_policies(expected, actual):
    def indexed(items):
        result = {}
        for item in items:
            validate_policy(item)
            if item['id'] in result:
                raise ValueError('Duplicate policy ID')
            result[item['id']] = item
        return result
    baseline, observed = indexed(expected), indexed(actual)
    return {
        'missing': sorted(set(baseline) - set(observed)),
        'unexpected': sorted(set(observed) - set(baseline)),
        'changed': [
            {'id': ident, 'fields': {field: {'expected': baseline[ident][field], 'actual': observed[ident][field]}
                                     for field in sorted(baseline[ident]) if baseline[ident][field] != observed[ident].get(field)}}
            for ident in sorted(set(baseline) & set(observed)) if baseline[ident] != observed[ident]
        ],
    }


def main():
    base = Path(__file__).resolve().parent.parent / 'examples'
    expected = json.loads((base / 'baseline.json').read_text())
    actual = json.loads((base / 'observed.json').read_text())
    print(json.dumps({'findings': audit_policies(actual), 'drift': compare_policies(expected, actual)}, indent=2))


if __name__ == '__main__':
    main()
