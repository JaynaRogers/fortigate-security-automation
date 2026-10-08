"""Offline FortiOS address/service object resolution with fail-closed behavior."""
import ipaddress


class ResolutionError(ValueError):
    """Object cannot be safely interpreted."""


def _index(records):
    indexed = {}
    for item in records:
        name = item.get("name")
        if not isinstance(name, str) or not name or name in indexed:
            raise ResolutionError("Missing or duplicate object name")
        indexed[name] = item
    return indexed


def _names(members):
    if not isinstance(members, list):
        raise ResolutionError("Group members must be a list")
    names = []
    for item in members:
        name = item.get("name") if isinstance(item, dict) else item
        if not isinstance(name, str) or not name:
            raise ResolutionError("Invalid group member")
        names.append(name)
    return names


def _address(record):
    kind = record.get("type", "ipmask")
    if kind != "ipmask":
        raise ResolutionError(f"Unsupported address type: {kind}")
    subnet = record.get("subnet")
    try:
        if isinstance(subnet, str):
            parts = subnet.split()
            if len(parts) == 2:
                return str(ipaddress.ip_network((parts[0], parts[1]), strict=False))
            return str(ipaddress.ip_network(subnet, strict=False))
        if isinstance(subnet, (list, tuple)) and len(subnet) == 2:
            return str(ipaddress.ip_network((subnet[0], subnet[1]), strict=False))
    except (ValueError, TypeError) as exc:
        raise ResolutionError(f"Invalid address subnet: {subnet}") from exc
    raise ResolutionError("Unsupported address subnet")


def resolve_addresses(names, addresses, groups):
    """Expand IPv4/IPv6 ipmask objects and nested address groups."""
    objects, group_index = _index(addresses), _index(groups)

    def expand(name, stack):
        if name in stack:
            raise ResolutionError("Address group cycle: " + " -> ".join((*stack, name)))
        if name == "all":
            return ["0.0.0.0/0"]
        if name in objects:
            return [_address(objects[name])]
        if name in group_index:
            members = _names(group_index[name].get("member", []))
            if not members:
                raise ResolutionError("Empty address group: " + name)
            return [item for member in members for item in expand(member, (*stack, name))]
        raise ResolutionError("Unresolved address object: " + name)

    return sorted(set(item for name in _names(names) for item in expand(name, ()))) 


def resolve_services(names, services, groups):
    """Resolve named services and groups; only literal ALL means all protocols.

    Specific services remain named; port-range semantics are not interpreted.
    """
    objects, group_index = _index(services), _index(groups)

    def expand(name, stack):
        if name in stack:
            raise ResolutionError("Service group cycle: " + " -> ".join((*stack, name)))
        if name == "ALL":
            return ["ALL"]
        if name in objects:
            return [name]
        if name in group_index:
            members = _names(group_index[name].get("member", []))
            if not members:
                raise ResolutionError("Empty service group: " + name)
            return [item for member in members for item in expand(member, (*stack, name))]
        raise ResolutionError("Unresolved service object: " + name)

    return sorted(set(item for name in _names(names) for item in expand(name, ())))


def normalize_fortios_policy(policy, addresses, address_groups, services, service_groups):
    """Map a FortiOS policy to the offline auditor's simplified model."""
    action = policy.get("action")
    if action not in ("accept", "deny"):
        raise ResolutionError("Unsupported policy action")
    logging = policy.get("logtraffic") in ("all", "utm")
    return {
        "id": policy["policyid"],
        "name": policy.get("name", ""),
        "source": resolve_addresses(policy.get("srcaddr", []), addresses, address_groups),
        "destination": resolve_addresses(policy.get("dstaddr", []), addresses, address_groups),
        "service": resolve_services(policy.get("service", []), services, service_groups),
        "action": action,
        "logging": logging,
        "enabled": policy.get("status", "enable") == "enable",
    }
