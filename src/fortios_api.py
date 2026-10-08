"""Read-only FortiOS policy inventory adapter.

Never sends POST, PUT, PATCH or DELETE. Do not disable TLS verification.
"""
import json
import os
from urllib.parse import urlparse

import requests


def fetch_firewall_policies(base_url=None, token=None, vdom="root", session=None):
    """Retrieve FortiOS firewall policies from an authorized device.

    Returns raw policy dictionaries; FortiOS objects require separate resolution
    before they can be evaluated by the simplified offline risk engine.
    """
    base_url = (base_url or os.environ["FORTIOS_URL"]).rstrip("/")
    token = token or os.environ["FORTIOS_TOKEN"]
    parsed = urlparse(base_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
        raise ValueError("FORTIOS_URL must be an HTTPS origin without credentials or paths")
    if not isinstance(vdom, str) or not vdom or any(char in vdom for char in "\r\n"):
        raise ValueError("Invalid VDOM")
    client = session if session is not None else requests.Session()
    response = client.get(
        base_url + "/api/v2/cmdb/firewall/policy",
        params={"vdom": vdom},
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        timeout=20,
        verify=True,
        allow_redirects=False,
    )
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        raise ValueError("Unexpected FortiOS API response")
    if payload.get("status") not in (None, "success"):
        raise ValueError("FortiOS API returned unsuccessful status")
    return payload["results"]


def summarize_raw_policies(policies):
    """Safely summarize FortiOS rules without interpreting unresolved objects."""
    return [
        {
            "policyid": policy.get("policyid"),
            "name": policy.get("name", ""),
            "action": policy.get("action"),
            "status": policy.get("status"),
            "srcaddr": [item.get("name") for item in policy.get("srcaddr", []) if isinstance(item, dict)],
            "dstaddr": [item.get("name") for item in policy.get("dstaddr", []) if isinstance(item, dict)],
            "service": [item.get("name") for item in policy.get("service", []) if isinstance(item, dict)],
            "logtraffic": policy.get("logtraffic"),
        }
        for policy in policies
    ]


def main():
    """Explicit live read-only request; outputs potentially sensitive inventory locally."""
    import argparse
    parser = argparse.ArgumentParser(description="Read-only FortiOS firewall policy inventory")
    parser.add_argument("--vdom", default="root")
    parser.add_argument("--output", default="output/fortios-policies.json")
    args = parser.parse_args()
    from pathlib import Path
    output = Path(args.output)
    policies = fetch_firewall_policies(vdom=args.vdom)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(summarize_raw_policies(policies), indent=2), encoding="utf-8")
    try:
        output.chmod(0o600)
    except OSError:
        pass
    print(f"Read {len(policies)} policies; wrote local summary to {output}")


if __name__ == "__main__":
    main()
