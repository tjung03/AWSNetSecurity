"""Find broadly sourced remote-admin ingress in EC2 security-group JSON.

This is an offline rule review, not an internet-reachability test.
"""

import argparse
import ipaddress
import json
import sys
from pathlib import Path


ADMIN_PORTS = (22, 3389)


def world_sources(permission: dict) -> list[str]:
    """Return only the IPv4/IPv6 CIDRs that cover every address."""
    found = []
    for field, cidr_field, version in (
        ("IpRanges", "CidrIp", 4),
        ("Ipv6Ranges", "CidrIpv6", 6),
    ):
        entries = permission.get(field, [])
        if not isinstance(entries, list):
            raise ValueError(f"{field} must be a list")
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError(f"{field} entries must be objects")
            cidr = entry.get(cidr_field)
            if not isinstance(cidr, str):
                raise ValueError(f"{cidr_field} must be a string")
            try:
                network = ipaddress.ip_network(cidr)
            except ValueError as error:
                raise ValueError(f"invalid {cidr_field}: {cidr}") from error
            if network.version != version:
                raise ValueError(f"{cidr_field} has the wrong IP version: {cidr}")
            if network.prefixlen == 0:
                found.append(str(network))
    return found


def permission_targets(permission: dict) -> list[str]:
    """Identify broad protocol access or TCP ranges containing admin ports."""
    protocol = permission.get("IpProtocol")
    if not isinstance(protocol, str) or not protocol:
        raise ValueError("each IpPermissions entry needs an IpProtocol string")
    protocol = protocol.lower()
    if protocol == "-1":
        return ["all protocols"]
    if protocol not in ("tcp", "6"):
        return []
    start, end = permission.get("FromPort"), permission.get("ToPort")
    if (type(start) is not int or type(end) is not int
            or not 0 <= start <= end <= 65535):
        raise ValueError("TCP rules need a valid FromPort and ToPort")
    return [f"tcp/{port}" for port in ADMIN_PORTS if start <= port <= end]


def inspect_groups(data: dict) -> list[tuple[str, str, str]]:
    """Return group ID, world CIDR, and allowed protocol/port findings."""
    groups = data.get("SecurityGroups")
    if not isinstance(groups, list):
        raise ValueError("expected a SecurityGroups list")
    findings = []
    for group in groups:
        if not isinstance(group, dict) or not isinstance(group.get("GroupId"), str):
            raise ValueError("each security group needs a GroupId")
        permissions = group.get("IpPermissions")
        if not isinstance(permissions, list):
            raise ValueError("each security group needs an IpPermissions list")
        for permission in permissions:
            if not isinstance(permission, dict):
                raise ValueError("each IpPermissions entry must be an object")
            sources = world_sources(permission)
            targets = permission_targets(permission)
            for source in sources:
                for target in targets:
                    findings.append((group["GroupId"], source, target))
    return sorted(set(findings))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("json_file", type=Path, help="describe-security-groups JSON file")
    args = parser.parse_args(argv)
    try:
        data = json.loads(args.json_file.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("expected a JSON object")
        findings = inspect_groups(data)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        print(f"cannot inspect input: {error}", file=sys.stderr)
        return 2
    for group_id, source, target in findings:
        print(f"{group_id}: {source} permits {target}")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
