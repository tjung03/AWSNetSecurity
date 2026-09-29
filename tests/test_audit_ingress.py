"""Check world IPv4/IPv6 sources and avoid flagging restricted rules."""

import unittest

from audit_ingress import inspect_groups


class IngressReviewTests(unittest.TestCase):
    def test_world_sources_and_ranges(self):
        data = {"SecurityGroups": [{"GroupId": "sg-example", "IpPermissions": [
            {"IpProtocol": "6", "FromPort": 20, "ToPort": 23,
             "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
             "Ipv6Ranges": [{"CidrIpv6": "::/0"}]},
            {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        ]}]}
        self.assertEqual(inspect_groups(data), [
            ("sg-example", "0.0.0.0/0", "all protocols"),
            ("sg-example", "0.0.0.0/0", "tcp/22"),
            ("sg-example", "::/0", "tcp/22"),
        ])

    def test_restricted_and_unrelated_rules(self):
        data = {"SecurityGroups": [{"GroupId": "sg-example", "IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
             "IpRanges": [{"CidrIp": "10.0.0.0/24"}]},
            {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80,
             "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        ]}]}
        self.assertEqual(inspect_groups(data), [])

    def test_malformed_range_is_not_silently_ignored(self):
        data = {"SecurityGroups": [{"GroupId": "sg-example", "IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
             "IpRanges": None},
        ]}]}
        with self.assertRaisesRegex(ValueError, "IpRanges must be a list"):
            inspect_groups(data)

        restricted = {"SecurityGroups": [{"GroupId": "sg-example", "IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 22,
             "IpRanges": [{"CidrIp": "10.0.0.0/24"}]},
        ]}]}
        with self.assertRaisesRegex(ValueError, "valid FromPort and ToPort"):
            inspect_groups(restricted)

    def test_malformed_protocol_and_cidr_version(self):
        missing_protocol = {"SecurityGroups": [{"GroupId": "sg-example", "IpPermissions": [
            {"IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        ]}]}
        with self.assertRaisesRegex(ValueError, "IpProtocol string"):
            inspect_groups(missing_protocol)

        wrong_version = {"SecurityGroups": [{"GroupId": "sg-example", "IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
             "IpRanges": [{"CidrIp": "::/0"}]},
        ]}]}
        with self.assertRaisesRegex(ValueError, "wrong IP version"):
            inspect_groups(wrong_version)

        invalid_port = {"SecurityGroups": [{"GroupId": "sg-example", "IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 65536,
             "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        ]}]}
        with self.assertRaisesRegex(ValueError, "valid FromPort and ToPort"):
            inspect_groups(invalid_port)


if __name__ == "__main__":
    unittest.main()
