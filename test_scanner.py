import unittest
from scanner import pab_is_complete, sg_exposed_ports


class Tests(unittest.TestCase):
    def test_pab(self):
        full = dict(BlockPublicAcls=True, IgnorePublicAcls=True, BlockPublicPolicy=True, RestrictPublicBuckets=True)
        self.assertTrue(pab_is_complete(full))
        self.assertFalse(pab_is_complete({**full, "BlockPublicPolicy": False}))
        self.assertFalse(pab_is_complete(None))

    def test_sg_ssh_open(self):
        perms = [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
        self.assertEqual(sg_exposed_ports(perms), {22: "SSH"})

    def test_sg_private_ok(self):
        perms = [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}]
        self.assertEqual(sg_exposed_ports(perms), {})

    def test_sg_all_traffic(self):
        perms = [{"IpProtocol": "-1", "IpRanges": [], "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}]
        self.assertEqual(sg_exposed_ports(perms), {0: "ALL TRAFFIC"})


if __name__ == "__main__":
    unittest.main()
