"""Tests for -n target expansion: single IP/host, CIDR, comma lists, files."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pysnaffler.cli import expand_targets


class TestExpandTargets(unittest.TestCase):
    def test_single_ip(self):
        self.assertEqual(expand_targets(["10.0.0.5"]), ["10.0.0.5"])

    def test_hostnames_kept_verbatim(self):
        self.assertEqual(expand_targets(["fs01.corp.local", "FS01"]),
                         ["fs01.corp.local", "FS01"])

    def test_cidr_30_expands_to_two_usable_hosts(self):
        self.assertEqual(expand_targets(["10.0.0.0/30"]), ["10.0.0.1", "10.0.0.2"])

    def test_cidr_32_is_the_single_host(self):
        self.assertEqual(expand_targets(["10.0.0.9/32"]), ["10.0.0.9"])

    def test_cidr_31_takes_both(self):
        self.assertEqual(expand_targets(["10.0.0.8/31"]), ["10.0.0.8", "10.0.0.9"])

    def test_24_has_254_hosts(self):
        self.assertEqual(len(expand_targets(["192.168.1.0/24"])), 254)

    def test_comments_and_blanks_ignored(self):
        self.assertEqual(expand_targets(["# header", "", "  ", "10.0.0.1"]),
                         ["10.0.0.1"])

    def test_dedup_preserves_order(self):
        self.assertEqual(
            expand_targets(["10.0.0.1", "10.0.0.0/30", "fs01", "fs01"]),
            ["10.0.0.1", "10.0.0.2", "fs01"])

    def test_ipv6_cidr(self):
        # small v6 range still expands
        hosts = expand_targets(["2001:db8::/126"])
        self.assertTrue(all(":" in h for h in hosts))
        self.assertGreaterEqual(len(hosts), 2)

    def test_oversized_cidr_rejected(self):
        with self.assertRaises(ValueError):
            expand_targets(["10.0.0.0/6"])

    def test_hostname_with_slash_is_not_a_cidr(self):
        # a stray slash that isn't a valid network is kept as a literal token
        self.assertEqual(expand_targets(["weird/name"]), ["weird/name"])

    def test_mixed_file_style_lines(self):
        lines = ["10.0.0.10", "10.0.0.16/30", "dc01.corp.local", "# note"]
        self.assertEqual(
            expand_targets(lines),
            ["10.0.0.10", "10.0.0.17", "10.0.0.18", "dc01.corp.local"])


if __name__ == "__main__":
    unittest.main()
