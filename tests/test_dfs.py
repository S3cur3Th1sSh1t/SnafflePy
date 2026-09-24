"""
Tests for the DFS v1 "pkt" blob parser (MS-DFSNM), built by constructing the
binary structure the way AD stores it and checking what comes back out.
"""
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pysnaffler.ad.dfsfinder import DfsFinder


def _u16(value):
    return struct.pack("<H", value)


def _u32(value):
    return struct.pack("<I", value)


def _wstr(text):
    """A UTF-16LE string prefixed with its byte length."""
    encoded = text.encode("utf-16-le")
    return _u16(len(encoded)) + encoded


def build_target(server, share):
    body = (b"\x00" * 8            # timestamp
            + _u32(2)              # state
            + _u32(1)              # type
            + _wstr(server)
            + _wstr(share))
    return _u32(len(body) + 4) + body


def build_domainroot_blob(prefix, targets, comment=""):
    target_list = _u32(len(targets)) + b"".join(
        build_target(server, share) for server, share in targets)

    blob = (b"\xAA" * 16                    # root/link guid
            + _wstr(prefix)
            + _wstr(prefix.upper())         # short prefix
            + _u32(1)                       # type
            + _u32(1)                       # state
            + _wstr(comment)[0:2] + comment.encode("utf-16-le")
            + b"\x00" * 8                   # prefix timestamp
            + b"\x00" * 8                   # state timestamp
            + b"\x00" * 8                   # comment timestamp
            + _u32(3)                       # version
            + _u32(len(target_list)) + target_list
            + _u32(0)                       # reserved blob
            + _u32(300))                    # referral ttl
    return blob


def build_pkt(elements):
    out = _u32(1) + _u32(len(elements))
    for name, blob in elements:
        encoded_name = name.encode("utf-16-le")
        out += _u16(len(encoded_name)) + encoded_name + _u32(len(blob)) + blob
    return out


class TestParsePkt(unittest.TestCase):
    def test_single_namespace_single_target(self):
        blob = build_domainroot_blob(r"\corp.local\public", [("FS01", "reports$")])
        pkt = build_pkt([(r"\domainroot\public", blob)])

        shares = DfsFinder.parse_pkt(pkt)
        self.assertEqual(len(shares), 1)
        self.assertEqual(shares[0].RemoteServerName, "FS01")
        self.assertEqual(shares[0].RemoteShareName, "reports$")
        self.assertEqual(shares[0].DFSFolderPath, "public")

    def test_nested_namespace_path(self):
        blob = build_domainroot_blob(r"\corp.local\public\reports",
                                     [("FS01", "reports$")])
        pkt = build_pkt([(r"\domainroot\public", blob)])
        shares = DfsFinder.parse_pkt(pkt)
        self.assertEqual(shares[0].DFSFolderPath, r"public\reports")

    def test_multiple_targets_are_all_returned(self):
        blob = build_domainroot_blob(
            r"\corp.local\public",
            [("FS01", "reports$"), ("FS02", "reports$"), ("FS03", "other$")])
        pkt = build_pkt([(r"\domainroot\public", blob)])

        shares = DfsFinder.parse_pkt(pkt)
        self.assertEqual(len(shares), 3)
        self.assertEqual([s.RemoteServerName for s in shares],
                         ["FS01", "FS02", "FS03"])
        self.assertEqual({s.DFSFolderPath for s in shares}, {"public"})

    def test_multiple_namespaces(self):
        pkt = build_pkt([
            (r"\domainroot\public",
             build_domainroot_blob(r"\corp.local\public", [("FS01", "pub$")])),
            (r"\domainroot\finance",
             build_domainroot_blob(r"\corp.local\finance", [("FS02", "fin$")])),
        ])
        shares = DfsFinder.parse_pkt(pkt)
        self.assertEqual(len(shares), 2)
        self.assertEqual({s.DFSFolderPath for s in shares}, {"public", "finance"})

    def test_siteroot_elements_are_skipped(self):
        pkt = build_pkt([
            (r"\siteroot", b"\x00" * 32),
            (r"\domainroot\public",
             build_domainroot_blob(r"\corp.local\public", [("FS01", "pub$")])),
        ])
        shares = DfsFinder.parse_pkt(pkt)
        self.assertEqual(len(shares), 1)
        self.assertEqual(shares[0].RemoteServerName, "FS01")

    def test_comment_is_handled(self):
        blob = build_domainroot_blob(r"\corp.local\public", [("FS01", "pub$")],
                                     comment="a namespace comment")
        pkt = build_pkt([(r"\domainroot\public", blob)])
        shares = DfsFinder.parse_pkt(pkt)
        self.assertEqual(len(shares), 1)
        self.assertEqual(shares[0].RemoteShareName, "pub$")

    def test_truncated_blob_does_not_raise(self):
        blob = build_domainroot_blob(r"\corp.local\public", [("FS01", "pub$")])
        pkt = build_pkt([(r"\domainroot\public", blob)])
        # every truncation point must be survivable - this is attacker-adjacent
        # data and a crash here would kill the scan
        for cut in range(0, len(pkt)):
            try:
                DfsFinder.parse_pkt(pkt[:cut])
            except Exception as exc:
                self.fail("parse_pkt raised on truncation at %d: %r" % (cut, exc))

    def test_empty_blob(self):
        self.assertEqual(DfsFinder.parse_pkt(b""), [])


if __name__ == "__main__":
    unittest.main()
