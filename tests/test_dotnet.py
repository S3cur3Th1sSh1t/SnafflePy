"""
Tests for the .NET semantics the output format depends on.

Expected values here were taken from the behaviour of the real .NET APIs, not
from our implementation, so these catch drift in the places where Python's
stdlib disagrees with .NET.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pysnaffler import dotnet


class TestGetExtension(unittest.TestCase):
    def test_normal(self):
        self.assertEqual(dotnet.get_extension("thing.kdbx"), ".kdbx")
        self.assertEqual(dotnet.get_extension(r"\\host\share\a\b.ps1"), ".ps1")

    def test_dotfile_keeps_whole_name(self):
        # os.path.splitext would say '' here; .NET says '.bashrc'
        self.assertEqual(dotnet.get_extension(".bashrc"), ".bashrc")
        self.assertEqual(dotnet.get_extension(r"C:\users\bob\.npmrc"), ".npmrc")

    def test_trailing_dot_is_empty(self):
        self.assertEqual(dotnet.get_extension("file."), "")

    def test_no_extension(self):
        self.assertEqual(dotnet.get_extension("shadow"), "")
        self.assertEqual(dotnet.get_extension(r"\\host\share\passwd"), "")

    def test_dot_in_directory_only(self):
        self.assertEqual(dotnet.get_extension(r"\\host\share.old\passwd"), "")

    def test_double_extension(self):
        self.assertEqual(dotnet.get_extension("thing.kdbx.bak"), ".bak")


class TestGetFileName(unittest.TestCase):
    def test_unc(self):
        self.assertEqual(dotnet.get_file_name(r"\\host\share\dir\f.txt"), "f.txt")

    def test_forward_slash(self):
        self.assertEqual(dotnet.get_file_name("/home/user/f.txt"), "f.txt")

    def test_volume_colon(self):
        self.assertEqual(dotnet.get_file_name(r"C:f.txt"), "f.txt")

    def test_bare(self):
        self.assertEqual(dotnet.get_file_name("f.txt"), "f.txt")

    def test_without_extension(self):
        self.assertEqual(
            dotnet.get_file_name_without_extension(r"\\h\s\cert.pfx"), "cert")
        self.assertEqual(
            dotnet.get_file_name_without_extension(".bashrc"), "")


class TestRegexEscape(unittest.TestCase):
    """.NET escapes ' ', '#' and ')' but NOT ']' or '}'; re.escape differs."""

    def test_whitespace(self):
        self.assertEqual(dotnet.regex_escape("a b"), r"a\ b")
        self.assertEqual(dotnet.regex_escape("a\tb"), r"a\tb")
        self.assertEqual(dotnet.regex_escape("a\nb"), r"a\nb")
        self.assertEqual(dotnet.regex_escape("a\r\nb"), r"a\r\nb")
        self.assertEqual(dotnet.regex_escape("a\fb"), r"a\fb")

    def test_metachars(self):
        self.assertEqual(dotnet.regex_escape("a#b"), r"a\#b")
        self.assertEqual(dotnet.regex_escape("a$b"), r"a\$b")
        self.assertEqual(dotnet.regex_escape("(x)"), r"\(x\)")
        self.assertEqual(dotnet.regex_escape("a*b"), r"a\*b")
        self.assertEqual(dotnet.regex_escape("a+b"), r"a\+b")
        self.assertEqual(dotnet.regex_escape("a.b"), r"a\.b")
        self.assertEqual(dotnet.regex_escape("a?b"), r"a\?b")
        self.assertEqual(dotnet.regex_escape("a[b"), r"a\[b")
        self.assertEqual(dotnet.regex_escape("a\\b"), "a\\\\b")
        self.assertEqual(dotnet.regex_escape("a^b"), r"a\^b")
        self.assertEqual(dotnet.regex_escape("a{b"), r"a\{b")
        self.assertEqual(dotnet.regex_escape("a|b"), r"a\|b")

    def test_not_escaped(self):
        # the ones .NET deliberately leaves alone
        self.assertEqual(dotnet.regex_escape("a]b"), "a]b")
        self.assertEqual(dotnet.regex_escape("a}b"), "a}b")
        self.assertEqual(dotnet.regex_escape("a-b"), "a-b")
        self.assertEqual(dotnet.regex_escape("a/b"), "a/b")
        self.assertEqual(dotnet.regex_escape("a!b"), "a!b")
        self.assertEqual(dotnet.regex_escape('a"b'), 'a"b')
        self.assertEqual(dotnet.regex_escape("a'b"), "a'b")
        self.assertEqual(dotnet.regex_escape("a:b"), "a:b")
        self.assertEqual(dotnet.regex_escape("a=b"), "a=b")
        self.assertEqual(dotnet.regex_escape("a<b>"), "a<b>")

    def test_realistic_connection_string(self):
        src = 'password="hunter2"; server=(local)'
        self.assertEqual(dotnet.regex_escape(src),
                         'password="hunter2";\\ server=\\(local\\)')

    def test_empty(self):
        self.assertEqual(dotnet.regex_escape(""), "")


class TestBytesToString(unittest.TestCase):
    def test_zero(self):
        self.assertEqual(dotnet.bytes_to_string(0), "0B")

    def test_bytes(self):
        self.assertEqual(dotnet.bytes_to_string(1), "1B")
        self.assertEqual(dotnet.bytes_to_string(1023), "1023B")

    def test_kilobytes(self):
        self.assertEqual(dotnet.bytes_to_string(1024), "1kB")
        self.assertEqual(dotnet.bytes_to_string(1536), "1.5kB")
        self.assertEqual(dotnet.bytes_to_string(3456), "3.4kB")

    def test_megabytes(self):
        self.assertEqual(dotnet.bytes_to_string(1024 * 1024), "1MB")
        self.assertEqual(dotnet.bytes_to_string(1500000), "1.4MB")

    def test_gigabytes(self):
        self.assertEqual(dotnet.bytes_to_string(1024 ** 3), "1GB")

    def test_integral_values_have_no_decimal_point(self):
        # C# double.ToString() prints 1, not 1.0
        self.assertNotIn(".0", dotnet.bytes_to_string(1024))


class TestFormatU(unittest.TestCase):
    def test_format(self):
        from datetime import datetime
        self.assertEqual(dotnet.format_u(datetime(2009, 6, 15, 13, 45, 30)),
                         "2009-06-15 13:45:30Z")


class TestPathCombine(unittest.TestCase):
    def test_combine(self):
        self.assertEqual(dotnet.path_combine(r"\\h\s", "DataLib"), r"\\h\s\DataLib")
        self.assertEqual(dotnet.path_combine("\\\\h\\s\\", "DataLib"), r"\\h\s\DataLib")
        self.assertEqual(dotnet.path_combine(r"\\h\s", "FileLib", "ABCD", "ABCD1234"),
                         r"\\h\s\FileLib\ABCD\ABCD1234")


if __name__ == "__main__":
    unittest.main()
