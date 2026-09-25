"""
The timestamp Snaffler reports is the file's LastWriteTime.

Two ways that went wrong, both pinned here:

1. impacket's SharedFile takes (ctime, atime, wtime, mtime) where the last one
   is LastChangeTime, so get_mtime() is the attribute-change time and get_wtime()
   is the write time.
2. get_*_epoch() masks the low 20 bits off the tick count, losing up to 0.105s,
   so a file written just after a second boundary logged a second early.
"""
import os
import sys
import unittest
from contextlib import contextmanager
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from impacket.smb import SharedFile

from pysnaffler import dotnet
from pysnaffler.fs.smb import SmbFileSystem, filetime_to_datetime

WRITE_TIME = datetime(2021, 6, 1, 12, 0, 0)
CHANGE_TIME = datetime(2024, 11, 15, 8, 30, 0)
ATTR_DIRECTORY = 0x10


def to_filetime(dt):
    """A local naive datetime as 100ns ticks since 1601.

    Whole seconds and microseconds are combined with integer arithmetic; a
    float FILETIME only carries ~16 digits and would lose a couple of ticks.
    """
    whole = int(dt.replace(microsecond=0).timestamp())
    return (whole + 11644473600) * 10_000_000 + dt.microsecond * 10


def shared_file(name, write_time, change_time, size=1234, attribs=0x80):
    return SharedFile(
        to_filetime(datetime(2000, 1, 1)),   # ctime
        to_filetime(datetime(2000, 1, 1)),   # atime
        to_filetime(write_time),             # wtime - LastWriteTime
        to_filetime(change_time),            # mtime - LastChangeTime
        size, size, attribs, name, name)


class FakeConnection:
    def __init__(self, entries):
        self.entries = entries

    def listPath(self, share, search):
        return self.entries


class FakePool:
    def __init__(self, entries):
        self.conn = FakeConnection(entries)

    @contextmanager
    def connection(self, host):
        yield self.conn


class SmbTimestampTests(unittest.TestCase):
    def setUp(self):
        self.entries = [shared_file("secrets.txt", WRITE_TIME, CHANGE_TIME)]
        self.fs = SmbFileSystem(FakePool(self.entries))

    def assert_is_write_time(self, actual):
        self.assertEqual(actual, WRITE_TIME,
                         "expected LastWriteTime, got %s (LastChangeTime is %s)"
                         % (actual, CHANGE_TIME))

    def test_list_directory_uses_write_time(self):
        files, _dirs = self.fs.list_directory("\\\\FS01\\Finance$\\deploy")
        self.assertEqual(len(files), 1)
        self.assert_is_write_time(files[0].LastWriteTime)

    def test_get_file_info_uses_write_time(self):
        info = self.fs.get_file_info("\\\\FS01\\Finance$\\secrets.txt")
        self.assert_is_write_time(info.LastWriteTime)

    def test_directories_are_split_out(self):
        self.entries.append(
            shared_file("subdir", WRITE_TIME, CHANGE_TIME, attribs=ATTR_DIRECTORY))
        files, dirs = self.fs.list_directory("\\\\FS01\\Finance$")
        self.assertEqual([f.FullName for f in files],
                         ["\\\\FS01\\Finance$\\secrets.txt"])
        self.assertEqual(dirs, ["\\\\FS01\\Finance$\\subdir"])


class FiletimeConversionTests(unittest.TestCase):
    def test_second_boundary_is_not_dragged_backwards(self):
        """The case impacket's 20-bit mask used to get wrong."""
        exact = datetime(2020, 1, 1, 0, 0, 0)
        self.assertEqual(filetime_to_datetime(to_filetime(exact)), exact)
        self.assertEqual(dotnet.format_u(exact), "2020-01-01 00:00:00Z")

    def test_sub_second_precision_survives(self):
        written = datetime(2023, 3, 4, 5, 6, 7, 123456)
        self.assertEqual(filetime_to_datetime(to_filetime(written)), written)

    def test_zeroed_filetime_falls_back_to_the_epoch(self):
        self.assertEqual(filetime_to_datetime(0), datetime.fromtimestamp(0))


if __name__ == "__main__":
    unittest.main()
