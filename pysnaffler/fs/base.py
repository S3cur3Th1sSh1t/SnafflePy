"""
The filesystem abstraction Snaffler's classifiers run against.

The C# original just uses System.IO against UNC paths and lets the Windows SMB
redirector do the work. We have no redirector, so every FileInfo/Directory
operation is routed through one of these backends instead (impacket for SMB,
plain os for local paths).
"""
from datetime import datetime

from .. import dotnet


# -- exceptions mirroring the ones the C# catches by name --------------------
class UnauthorizedAccessError(Exception):
    pass


class DirectoryNotFoundError(Exception):
    pass


class FileNotFoundError_(Exception):
    pass


class IOError_(Exception):
    pass


class PathTooLongError(Exception):
    pass


class FileInfo:
    """System.IO.FileInfo.

    Size and mtime come from the directory listing that produced this object,
    so scanning a share costs one round trip per directory rather than one per
    file.
    """

    __slots__ = ("FullName", "Name", "Extension", "Length", "LastWriteTime",
                 "_fs", "_exists")

    def __init__(self, fs, full_name, length=0, last_write_time=None, exists=True):
        self._fs = fs
        self.FullName = full_name
        self.Name = dotnet.get_file_name(full_name)
        self.Extension = dotnet.get_extension(full_name)
        self.Length = length
        self.LastWriteTime = last_write_time or datetime.fromtimestamp(0)
        self._exists = exists

    @property
    def DirectoryName(self):
        return dotnet.get_directory_name(self.FullName)

    @property
    def Exists(self):
        return self._exists

    def read_all_bytes(self):
        return self._fs.read_all_bytes(self.FullName)

    def read_all_text(self):
        """File.ReadAllText - UTF-8 with BOM detection, like .NET's default."""
        data = self.read_all_bytes()
        return decode_text(data)

    def can_read(self):
        return self._fs.can_read(self.FullName)

    def __repr__(self):
        return "<FileInfo %s %d>" % (self.FullName, self.Length)


def decode_text(data):
    """Approximates File.ReadAllText's encoding detection.

    .NET sniffs a BOM and otherwise decodes UTF-8; invalid sequences become
    U+FFFD rather than throwing, which matters because Snaffler greps plenty of
    files that are not really text.
    """
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", errors="replace")
    if data.startswith(b"\xff\xfe\x00\x00"):
        return data[4:].decode("utf-32-le", errors="replace")
    if data.startswith(b"\x00\x00\xfe\xff"):
        return data[4:].decode("utf-32-be", errors="replace")
    if data.startswith(b"\xff\xfe"):
        return data[2:].decode("utf-16-le", errors="replace")
    if data.startswith(b"\xfe\xff"):
        return data[2:].decode("utf-16-be", errors="replace")
    return data.decode("utf-8", errors="replace")


class FileSystem:
    """Interface implemented by the SMB and local backends."""

    def directory_exists(self, path):
        raise NotImplementedError

    def list_directory(self, path):
        """Return (files, dirs): a list of FileInfo and a list of full paths."""
        raise NotImplementedError

    def get_files(self, path):
        return self.list_directory(path)[0]

    def get_file_info(self, path):
        raise NotImplementedError

    def read_all_bytes(self, path):
        raise NotImplementedError

    def can_read(self, path):
        raise NotImplementedError

    def close(self):
        pass
