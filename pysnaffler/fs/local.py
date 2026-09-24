"""
Local filesystem backend, used when -i points at a path that is not a UNC
share. Handy for testing rules against a directory (e.g. upstream's
snafflertest/ corpus) without a domain.
"""
import os
from datetime import datetime

from .base import (DirectoryNotFoundError, FileInfo, FileSystem, IOError_,
                   UnauthorizedAccessError)


class LocalFileSystem(FileSystem):
    def directory_exists(self, path):
        return os.path.isdir(path)

    def list_directory(self, path):
        files, dirs = [], []
        try:
            with os.scandir(path) as it:
                for entry in it:
                    try:
                        # follow symlinks: .NET's Directory.GetFiles /
                        # GetDirectories resolve reparse points and symlinks, so
                        # a symlinked file or a junctioned directory is scanned.
                        if entry.is_dir(follow_symlinks=True):
                            dirs.append(entry.path)
                        elif entry.is_file(follow_symlinks=True):
                            st = entry.stat(follow_symlinks=True)
                            files.append(FileInfo(
                                self, entry.path,
                                length=st.st_size,
                                last_write_time=datetime.fromtimestamp(st.st_mtime)))
                    except OSError:
                        # a broken symlink resolves to nothing - skip it
                        continue
        except PermissionError as exc:
            raise UnauthorizedAccessError(str(exc))
        except FileNotFoundError as exc:
            raise DirectoryNotFoundError(str(exc))
        except OSError as exc:
            raise IOError_(str(exc))
        return files, dirs

    def get_file_info(self, path):
        try:
            st = os.stat(path)
        except PermissionError as exc:
            raise UnauthorizedAccessError(str(exc))
        except FileNotFoundError:
            return FileInfo(self, path, exists=False)
        except OSError as exc:
            raise IOError_(str(exc))
        return FileInfo(self, path, length=st.st_size,
                        last_write_time=datetime.fromtimestamp(st.st_mtime))

    def read_all_bytes(self, path):
        try:
            with open(path, "rb") as fh:
                return fh.read()
        except PermissionError as exc:
            raise UnauthorizedAccessError(str(exc))
        except IsADirectoryError as exc:
            raise IOError_(str(exc))
        except OSError as exc:
            raise IOError_(str(exc))

    def can_read(self, path):
        try:
            with open(path, "rb"):
                return True
        except Exception:
            return False
