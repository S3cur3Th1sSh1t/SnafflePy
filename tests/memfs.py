"""An in-memory filesystem using UNC paths, for tests."""
import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pysnaffler.fs.base import DirectoryNotFoundError, FileInfo, FileSystem


class MemoryFileSystem(FileSystem):
    def __init__(self, files=None):
        # path -> bytes
        self.files = {}
        self.unreadable = set()
        for path, content in (files or {}).items():
            self.add(path, content)

    def add(self, path, content=b"", mtime=None):
        if isinstance(content, str):
            content = content.encode("utf-8")
        self.files[path] = (content, mtime or datetime(2021, 6, 1, 12, 0, 0))
        return self

    def _children(self, path):
        prefix = path.rstrip("\\") + "\\"
        files, dirs = [], set()
        for full in self.files:
            if not full.startswith(prefix):
                continue
            rest = full[len(prefix):]
            if "\\" in rest:
                dirs.add(prefix + rest.split("\\")[0])
            else:
                files.append(full)
        return files, sorted(dirs)

    def directory_exists(self, path):
        files, dirs = self._children(path)
        return bool(files or dirs)

    def list_directory(self, path):
        files, dirs = self._children(path)
        if not files and not dirs:
            raise DirectoryNotFoundError(path)
        infos = []
        for full in sorted(files):
            content, mtime = self.files[full]
            infos.append(FileInfo(self, full, length=len(content), last_write_time=mtime))
        return infos, dirs

    def get_file_info(self, path):
        if path not in self.files:
            return FileInfo(self, path, exists=False)
        content, mtime = self.files[path]
        return FileInfo(self, path, length=len(content), last_write_time=mtime)

    def read_all_bytes(self, path):
        if path not in self.files:
            raise DirectoryNotFoundError(path)
        return self.files[path][0]

    def can_read(self, path):
        return path in self.files and path not in self.unreadable
