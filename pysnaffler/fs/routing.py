"""
Dispatches filesystem calls to the SMB or local backend based on the path, so a
single run can mix UNC shares and local directories.
"""
from .base import FileSystem
from .local import LocalFileSystem


class RoutingFileSystem(FileSystem):
    def __init__(self, smb_fs=None, local_fs=None):
        self.smb = smb_fs
        self.local = local_fs or LocalFileSystem()

    def _for(self, path):
        if path.startswith("\\\\"):
            if self.smb is None:
                raise RuntimeError("SMB target given but no credentials configured")
            return self.smb
        return self.local

    def directory_exists(self, path):
        return self._for(path).directory_exists(path)

    def list_directory(self, path):
        return self._for(path).list_directory(path)

    def get_file_info(self, path):
        return self._for(path).get_file_info(path)

    def read_all_bytes(self, path):
        return self._for(path).read_all_bytes(path)

    def can_read(self, path):
        return self._for(path).can_read(path)

    def close(self):
        if self.smb is not None:
            self.smb.close()
