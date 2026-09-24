"""
impacket-backed SMB filesystem and share enumeration.

This is what stands in for the Windows SMB redirector the C# relies on. UNC
paths (\\\\server\\share\\dir\\file) are parsed and served out of a pool of
SMBConnections, one checked out at a time per worker because impacket's
SMBConnection is not thread safe.
"""
import threading
from contextlib import contextmanager
from datetime import datetime, timezone

from impacket.smbconnection import SMBConnection, SessionError

from .base import (DirectoryNotFoundError, FileInfo, FileSystem, IOError_,
                   UnauthorizedAccessError)

# NT status codes we translate into the exceptions the classifiers expect
STATUS_ACCESS_DENIED = 0xC0000022
STATUS_LOGON_FAILURE = 0xC000006D
STATUS_BAD_NETWORK_NAME = 0xC00000CC
STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
STATUS_OBJECT_PATH_NOT_FOUND = 0xC000003A
STATUS_NO_SUCH_FILE = 0xC000000F
STATUS_NOT_A_DIRECTORY = 0xC0000103
STATUS_FILE_IS_A_DIRECTORY = 0xC00000BA
STATUS_SHARING_VIOLATION = 0xC0000043

_DENIED = (STATUS_ACCESS_DENIED, STATUS_LOGON_FAILURE)
_NOT_FOUND = (STATUS_BAD_NETWORK_NAME, STATUS_OBJECT_NAME_NOT_FOUND,
              STATUS_OBJECT_PATH_NOT_FOUND, STATUS_NO_SUCH_FILE,
              STATUS_NOT_A_DIRECTORY)


def _status_of(exc):
    try:
        return exc.getErrorCode() & 0xFFFFFFFF
    except Exception:
        return None


def translate(exc):
    """Turn an impacket SessionError into the .NET exception Snaffler expects."""
    status = _status_of(exc)
    if status in _DENIED:
        return UnauthorizedAccessError(str(exc))
    if status in _NOT_FOUND:
        return DirectoryNotFoundError(str(exc))
    return IOError_(str(exc))


def parse_unc(path):
    """\\\\server\\share\\a\\b -> ('server', 'share', 'a\\b')."""
    if not path.startswith("\\\\"):
        raise ValueError("Not a UNC path: %r" % path)
    rest = path[2:]
    parts = rest.split("\\")
    parts = [p for p in parts]
    if len(parts) < 2 or not parts[0]:
        raise ValueError("Not a UNC path: %r" % path)
    server = parts[0]
    share = parts[1]
    relative = "\\".join(parts[2:]).strip("\\")
    return server, share, relative


def filetime_to_datetime(ts):
    """impacket hands back epoch seconds for mtime."""
    try:
        return datetime.fromtimestamp(ts)
    except (OverflowError, OSError, ValueError):
        return datetime.fromtimestamp(0)


class Credentials:
    def __init__(self, username="", password="", domain="", lmhash="", nthash="",
                 aes_key=None, do_kerberos=False, dc_ip=None, port=445, timeout=30):
        self.username = username or ""
        self.password = password or ""
        self.domain = domain or ""
        self.lmhash = lmhash or ""
        self.nthash = nthash or ""
        # impacket's kerberosLogin wants a string aesKey, never None
        self.aes_key = aes_key or ""
        self.do_kerberos = do_kerberos
        self.dc_ip = dc_ip
        self.port = port
        self.timeout = timeout


class SmbConnectionPool:
    """Per-host pool of authenticated SMBConnections.

    A connection is checked out for the duration of an operation, so no two
    threads ever drive the same socket. Hosts that fail to connect are
    remembered so we stop hammering them.
    """

    def __init__(self, creds, max_per_host=4):
        self.creds = creds
        self.max_per_host = max(1, max_per_host)
        self._lock = threading.Lock()
        self._idle = {}        # host -> [SMBConnection]
        self._sema = {}        # host -> BoundedSemaphore
        self._dead = {}        # host -> reason
        self._closed = False

    def _semaphore(self, host):
        with self._lock:
            if host not in self._sema:
                self._sema[host] = threading.BoundedSemaphore(self.max_per_host)
                self._idle[host] = []
            return self._sema[host]

    def is_dead(self, host):
        with self._lock:
            return self._dead.get(host)

    def mark_dead(self, host, reason):
        with self._lock:
            self._dead[host] = str(reason)

    def _connect(self, host):
        c = self.creds
        conn = SMBConnection(host, host, sess_port=c.port, timeout=c.timeout)
        if c.do_kerberos:
            conn.kerberosLogin(c.username, c.password, c.domain, c.lmhash, c.nthash,
                               c.aes_key, c.dc_ip)
        else:
            conn.login(c.username, c.password, c.domain, c.lmhash, c.nthash)
        return conn

    @contextmanager
    def connection(self, host):
        host = host.lower()
        dead = self.is_dead(host)
        if dead:
            raise IOError_("host %s previously unreachable: %s" % (host, dead))
        sema = self._semaphore(host)
        sema.acquire()
        conn = None
        try:
            with self._lock:
                pool = self._idle.get(host) or []
                conn = pool.pop() if pool else None
            if conn is None:
                try:
                    conn = self._connect(host)
                except SessionError as exc:
                    raise translate(exc)
                except Exception as exc:
                    self.mark_dead(host, exc)
                    raise IOError_("could not connect to %s: %s" % (host, exc))

            try:
                yield conn
            except (UnauthorizedAccessError, DirectoryNotFoundError, IOError_):
                # A denied or missing file is an ordinary result on a share we
                # only partly have access to - the session is still good, so
                # keep the connection rather than reconnecting per bad file.
                raise
            except Exception:
                try:
                    conn.close()
                except Exception:
                    pass
                conn = None
                raise
        finally:
            if conn is not None:
                with self._lock:
                    if self._closed:
                        try:
                            conn.close()
                        except Exception:
                            pass
                    else:
                        self._idle.setdefault(host, []).append(conn)
            sema.release()

    def close(self):
        with self._lock:
            self._closed = True
            pools = list(self._idle.values())
            self._idle = {}
        for pool in pools:
            for conn in pool:
                try:
                    conn.close()
                except Exception:
                    pass


class SmbFileSystem(FileSystem):
    def __init__(self, pool):
        self.pool = pool

    # -- Directory.Exists / GetFiles / GetDirectories ------------------------
    def directory_exists(self, path):
        try:
            self.list_directory(path)
            return True
        except Exception:
            return False

    def list_directory(self, path):
        """One listing yields both the files and the subdirectories."""
        server, share, relative = parse_unc(path)
        search = (relative + "\\*") if relative else "*"
        base = path.rstrip("\\")
        files, dirs = [], []
        with self.pool.connection(server) as conn:
            try:
                entries = conn.listPath(share, search)
            except SessionError as exc:
                raise translate(exc)
        for entry in entries:
            name = entry.get_longname()
            if name in (".", ".."):
                continue
            full = base + "\\" + name
            if entry.is_directory():
                dirs.append(full)
            else:
                files.append(FileInfo(
                    self, full,
                    length=entry.get_filesize(),
                    last_write_time=filetime_to_datetime(entry.get_mtime_epoch())))
        return files, dirs

    def get_file_info(self, path):
        server, share, relative = parse_unc(path)
        with self.pool.connection(server) as conn:
            try:
                entries = conn.listPath(share, relative)
            except SessionError as exc:
                raise translate(exc)
        for entry in entries:
            if entry.is_directory():
                continue
            return FileInfo(self, path,
                            length=entry.get_filesize(),
                            last_write_time=filetime_to_datetime(entry.get_mtime_epoch()))
        return FileInfo(self, path, exists=False)

    # -- File.ReadAllBytes / File.OpenRead -----------------------------------
    def read_all_bytes(self, path):
        server, share, relative = parse_unc(path)
        chunks = []
        with self.pool.connection(server) as conn:
            try:
                conn.getFile(share, relative, chunks.append)
            except SessionError as exc:
                raise translate(exc)
        return b"".join(chunks)

    def can_read(self, path):
        """Stands in for the C#'s File.OpenRead() probe used to set RwStatus.

        The tree connection is left in place: impacket caches it per share, and
        tearing it down here would force a reconnect on the next listing.
        """
        server, share, relative = parse_unc(path)
        try:
            with self.pool.connection(server) as conn:
                try:
                    tid = conn.connectTree(share)
                    fid = conn.openFile(tid, relative)
                    conn.closeFile(tid, fid)
                    return True
                except SessionError as exc:
                    # translate before it leaves the context manager, so a
                    # denied file isn't mistaken for a broken connection
                    raise translate(exc)
        except Exception:
            return False

    def close(self):
        self.pool.close()


class HostShareInfo:
    """The ShareFinder.HostShareInfo struct, filled from NetrShareEnum level 1."""

    __slots__ = ("shi1_netname", "shi1_type", "shi1_remark")

    def __init__(self, netname, sharetype, remark):
        self.shi1_netname = netname
        self.shi1_type = sharetype
        self.shi1_remark = remark

    def __str__(self):
        return self.shi1_netname


def _unwrap(value):
    """impacket returns null-terminated wide strings from srvsvc."""
    if value is None:
        return ""
    try:
        text = str(value)
    except Exception:
        return ""
    return text.rstrip("\x00")


def get_host_share_info(pool, server):
    """Port of ShareFinder.GetHostShareInfo - NetShareEnum level 1 over srvsvc.

    Errors come back in-band as a fake share named "ERROR=<n>", exactly as the
    C# does, because GetShareName() filters those out downstream.
    """
    try:
        with pool.connection(server) as conn:
            shares = conn.listShares()
    except Exception as exc:
        status = _status_of(exc)
        code = 5 if status in _DENIED else 53
        return [HostShareInfo("ERROR=%d" % code, 10, "")]

    infos = []
    for share in shares:
        try:
            netname = _unwrap(share["shi1_netname"])
            remark = _unwrap(share["shi1_remark"])
            sharetype = int(share["shi1_type"])
        except Exception:
            continue
        infos.append(HostShareInfo(netname, sharetype, remark))
    return infos
