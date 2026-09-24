"""
Port of SnaffCore/TreeWalk/TreeWalker.cs, including the SCCM content library
special case.

One difference from the C#: it calls Directory.GetFiles() and then
Directory.GetDirectories(), enumerating each directory twice. We take a single
listing and split it, which is the same set of files and subdirectories for one
round trip instead of two - a large saving over SMB.
"""
import re

from . import dotnet
from .classifiers import AlternativeFileInfo, DirClassifier
from .concurrency import BlockingMq
from .context import ctx
from .fs.base import (DirectoryNotFoundError, FileNotFoundError_, IOError_,
                      PathTooLongError, UnauthorizedAccessError)

_SCCM_HASH_RE = re.compile(r"Hash=([0-9A-Fa-f]+)")


class TreeWalker:
    def __init__(self):
        self.Mq = BlockingMq.get_mq()

    @property
    def FileTaskScheduler(self):
        return ctx.FileTaskScheduler

    @property
    def TreeTaskScheduler(self):
        return ctx.TreeTaskScheduler

    def walk_tree(self, current_dir):
        fs = ctx.FileSystem

        # SCCM ContentLib($)
        try:
            current_directory_name = dotnet.get_file_name(current_dir.rstrip("\\"))
            if current_directory_name in ("SCCMContentLib", "SCCMContentLib$"):
                self.Mq.info("SCCM content library found: " + current_dir)
                data_lib_dir = dotnet.path_combine(current_dir, "DataLib")
                if not fs.directory_exists(data_lib_dir):
                    self.Mq.error("SCCM content library found but no DataLib found: "
                                  + data_lib_dir)
                    return
                self.Mq.info("SCCM content library: Entering into datalib: " + data_lib_dir)
                self.walk_sccm_tree(data_lib_dir, current_dir)
                return
        except Exception as exc:
            self.Mq.degub(str(exc))

        try:
            files, sub_dirs = fs.list_directory(current_dir)
        except (UnauthorizedAccessError, DirectoryNotFoundError, IOError_):
            return
        except Exception as exc:
            self.Mq.degub(str(exc))
            return

        for file_info in files:
            self._queue_file(file_info)

        self._queue_subdirs(sub_dirs, self.walk_tree)

    def _queue_file(self, file_info, alt_file_info=None):
        def task():
            try:
                ctx.FileScanner.scan_file(file_info, alt_file_info)
            except Exception as exc:
                self.Mq.error("Exception in FileScanner task for file " + file_info.FullName)
                self.Mq.trace(str(exc))
        self.FileTaskScheduler.new(task)

    def _queue_subdirs(self, sub_dirs, walker):
        for dir_str in sub_dirs:
            scan_dir = True
            for classifier in ctx.MyOptions.DirClassifiers:
                try:
                    dir_result = DirClassifier(classifier).classify_dir(dir_str)
                    if dir_result is not None and dir_result.ScanDir is False:
                        scan_dir = False
                        break
                except Exception as exc:
                    self.Mq.trace(str(exc))
                    continue

            if scan_dir:
                def task(d=dir_str):
                    try:
                        walker(d)
                    except Exception as exc:
                        self.Mq.error("Exception in TreeWalker task for dir " + d)
                        self.Mq.error(str(exc))
                self.TreeTaskScheduler.new(task)
            else:
                self.Mq.trace("Skipped scanning on " + dir_str + " due to Discard rule match.")

    # -- SCCM content library ------------------------------------------------
    def walk_sccm_tree(self, current_dir, sccm_base_dir):
        """DataLib holds <name>.INI stubs pointing at hash-named blobs in FileLib.

        We scan the blob but report it under the real filename from the stub.
        """
        fs = ctx.FileSystem

        try:
            files, sub_dirs = fs.list_directory(current_dir)
        except (UnauthorizedAccessError, DirectoryNotFoundError, IOError_):
            return
        except Exception as exc:
            self.Mq.degub(str(exc))
            return

        for file_info in files:
            self._queue_sccm_stub(file_info, sccm_base_dir)

        self._queue_subdirs(sub_dirs, lambda d: self.walk_sccm_tree(d, sccm_base_dir))

    def _queue_sccm_stub(self, file_info, sccm_base_dir):
        def task():
            try:
                if file_info.Extension != ".INI":
                    self.Mq.trace("Skipping file in DataLib but does not extention .INI; "
                                  "Something wrong: " + file_info.FullName)
                    return

                file_string = file_info.read_all_text()
                if not file_string.startswith("[File]"):
                    self.Mq.trace("Skipping file in DataLib but does not points to any file: "
                                  + file_info.FullName)
                    return

                match = _SCCM_HASH_RE.search(file_string)
                if not match:
                    self.Mq.trace("Skipping file in DataLib but does not have hash of any "
                                  "file: " + file_info.FullName)
                    return
                hash_value_text = match.group(1)
                target_dir_name = hash_value_text[:4]

                tmp_full = file_info.FullName
                alternative_full_file_name = tmp_full[:len(tmp_full) - 4]  # strip ".INI"
                alt_file_info = AlternativeFileInfo(alternative_full_file_name)

                target_file_path_name = dotnet.path_combine(
                    sccm_base_dir, "FileLib", target_dir_name, hash_value_text)

                self.Mq.trace("We can look at file [" + target_file_path_name +
                              " ] reffered by [ " + file_info.FullName +
                              " ] should be handled as [ " + alternative_full_file_name + " ]")

                def inner():
                    try:
                        ctx.FileScanner.scan_file(target_file_path_name, alt_file_info)
                    except Exception as exc:
                        self.Mq.error("Exception in FileScanner task for file "
                                      + file_info.FullName)
                        self.Mq.trace(str(exc))
                self.FileTaskScheduler.new(inner)
            except FileNotFoundError_ as exc:
                self.Mq.trace(str(exc))
            except UnauthorizedAccessError as exc:
                self.Mq.trace(str(exc))
            except PathTooLongError:
                self.Mq.trace(file_info.FullName + " path was too long for me to look at.")
            except Exception as exc:
                self.Mq.trace(str(exc))

        self.FileTaskScheduler.new(task)
