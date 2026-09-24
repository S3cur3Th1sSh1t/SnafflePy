"""Port of SnaffCore/FileScan/FileScanner.cs."""
from .classifiers import FileClassifier
from .concurrency import BlockingMq
from .context import ctx
from .fs.base import (FileNotFoundError_, IOError_, PathTooLongError,
                      UnauthorizedAccessError)


class FileScanner:
    def __init__(self):
        self.Mq = BlockingMq.get_mq()

    def scan_file(self, file, alt_file_info=None):
        """`file` is either a path or an already-populated FileInfo.

        The tree walker passes FileInfo objects it got from the directory
        listing, which saves a round trip per file over SMB.
        """
        try:
            if isinstance(file, str):
                file_info = ctx.FileSystem.get_file_info(file)
            else:
                file_info = file

            for classifier in ctx.MyOptions.FileClassifiers:
                if FileClassifier(classifier).classify_file(file_info, alt_file_info):
                    return
        except FileNotFoundError_ as exc:
            self.Mq.trace(str(exc))
        except UnauthorizedAccessError as exc:
            self.Mq.trace(str(exc))
        except PathTooLongError:
            self.Mq.trace(str(file) + " path was too long for me to look at.")
        except Exception as exc:
            self.Mq.trace(str(exc))
