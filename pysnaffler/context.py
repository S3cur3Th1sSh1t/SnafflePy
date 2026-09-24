"""
Stand-in for the C#'s statics: Options.MyOptions and SnaffCon.Get*().
"""


class _Context:
    def __init__(self):
        self.MyOptions = None
        self.FileSystem = None
        self.ShareTaskScheduler = None
        self.TreeTaskScheduler = None
        self.FileTaskScheduler = None
        self.ShareFinder = None
        self.TreeWalker = None
        self.FileScanner = None
        self.SmbPool = None
        self.Collector = None


ctx = _Context()
