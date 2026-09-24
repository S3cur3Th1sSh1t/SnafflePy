"""
Port of SnaffCore/ShareFind/ShareFinder.cs.

The Win32 NetShareEnum P/Invoke is replaced by impacket's srvsvc
NetrShareEnum level 1, which returns the same shi1_netname / shi1_type /
shi1_remark fields.
"""
from .classifiers import ShareClassifier, ShareResult
from .concurrency import BlockingMq
from .context import ctx
from .fs.base import DirectoryNotFoundError, IOError_, UnauthorizedAccessError
from .fs.smb import get_host_share_info
from .rules import Triage

NEVER_SCAN = ("ipc$", "print$")
SHARE_ENUM_ERRORS = ("ERROR=53", "ERROR=5")


class ShareFinder:
    def __init__(self):
        self.Mq = BlockingMq.get_mq()

    def get_computer_shares(self, computer):
        options = ctx.MyOptions
        host_share_infos = get_host_share_info(ctx.SmbPool, computer)

        for host_share_info in host_share_infos:
            # skip IPC$ and PRINT$ shares for #OPSEC!!!
            if host_share_info.shi1_netname.lower() in NEVER_SCAN:
                continue

            share_name = self.get_share_name(host_share_info, computer)
            if not share_name or not share_name.strip():
                continue

            matched = False
            netname_upper = host_share_info.shi1_netname.upper()

            # SYSVOL and NETLOGON are replicated to every DC, so only the first
            # replica we meet gets walked.
            if netname_upper == "SYSVOL":
                if options.ScanSysvol:
                    options.ScanSysvol = False
                else:
                    matched = True
            elif netname_upper == "NETLOGON":
                if options.ScanNetlogon:
                    options.ScanNetlogon = False
                else:
                    matched = True
            else:
                for classifier in options.ShareClassifiers:
                    if ShareClassifier(classifier).classify_share(share_name):
                        # matched a Discard rule, so don't send to treewalker
                        matched = True
                        break

            if matched:
                continue

            share_result = ShareResult(
                share_path=share_name,
                share_comment=str(host_share_info.shi1_remark),
                listable=True)

            # If this path can be reached through DFS, prefer the DFS referral
            # and make sure we only scan the namespace once.
            if share_name in options.DfsSharesDict:
                dfs_unc_path = options.DfsSharesDict[share_name]
                self.Mq.degub("Matched host path {0} to DFS {1}".format(
                    share_name, dfs_unc_path))

                if dfs_unc_path in options.DfsNamespacePaths:
                    self.Mq.degub("Will scan {0} using DFS referral instead of "
                                  "explicit host".format(dfs_unc_path))
                    share_result.SharePath = dfs_unc_path
                    try:
                        options.DfsNamespacePaths.remove(dfs_unc_path)
                    except ValueError:
                        pass
                else:
                    # already scanned via the namespace - upstream breaks out of
                    # the whole share loop here, so we do too.
                    break

            if self.is_share_readable(share_result.SharePath):
                share_result.Triage = Triage.Green

                try:
                    share_result.RootModifyable = False
                    share_result.RootWritable = False
                    share_result.RootReadable = True
                except UnauthorizedAccessError:
                    self.Mq.error("Failed to get permissions on " + share_result.SharePath)

                if ctx.MyOptions.ScanFoundShares:
                    self.Mq.trace("Creating a TreeWalker task for " + share_result.SharePath)

                    def task(path=share_result.SharePath):
                        try:
                            ctx.TreeWalker.walk_tree(path)
                        except Exception as exc:
                            self.Mq.error("Exception in TreeWalker task for share " + path)
                            self.Mq.error(str(exc))
                    ctx.TreeTaskScheduler.new(task)

                self.Mq.share_result(share_result)
            elif ctx.MyOptions.LogDeniedShares:
                self.Mq.share_result(share_result)

    def is_share_readable(self, share):
        if share.lower().endswith("ipc$") or share.lower().endswith("print$"):
            return False
        try:
            ctx.FileSystem.list_directory(share)
            return True
        except (UnauthorizedAccessError, DirectoryNotFoundError, IOError_):
            return False
        except Exception as exc:
            self.Mq.trace("Unhandled exception in IsShareReadable() for share path: "
                          + share + " Full Exception:" + str(exc))
        return False

    def get_share_name(self, host_share_info, computer):
        """Turns a share info entry into a usable UNC path, dropping errors."""
        if host_share_info.shi1_netname in SHARE_ENUM_ERRORS:
            return None
        self.Mq.degub("Share discovered: " +
                      "\\\\{0}\\{1}".format(computer, host_share_info.shi1_netname))
        return "\\\\{0}\\{1}".format(computer, host_share_info.shi1_netname)
