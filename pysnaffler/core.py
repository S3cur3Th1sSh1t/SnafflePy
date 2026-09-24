"""
Port of SnaffCore/SnaffCon.cs - target discovery and the run loop.
"""
import ipaddress
import os
import socket
import threading
from datetime import datetime

from . import dotnet
from .ad.addata import AdData
from .concurrency import BlockingMq, BlockingStaticTaskScheduler
from .context import ctx
from .filescan import FileScanner
from .sharefind import ShareFinder
from .treewalk import TreeWalker


def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _timespan(delta):
    """C# TimeSpan.ToString() - [d.]hh:mm:ss[.fffffff]"""
    total = delta.total_seconds()
    sign = "-" if total < 0 else ""
    total = abs(total)
    days, rem = divmod(int(total), 86400)
    hours, rem = divmod(rem, 3600)
    minutes, seconds = divmod(rem, 60)
    frac = delta.microseconds
    out = "%s%02d:%02d:%02d" % (sign, hours, minutes, seconds)
    if days:
        out = "%s%d.%02d:%02d:%02d" % (sign, days, hours, minutes, seconds)
    if frac:
        out += ".%07d" % (frac * 10)
    return out


def _private_memory_size():
    try:
        with open("/proc/self/status") as fh:
            for line in fh:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) * 1024
    except Exception:
        pass
    try:
        import resource
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
    except Exception:
        return 0


class SnaffCon:
    def __init__(self, options):
        ctx.MyOptions = options
        self.Mq = BlockingMq.get_mq()
        self._wait_handle = threading.Event()
        self._discovery_done = threading.Event()
        self._ad_data = AdData.instance()
        self.StartTime = None

        ctx.ShareTaskScheduler = BlockingStaticTaskScheduler(
            options.ShareThreads, options.MaxShareQueue, "share")
        ctx.TreeTaskScheduler = BlockingStaticTaskScheduler(
            options.TreeThreads, options.MaxTreeQueue, "tree")
        ctx.FileTaskScheduler = BlockingStaticTaskScheduler(
            options.FileThreads, options.MaxFileQueue, "file")

        ctx.FileScanner = FileScanner()
        ctx.TreeWalker = TreeWalker()
        ctx.ShareFinder = ShareFinder()

    # -- main ----------------------------------------------------------------
    def execute(self):
        options = ctx.MyOptions
        self.StartTime = datetime.now()

        # The C# only ever checks for completion on the status-update tick, so a
        # short scan still sits there for the full interval. We keep the status
        # cadence but poll for completion separately so the run ends when the
        # work does.
        stop = threading.Event()
        status_thread = threading.Thread(
            target=self._status_loop, args=(stop,), daemon=True)
        status_thread.start()

        try:
            # Guard against the status loop seeing three empty schedulers before
            # discovery has queued anything and declaring the run finished. Only
            # after this is set may completion be checked.
            if options.DomainUserRules:
                self.domain_user_discovery()

            # Explicit folder setting overrides DFS
            if len(options.PathTargets) != 0 and (options.DfsShareDiscovery or options.DfsOnly):
                self.domain_dfs_discovery()

            if len(options.PathTargets) == 0 and options.ComputerTargets is None:
                if len(options.DfsSharesDict) == 0:
                    self.Mq.info("Invoking DFS Discovery because no ComputerTargets "
                                 "or PathTargets were specified")
                    self.domain_dfs_discovery()

                if not options.DfsOnly:
                    self.Mq.info("Invoking full domain computer discovery.")
                    self.domain_target_discovery()
                else:
                    self.Mq.info("Skipping domain computer discovery.")
                    for share in options.DfsSharesDict.keys():
                        if share not in options.PathTargets:
                            options.PathTargets.append(share)
                    self.Mq.info("Starting TreeWalker tasks on DFS shares.")
                    self.file_discovery(list(options.PathTargets))
            elif len(options.PathTargets) != 0:
                self.file_discovery(list(options.PathTargets))
            elif options.ComputerTargets is not None:
                self.share_discovery(options.ComputerTargets)
            else:
                self.Mq.error("OctoParrot says: AWK! I SHOULDN'T BE!")

            self._discovery_done.set()
            self._wait_handle.wait()
        finally:
            self._discovery_done.set()
            stop.set()

        self.status_update()
        finished = datetime.now()
        run_span = finished - self.StartTime
        self.Mq.info("Finished at " + finished.strftime("%d/%m/%Y %H:%M:%S"))
        self.Mq.info("Snafflin' took " + _timespan(run_span))
        self.Mq.finish()

    # -- discovery -----------------------------------------------------------
    def domain_dfs_discovery(self):
        options = ctx.MyOptions
        self.Mq.info("Getting DFS paths from AD.")
        self._ad_data.set_dfs_paths()
        dfs_shares_dict = self._ad_data.get_dfs_shares_dict()

        if dfs_shares_dict and len(dfs_shares_dict) >= 1:
            options.DfsSharesDict = dfs_shares_dict
            options.DfsNamespacePaths = self._ad_data.get_dfs_namespace_paths()

    def domain_target_discovery(self):
        options = ctx.MyOptions

        if options.ComputerTargets is not None:
            self.Mq.info("Using computer list from user-specified options.")
            target_computers = list(options.ComputerTargets)
            self.Mq.info("Took {0} computers specified in options file.".format(
                len(target_computers)))
        else:
            # single threaded because it's fast and not easily divisible
            self.Mq.info("Getting computers from AD.")
            self._ad_data.set_domain_computers(options.ComputerTargetsLdapFilter)
            target_computers = self._ad_data.get_domain_computers()
            self.Mq.info("Got {0} computers from AD.".format(len(target_computers)))

            if options.DfsOnly:
                self.file_discovery(list(options.DfsNamespacePaths))

        if target_computers is None and options.DfsNamespacePaths is None:
            self.Mq.error("Something fucked out finding stuff in the domain. "
                          "You must be holding it wrong.")
            self.Mq.terminate()
            return

        if len(target_computers) == 0 and len(options.DfsNamespacePaths) == 0:
            self.Mq.error("Didn't find any domain computers. Seems weird. "
                          "Try pouring water on it.")
            self.Mq.terminate()
            return

        self.share_discovery(target_computers)

    def domain_user_discovery(self):
        options = ctx.MyOptions
        self.Mq.info("Getting interesting users from AD.")
        self._ad_data.set_domain_users()

        for user in self._ad_data.get_domain_users():
            options.DomainUsersToMatch.append(user)

        self.prep_domain_user_rules()

    def prep_domain_user_rules(self):
        """Fold the discovered usernames into the configured wordlist rules."""
        import re
        options = ctx.MyOptions
        try:
            if len(options.DomainUsersWordlistRules) >= 1:
                for rule_name in options.DomainUsersWordlistRules:
                    rule = next((r for r in options.ClassifierRules
                                 if r.RuleName == rule_name), None)
                    if rule is None:
                        raise KeyError(rule_name)

                    for user in options.DomainUsersToMatch:
                        if len(user) < options.DomainUserMinLen:
                            self.Mq.trace('Skipping regex for "{0}".  Shorter than '
                                          'minimum chars: {1}'.format(
                                              user, options.DomainUserMinLen))
                            continue

                        pattern = "(| |'|\")" + re.escape(user) + "(| |'|\")"
                        regex = dotnet.compile_pattern(pattern, singleline=True)
                        rule.Regexes.append(regex)
                        self.Mq.trace("Adding regex {0} to rule {1}".format(
                            regex.pattern, rule_name))
        except Exception:
            self.Mq.error("Something went wrong adding domain users to rules.")

    def share_discovery(self, computer_targets):
        self.Mq.info("Starting to look for readable shares...")
        for computer in computer_targets:
            if self.check_exclusions(computer):
                continue

            if is_ip(computer):
                try:
                    self.Mq.trace("Performing reverse lookup for " + computer)
                    computer_name = socket.gethostbyaddr(computer)[0]
                    self.Mq.trace("Got DNSName " + computer_name + " for " + computer)
                except Exception as exc:
                    self.Mq.degub(str(exc))
                    computer_name = computer   # keep the IP if reverse lookup fails
            else:
                computer_name = computer

            self.Mq.trace("Creating a ShareFinder task for " + computer_name)

            def task(name=computer_name):
                try:
                    ShareFinder().get_computer_shares(name)
                except Exception as exc:
                    self.Mq.error("Exception in ShareFinder task for host " + name)
                    self.Mq.error(str(exc))
            ctx.ShareTaskScheduler.new(task)

        self.Mq.info("Created all sharefinder tasks.")

    def check_exclusions(self, computer):
        options = ctx.MyOptions
        if is_ip(computer):
            if computer in options.ComputerExclusions:
                self.Mq.degub("Excluded " + computer)
                return True
        else:
            try:
                _name, _aliases, addresses = socket.gethostbyname_ex(computer)
                for ip_address in addresses:
                    if ip_address in options.ComputerExclusions:
                        self.Mq.degub("Excluded " + computer + " at " + ip_address)
                        return True
            except Exception as exc:
                # fail safe: a host we can't resolve is a host we don't scan
                self.Mq.degub(str(exc))
                self.Mq.degub("Excluded " + computer)
                return True
        self.Mq.degub("Included " + computer)
        return False

    def file_discovery(self, path_targets):
        for path_target in path_targets:
            self.Mq.info("Creating a TreeWalker task for " + path_target)

            def task(path=path_target):
                try:
                    ctx.TreeWalker.walk_tree(path)
                except Exception as exc:
                    self.Mq.error("Exception in TreeWalker task for path " + path)
                    self.Mq.error(str(exc))
            ctx.TreeTaskScheduler.new(task)

        self.Mq.info("Created all TreeWalker tasks.")

    # -- status --------------------------------------------------------------
    def _status_loop(self, stop):
        interval = ctx.MyOptions.TimeOut * 60
        elapsed = 0.0
        while not stop.wait(0.25):
            elapsed += 0.25
            # don't declare victory until discovery has queued its initial work
            if self._discovery_done.is_set() and self._all_done():
                self._wait_handle.set()
                return
            if elapsed >= interval:
                elapsed = 0.0
                self.status_update()

    def _all_done(self):
        return (ctx.FileTaskScheduler.done() and ctx.ShareTaskScheduler.done()
                and ctx.TreeTaskScheduler.done())

    def status_update(self):
        options = ctx.MyOptions
        memorynumber = dotnet.bytes_to_string(_private_memory_size())

        share_counters = ctx.ShareTaskScheduler.recalculate_counters()
        tree_counters = ctx.TreeTaskScheduler.recalculate_counters()
        file_counters = ctx.FileTaskScheduler.recalculate_counters()

        lines = ["Status Update: \n"]
        lines.append("ShareFinder Tasks Completed: %d\n" % share_counters.CompletedTasks)
        lines.append("ShareFinder Tasks Remaining: %d\n" % share_counters.CurrentTasksRemaining)
        lines.append("ShareFinder Tasks Running: %d\n" % share_counters.CurrentTasksRunning)
        lines.append("TreeWalker Tasks Completed: %d\n" % tree_counters.CompletedTasks)
        lines.append("TreeWalker Tasks Remaining: %d\n" % tree_counters.CurrentTasksRemaining)
        lines.append("TreeWalker Tasks Running: %d\n" % tree_counters.CurrentTasksRunning)
        lines.append("FileScanner Tasks Completed: %d\n" % file_counters.CompletedTasks)
        lines.append("FileScanner Tasks Remaining: %d\n" % file_counters.CurrentTasksRemaining)
        lines.append("FileScanner Tasks Running: %d\n" % file_counters.CurrentTasksRunning)
        lines.append(memorynumber + " RAM in use." + "\n")
        lines.append("\n")

        # once the share queue drains, hand its capacity to the file scanner
        if ctx.ShareTaskScheduler.done() and share_counters.MaxParallelism >= 1:
            transfer_val = share_counters.MaxParallelism
            ctx.ShareTaskScheduler.max_parallelism = 0
            ctx.FileTaskScheduler.max_parallelism = (
                ctx.FileTaskScheduler.max_parallelism + transfer_val)
            lines.append("ShareScanner queue finished, rebalancing workload." + "\n")

        if file_counters.CurrentTasksQueued <= (options.MaxFileQueue / 20):
            if ctx.FileTaskScheduler.max_parallelism > 1:
                lines.append("Insufficient FileScanner queue size, rebalancing workload." + "\n")
                ctx.FileTaskScheduler.max_parallelism -= 1
                ctx.TreeTaskScheduler.max_parallelism += 1
        if file_counters.CurrentTasksQueued == options.MaxFileQueue:
            if ctx.TreeTaskScheduler.max_parallelism > 1:
                lines.append("Max FileScanner queue size reached, rebalancing workload." + "\n")
                ctx.FileTaskScheduler.max_parallelism += 1
                ctx.TreeTaskScheduler.max_parallelism -= 1

        lines.append("Max ShareFinder Threads: %d\n" % ctx.ShareTaskScheduler.max_parallelism)
        lines.append("Max TreeWalker Threads: %d\n" % ctx.TreeTaskScheduler.max_parallelism)
        lines.append("Max FileScanner Threads: %d\n" % ctx.FileTaskScheduler.max_parallelism)

        run_span = datetime.now() - self.StartTime
        lines.append("Been Snafflin' for " + _timespan(run_span) +
                     " and we ain't done yet..." + "\n")

        self.Mq.info("".join(lines))

        if self._discovery_done.is_set() and self._all_done():
            self._wait_handle.set()
