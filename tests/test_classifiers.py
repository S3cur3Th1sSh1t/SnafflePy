"""
Behavioural tests for the classifier pipeline, run against UNC paths so the
FilePath-based rules are actually exercised (a local-filesystem test would use
forward slashes and silently skip them).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from memfs import MemoryFileSystem

from pysnaffler.concurrency import BlockingMq, SnafflerMessageType
from pysnaffler.context import ctx
from pysnaffler.options import Options
from pysnaffler.rules import (EnumerationScope, MatchAction, MatchListType,
                              MatchLoc, Triage, load_default_rules)


def make_options(interest=0, context_bytes=200):
    options = Options()
    options.InterestLevel = interest
    options.MatchContextBytes = context_bytes
    options.ClassifierRules = load_default_rules()
    options.prepare_classifiers()
    return options


def scan(fs, paths, options=None):
    """Run the file classifiers over paths, returning the FileResult messages."""
    from pysnaffler.filescan import FileScanner

    BlockingMq.make_mq()
    ctx.MyOptions = options or make_options()
    ctx.FileSystem = fs

    scanner = FileScanner()
    for path in paths:
        scanner.scan_file(fs.get_file_info(path))

    results = []
    for message in BlockingMq.get_mq().drain():
        if message.Type == SnafflerMessageType.FileResult:
            results.append(message)
    return results


def findings(results):
    return {(m.FileResult.MatchedRule.RuleName, m.FileResult.FileInfo.FullName)
            for m in results}


class TestDefaultRuleset(unittest.TestCase):
    def test_all_rules_load(self):
        rules = load_default_rules()
        self.assertEqual(len(rules), 88)
        self.assertEqual(len({r.RuleName for r in rules}), 88)

    def test_every_relay_target_resolves(self):
        rules = load_default_rules()
        names = {r.RuleName for r in rules}
        for rule in rules:
            for target in (rule.RelayTargets or []):
                self.assertIn(target, names,
                              "%s relays to missing rule %s" % (rule.RuleName, target))

    def test_every_pattern_compiles(self):
        options = make_options()
        total = sum(len(r.Regexes) for r in options.ClassifierRules)
        self.assertGreater(total, 300)

    def test_buckets_are_sorted_discard_first(self):
        options = make_options()
        for bucket in (options.ShareClassifiers, options.DirClassifiers,
                       options.FileClassifiers, options.ContentsClassifiers):
            actions = [r.MatchAction for r in bucket]
            self.assertEqual(actions, sorted(actions),
                             "rules must be ordered by MatchAction")

    def test_contains_wordlists_are_unanchored_regexes(self):
        # Snaffler's "Contains" is a regex search, not a literal substring test
        options = make_options()
        rule = next(r for r in options.ClassifierRules
                    if r.WordListType == MatchListType.Contains)
        self.assertTrue(rule.Regexes)


class TestFileNameRules(unittest.TestCase):
    def test_ssh_private_keys_are_black(self):
        fs = MemoryFileSystem()
        paths = [r"\\HOST\share\home\bob\id_rsa",
                 r"\\HOST\share\home\bob\id_dsa",
                 r"\\HOST\share\home\bob\id_ed25519"]
        for p in paths:
            fs.add(p, "not a real key")
        results = scan(fs, paths)
        found = findings(results)
        for p in paths:
            self.assertIn(("KeepSSHKeysByFileName", p), found)
        for m in results:
            if m.FileResult.MatchedRule.RuleName == "KeepSSHKeysByFileName":
                self.assertEqual(m.FileResult.MatchedRule.Triage, Triage.Black)

    def test_public_key_is_not_flagged_as_private(self):
        fs = MemoryFileSystem()
        path = r"\\HOST\share\home\bob\id_rsa.pub"
        fs.add(path, "ssh-rsa AAAA")
        found = findings(scan(fs, [path]))
        self.assertNotIn(("KeepSSHKeysByFileName", path), found)

    def test_dotfile_extension_handling(self):
        # .bashrc's "extension" is the whole name in .NET; the rule that catches
        # it is a FileName rule, and it must still fire
        fs = MemoryFileSystem()
        path = r"\\HOST\share\home\bob\.bashrc"
        fs.add(path, "export FOO=bar")
        rules = {r for r, _ in findings(scan(fs, [path]))}
        self.assertIn("KeepShellRcFilesByName", rules)

    def test_kdbx_bak_matches_through_the_bak_stripping(self):
        fs = MemoryFileSystem()
        path = r"\\HOST\share\backup\secrets.kdbx.bak"
        fs.add(path, "x")
        rules = {r for r, _ in findings(scan(fs, [path]))}
        self.assertIn("KeepPassMgrsByExtension", rules)

    def test_filepath_rule_matches_unc_path(self):
        fs = MemoryFileSystem()
        path = r"\\HOST\share\users\bob\doctl\config.yaml"
        fs.add(path, "token: abc")
        rules = {r for r, _ in findings(scan(fs, [path]))}
        self.assertIn("KeepCloudApiKeysByPath", rules)

    def test_ssh_dir_path_rule_matches_unc_path(self):
        fs = MemoryFileSystem()
        path = r"\\HOST\share\users\bob\.ssh\authorized_keys"
        fs.add(path, "ssh-rsa AAAA")
        rules = {r for r, _ in findings(scan(fs, [path]))}
        self.assertIn("KeepSSHFilesByPath", rules)

    def test_boring_file_is_not_flagged(self):
        fs = MemoryFileSystem()
        path = r"\\HOST\share\pics\holiday.jpg"
        fs.add(path, "\xff\xd8\xff")
        self.assertEqual(findings(scan(fs, [path])), set())


class TestContentRules(unittest.TestCase):
    def test_private_key_in_file_contents(self):
        fs = MemoryFileSystem()
        path = r"\\HOST\share\scripts\deploy.ps1"
        fs.add(path, "# deploy\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKC\n")
        rules = {r for r, _ in findings(scan(fs, [path]))}
        self.assertIn("KeepInlinePrivateKey", rules)

    def test_password_assignment_in_code(self):
        fs = MemoryFileSystem()
        path = r"\\HOST\share\scripts\thing.ps1"
        fs.add(path, '$cred = "hunter2"\n$password = "S3cret!!"\n')
        rules = {r for r, _ in findings(scan(fs, [path]))}
        self.assertIn("KeepPassOrKeyInCode", rules)

    def test_content_rules_skip_files_over_maxsizetogrep(self):
        options = make_options()
        options.MaxSizeToGrep = 10
        fs = MemoryFileSystem()
        path = r"\\HOST\share\scripts\big.ps1"
        fs.add(path, "-----BEGIN RSA PRIVATE KEY-----" + ("A" * 5000))
        rules = {r for r, _ in findings(scan(fs, [path], options))}
        self.assertNotIn("KeepInlinePrivateKey", rules)

    def test_match_context_is_dotnet_escaped(self):
        fs = MemoryFileSystem()
        path = r"\\HOST\share\scripts\thing.ps1"
        fs.add(path, '$password = "S3cret!!"\n' + ("x" * 1000))
        results = scan(fs, [path])
        contexts = [m.FileResult.TextResult.MatchContext for m in results
                    if m.FileResult.TextResult]
        joined = " ".join(c for c in contexts if c)
        # spaces become '\ ' under .NET's Regex.Escape
        self.assertIn("\\ ", joined)


class TestDiscardRules(unittest.TestCase):
    def test_windows_system_dirs_are_discarded(self):
        from pysnaffler.classifiers import DirClassifier

        BlockingMq.make_mq()
        options = make_options()
        ctx.MyOptions = options

        discarded = []
        for path in (r"\\HOST\C$\Windows\System32",
                     r"\\HOST\C$\Windows\WinSxS"):
            scan_dir = True
            for rule in options.DirClassifiers:
                result = DirClassifier(rule).classify_dir(path)
                if result is not None and not result.ScanDir:
                    scan_dir = False
                    break
            if not scan_dir:
                discarded.append(path)
        self.assertEqual(len(discarded), 2)

    def test_ordinary_dir_is_not_discarded(self):
        from pysnaffler.classifiers import DirClassifier

        BlockingMq.make_mq()
        options = make_options()
        ctx.MyOptions = options
        path = r"\\HOST\Finance$\budgets"
        for rule in options.DirClassifiers:
            result = DirClassifier(rule).classify_dir(path)
            self.assertTrue(result is None or result.ScanDir)

    def test_winsxs_discard_needs_backslashes(self):
        """The path rules are written for UNC paths.

        This is why a scan of a real share finds fewer things than a scan of the
        same tree on a local Linux path: \\winsxs only matches the former.
        """
        from pysnaffler.classifiers import DirClassifier

        BlockingMq.make_mq()
        options = make_options()
        ctx.MyOptions = options

        def discarded(path):
            for rule in options.DirClassifiers:
                result = DirClassifier(rule).classify_dir(path)
                if result is not None and not result.ScanDir:
                    return True
            return False

        self.assertTrue(discarded(r"\\HOST\share\bait\winsxs"))
        self.assertFalse(discarded("/mnt/share/bait/winsxs"))

    def test_discarded_extension_stops_further_rules(self):
        fs = MemoryFileSystem()
        path = r"\\HOST\share\pics\photo.jpeg"
        fs.add(path, "x")
        self.assertEqual(findings(scan(fs, [path])), set())


class TestShareRules(unittest.TestCase):
    def test_ipc_and_print_shares_discarded(self):
        from pysnaffler.classifiers import ShareClassifier

        BlockingMq.make_mq()
        options = make_options()
        ctx.MyOptions = options
        ctx.FileSystem = MemoryFileSystem()

        for share in (r"\\HOST\IPC$", r"\\HOST\print$"):
            discarded = any(ShareClassifier(r).classify_share(share)
                            for r in options.ShareClassifiers)
            self.assertTrue(discarded, share)

    def test_admin_share_is_reported_black(self):
        from pysnaffler.classifiers import ShareClassifier

        BlockingMq.make_mq()
        options = make_options()
        ctx.MyOptions = options
        fs = MemoryFileSystem()
        fs.add(r"\\HOST\C$\file.txt", "x")
        ctx.FileSystem = fs

        share = r"\\HOST\C$"
        for rule in options.ShareClassifiers:
            ShareClassifier(rule).classify_share(share)

        shares = [m for m in BlockingMq.get_mq().drain()
                  if m.Type == SnafflerMessageType.ShareResult]
        self.assertTrue(shares)
        self.assertEqual(shares[0].ShareResult.Triage, Triage.Black)


class TestInterestLevel(unittest.TestCase):
    def test_higher_interest_drops_low_severity_rules(self):
        at_zero = make_options(interest=0)
        at_three = make_options(interest=3)
        self.assertLess(len(at_three.ClassifierRules), len(at_zero.ClassifierRules))

    def test_interest_three_keeps_black_snaffle_rules(self):
        options = make_options(interest=3)
        kept = [r for r in options.ClassifierRules
                if r.MatchAction == MatchAction.Snaffle and r.Triage == Triage.Black]
        self.assertTrue(kept)

    def test_interest_three_drops_green_snaffle_rules(self):
        options = make_options(interest=3)
        greens = [r for r in options.ClassifierRules
                  if r.MatchAction == MatchAction.Snaffle
                  and r.Triage == Triage.Green
                  and r.EnumerationScope == EnumerationScope.FileEnumeration]
        self.assertEqual(greens, [])

    def test_discard_rules_survive_every_interest_level(self):
        for level in range(4):
            options = make_options(interest=level)
            discards = [r for r in options.ClassifierRules
                        if r.MatchAction == MatchAction.Discard]
            self.assertTrue(discards, "interest %d dropped the discard rules" % level)


class TestRwStatus(unittest.TestCase):
    def test_unreadable_file_is_not_reported(self):
        fs = MemoryFileSystem()
        path = r"\\HOST\share\home\bob\id_rsa"
        fs.add(path, "key")
        fs.unreadable.add(path)
        self.assertEqual(findings(scan(fs, [path])), set())


if __name__ == "__main__":
    unittest.main()
