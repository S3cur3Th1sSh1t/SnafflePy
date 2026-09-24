"""
Tests for the bundled snaffleplus extended rules and the merge (--plus /
--extra-rules) that layers them onto the defaults without replacing them.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from memfs import MemoryFileSystem

from pysnaffler.concurrency import BlockingMq, SnafflerMessageType
from pysnaffler.context import ctx
from pysnaffler.filescan import FileScanner
from pysnaffler.options import Options
from pysnaffler.rules import (build_regexes, load_default_rules,
                              load_extended_rules)


def make_options(plus=True):
    options = Options()
    options.ClassifierRules = load_default_rules()
    if plus:
        added = load_extended_rules()
        names = {r.RuleName for r in added}
        options.ClassifierRules = [r for r in options.ClassifierRules
                                   if r.RuleName not in names] + added
    options.prepare_classifiers()
    return options


def scan(fs, paths, options):
    BlockingMq.make_mq()
    ctx.MyOptions = options
    ctx.FileSystem = fs
    scanner = FileScanner()
    for path in paths:
        scanner.scan_file(fs.get_file_info(path))
    return {(m.FileResult.MatchedRule.RuleName, m.FileResult.FileInfo.FullName)
            for m in BlockingMq.get_mq().drain()
            if m.Type == SnafflerMessageType.FileResult}


class TestExtendedPackLoads(unittest.TestCase):
    def test_pack_loads_and_compiles(self):
        rules = load_extended_rules()
        self.assertGreaterEqual(len(rules), 9)
        for r in rules:
            build_regexes(r)

    def test_merge_resolves_relay_targets(self):
        options = make_options(plus=True)
        names = {r.RuleName for r in options.ClassifierRules}
        for r in options.ClassifierRules:
            for t in (r.RelayTargets or []):
                self.assertIn(t, names)

    def test_no_duplicate_names_after_merge(self):
        options = make_options(plus=True)
        names = [r.RuleName for r in options.ClassifierRules]
        self.assertEqual(len(names), len(set(names)))


class TestExtendedFindings(unittest.TestCase):
    def setUp(self):
        self.opts = make_options(plus=True)

    def _rules_for(self, filename, content):
        fs = MemoryFileSystem()
        path = r"\\HOST\share\%s" % filename
        fs.add(path, content)
        return {r for r, _ in scan(fs, [path], self.opts)}

    def test_gpp_cpassword_is_black(self):
        rules = self._rules_for(
            "Groups.xml",
            '<Properties cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw"/>')
        self.assertIn("KeepSecretsPlusBlack", rules)

    def test_gcp_service_account_key(self):
        rules = self._rules_for(
            "sa.json",
            '{"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----\\nAAA"}')
        self.assertIn("KeepSecretsPlusBlack", rules)

    def test_github_token(self):
        rules = self._rules_for(
            "app.env", "GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
        self.assertIn("KeepSecretsPlusRed", rules)

    def test_db_uri_with_inline_creds(self):
        rules = self._rules_for(
            "config.yml", "url: postgres://user:s3cret@db.corp.local:5432/prod")
        self.assertIn("KeepSecretsPlusRed", rules)

    def test_azure_storage_key(self):
        rules = self._rules_for(
            "az.config",
            'value="AccountKey=' + "A" * 86 + '=="')
        self.assertIn("KeepSecretsPlusRed", rules)

    def test_terraform_state_by_extension(self):
        rules = self._rules_for("terraform.tfstate", "{}")
        self.assertIn("KeepTerraformState", rules)

    def test_kubeconfig_by_name(self):
        rules = self._rules_for("kubeconfig", "apiVersion: v1")
        self.assertIn("KeepKubeconfigByName", rules)

    def test_jwt_is_yellow(self):
        rules = self._rules_for(
            "token.txt",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N")
        self.assertIn("KeepSecretsPlusYellow", rules)

    def test_boring_file_still_ignored(self):
        rules = self._rules_for("notes.md", "just some meeting notes, nothing here")
        self.assertNotIn("KeepSecretsPlusRed", rules)
        self.assertNotIn("KeepSecretsPlusBlack", rules)


class TestDefaultsUnaffected(unittest.TestCase):
    def test_defaults_only_still_88_rules(self):
        # the pack must be strictly opt-in; the default path is unchanged
        options = make_options(plus=False)
        self.assertEqual(len(load_default_rules()), 88)


if __name__ == "__main__":
    unittest.main()
