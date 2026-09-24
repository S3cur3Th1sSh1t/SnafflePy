"""
Port of SnaffCore/Config/Options.cs and ClassifierOptions.cs.

Defaults are copied verbatim from the C# so that a run with no arguments
behaves the same as the original.
"""
from enum import IntEnum

from .rules import EnumerationScope, MatchAction, Triage


class LogType(IntEnum):
    Plain = 0
    JSON = 1


class DomainUserNamesFormat(IntEnum):
    sAMAccountName = 0
    NetBIOS = 1
    UPN = 2


# Passwords Snaffler tries against certificates that need one. Straight from
# Options.cs (they come from assorted online tutorials).
CERT_PASSWORDS = [
    "",
    "password",
    "mimikatz",
    "1234",
    "abcd",
    "secret",
    "MyPassword",
    "myPassword",
    "MyClearTextPassword",
    "ThePasswordToKeyonPFXFile",
    "P@ssw0rd",
    "testpassword",
    "@OurPassword1",
    "@de08nt2128",
    "changeme",
    "changeit",
    "SolarWinds.R0cks",
]

DOMAIN_USER_MATCH_STRINGS = [
    "sql", "svc", "service", "backup", "ccm", "scom", "opsmgr", "adm",
    "adcs", "MSOL", "adsync", "thycotic", "secretserver", "cyberark",
    "configmgr",
]


class Options:
    def __init__(self):
        # Manual Targeting Options
        self.PathTargets = []
        self.ComputerTargets = None
        self.ComputerTargetsLdapFilter = "(objectClass=computer)"
        self.ComputerExclusionFile = None
        self.ComputerExclusions = []
        self.ScanSysvol = True
        self.ScanNetlogon = True
        self.ScanFoundShares = True
        self.InterestLevel = 0
        self.DfsOnly = False
        self.DfsShareDiscovery = False
        self.DfsSharesDict = {}
        self.DfsNamespacePaths = []
        self.CurrentUser = None          # filled in from the SMB credentials
        self.RuleDir = None

        self.TimeOut = 5

        # Concurrency Options
        self.MaxThreads = 60
        self.ShareThreads = 0
        self.TreeThreads = 0
        self.FileThreads = 0
        self.MaxFileQueue = 200000
        self.MaxTreeQueue = 0
        self.MaxShareQueue = 0

        # Logging Options
        self.LogToFile = False
        self.LogFilePath = None
        self.LogType = LogType.Plain
        self.LogTSV = False
        self.Separator = " "
        self.LogToConsole = True
        self.LogLevelString = "info"

        # ShareFinder Options
        self.ShareFinderEnabled = True
        self.TargetDomain = None
        self.TargetDc = None
        self.LogDeniedShares = False

        # FileScanner Options
        self.DomainUserRules = False
        self.DomainUserMinLen = 6
        self.DomainUserNameFormats = [DomainUserNamesFormat.sAMAccountName]

        self.CertPasswords = list(CERT_PASSWORDS)
        self.DomainUsersToMatch = []
        self.DomainUserMatchStrings = list(DOMAIN_USER_MATCH_STRINGS)
        self.DomainUserStrictStrings = []
        self.DomainUsersWordlistRules = ["KeepConfigRegexRed"]

        self.MaxSizeToGrep = 1000000

        self.Snaffle = False
        self.MaxSizeToSnaffle = 10000000
        self.SnafflePath = None

        self.MatchContextBytes = 200

        # Rules
        self.ClassifierRules = []
        self.ShareClassifiers = []
        self.DirClassifiers = []
        self.FileClassifiers = []
        self.ContentsClassifiers = []
        self.PostMatchClassifiers = []

        # --- additions required by the port ---------------------------------
        # The C# runs as a Windows process and uses the caller's token for both
        # SMB and LDAP. We have to be told who to be.
        self.Username = None
        self.Password = None
        self.Domain = ""
        self.LmHash = ""
        self.NtHash = ""
        self.AesKey = None
        self.DoKerberos = False
        self.NoPass = False
        self.DcIp = None
        self.SmbPort = 445
        self.SmbTimeout = 30
        self.MaxConnectionsPerHost = 0   # 0 => derive from thread counts
        self.HtmlReportPath = None
        self.JsonReportPath = None

    # -- ClassifierOptions.cs ------------------------------------------------
    def prepare_classifiers(self):
        """Port of Options.PrepareClassifiers()."""
        from .rules import build_regexes

        for rule in self.ClassifierRules:
            build_regexes(rule)

        # figure out which rules match our interest level flag
        self.ClassifierRules = [r for r in self.ClassifierRules if self._is_interest(r)]

        def bucket(scope):
            return [r for r in self.ClassifierRules if r.EnumerationScope == scope]

        # sorted by MatchAction so Discard rules are evaluated first
        self.ShareClassifiers = sorted(
            bucket(EnumerationScope.ShareEnumeration), key=lambda r: r.MatchAction)
        self.DirClassifiers = sorted(
            bucket(EnumerationScope.DirectoryEnumeration), key=lambda r: r.MatchAction)
        self.FileClassifiers = sorted(
            bucket(EnumerationScope.FileEnumeration), key=lambda r: r.MatchAction)
        self.ContentsClassifiers = sorted(
            bucket(EnumerationScope.ContentsEnumeration), key=lambda r: r.MatchAction)
        # PostMatch is deliberately left unsorted, as in the original
        self.PostMatchClassifiers = bucket(EnumerationScope.PostMatch)

    def _below_interest_bar(self, triage):
        lvl = self.InterestLevel
        return ((triage == Triage.Black and lvl > 3) or
                (triage == Triage.Red and lvl > 2) or
                (triage == Triage.Yellow and lvl > 1) or
                (triage == Triage.Green and lvl > 0))

    def _is_interest(self, classifier):
        """Port of Options.IsInterest().

        Kept faithful to the original including its quirk: a relay rule is
        retained as soon as ANY of its targets is *below* the interest bar.
        """
        try:
            if classifier.RelayTargets is not None:
                for relay_target in classifier.RelayTargets:
                    relay_rule = next(
                        (r for r in self.ClassifierRules if r.RuleName == relay_target), None)
                    if relay_rule is None:
                        raise ValueError(
                            "You have a misconfigured rule trying to relay to " +
                            relay_target + " and no such rule exists by that name.")
                    if self._below_interest_bar(relay_rule.Triage):
                        return True

            return not (
                classifier.MatchAction in (MatchAction.Snaffle, MatchAction.CheckForKeys)
                and self._below_interest_bar(classifier.Triage)
            )
        except Exception as exc:  # matches the C# catch-and-carry-on
            print(classifier.RuleName)
            print(exc)
        return True
