"""
ClassifierRule and the enums it uses - a port of SnaffCore/Classifiers/ClassifierRule.cs.

The integer values of every enum match the C# declaration order, because
Snaffler sorts its rules with MatchAction.CompareTo() (so Discard rules run
before Snaffle rules) and compares Triage levels by ordinal.
"""
import glob
import os
import tomllib
from enum import IntEnum

from .dotnet import compile_pattern


class EnumerationScope(IntEnum):
    ShareEnumeration = 0
    DirectoryEnumeration = 1
    FileEnumeration = 2
    ContentsEnumeration = 3
    PostMatch = 4


class MatchLoc(IntEnum):
    ShareName = 0
    FilePath = 1
    FileName = 2
    FileExtension = 3
    FileContentAsString = 4
    FileContentAsBytes = 5
    FileLength = 6
    FileMD5 = 7


class MatchListType(IntEnum):
    Exact = 0
    Contains = 1
    Regex = 2
    EndsWith = 3
    StartsWith = 4


class MatchAction(IntEnum):
    Discard = 0
    SendToNextScope = 1
    Snaffle = 2
    Relay = 3
    CheckForKeys = 4
    EnterArchive = 5


class Triage(IntEnum):
    Black = 0
    Green = 1
    Yellow = 2
    Red = 3
    Gray = 4


def _enum(enum_cls, value, default):
    if value is None:
        return default
    if isinstance(value, enum_cls):
        return value
    try:
        return enum_cls[str(value)]
    except KeyError:
        raise ValueError("Invalid %s value: %r" % (enum_cls.__name__, value))


class ClassifierRule:
    """Mirrors the C# class, defaults included."""

    def __init__(self, **kwargs):
        self.EnumerationScope = _enum(
            EnumerationScope, kwargs.get("EnumerationScope"), EnumerationScope.FileEnumeration)
        self.RuleName = kwargs.get("RuleName", "Default")
        self.MatchAction = _enum(MatchAction, kwargs.get("MatchAction"), MatchAction.Snaffle)
        self.RelayTargets = kwargs.get("RelayTargets", None)
        self.Description = kwargs.get("Description", "A description of what a rule does.")
        self.MatchLocation = _enum(MatchLoc, kwargs.get("MatchLocation"), MatchLoc.FileName)
        self.WordListType = _enum(MatchListType, kwargs.get("WordListType"), MatchListType.Contains)
        self.MatchLength = kwargs.get("MatchLength", 0)
        self.MatchMD5 = kwargs.get("MatchMD5", None)
        self.WordList = list(kwargs.get("WordList", []))
        self.Triage = _enum(Triage, kwargs.get("Triage"), Triage.Green)
        self.Regexes = []

    def __repr__(self):
        return "<ClassifierRule %s %s/%s>" % (
            self.RuleName, self.EnumerationScope.name, self.MatchAction.name)


def build_regexes(rule):
    """Port of Options.PrepareClassifiers()'s per-rule regex precompilation.

    Note that Contains is compiled exactly like Regex - in Snaffler a
    "Contains" wordlist is a list of unanchored regexes, not literals.
    """
    rule.Regexes = []
    wlt = rule.WordListType
    for pattern in rule.WordList:
        if wlt == MatchListType.Regex or wlt == MatchListType.Contains:
            expr = pattern
        elif wlt == MatchListType.EndsWith:
            expr = pattern + "$"
        elif wlt == MatchListType.StartsWith:
            expr = "^" + pattern
        elif wlt == MatchListType.Exact:
            expr = "^" + pattern + "$"
        else:
            continue
        rule.Regexes.append(compile_pattern(expr))


def rules_from_toml_dict(data):
    return [ClassifierRule(**entry) for entry in data.get("ClassifierRules", [])]


def load_rules_from_dir(rule_dir):
    """Directory.GetFiles(ruleDir, "*.toml", AllDirectories) + Toml.ReadString."""
    rules = []
    pattern = os.path.join(rule_dir, "**", "*.toml")
    for path in sorted(glob.glob(pattern, recursive=True)):
        with open(path, "rb") as fh:
            rules.extend(rules_from_toml_dict(tomllib.load(fh)))
    return rules


def default_rules_dir():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules", "DefaultRules")


def extended_rules_dir():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules", "ExtendedRules")


def load_default_rules():
    """Equivalent of reading the embedded .toml resources out of the assembly."""
    return load_rules_from_dir(default_rules_dir())


def load_extended_rules():
    """The bundled 'snaffleplus' pack, loaded on top of the base ruleset."""
    return load_rules_from_dir(extended_rules_dir())
