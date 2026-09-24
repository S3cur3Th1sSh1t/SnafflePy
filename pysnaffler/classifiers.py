"""
Port of SnaffCore/Classifiers/*.cs.

TextClassifier, FileClassifier, ContentClassifier, PostMatchClassifier,
DirClassifier and ShareClassifier, plus the result types they emit. The
control flow - including which branches return early and which quirks decide
whether a result is reported - is kept as close to the original as possible,
because that is what determines exactly which findings a scan produces.
"""
import hashlib
import os

from . import dotnet
from .concurrency import BlockingMq
from .context import ctx
from .fs.base import (DirectoryNotFoundError, FileNotFoundError_, IOError_,
                      PathTooLongError, UnauthorizedAccessError)
from .rules import MatchAction, MatchListType, MatchLoc, Triage

_FS_ERRORS = (UnauthorizedAccessError, DirectoryNotFoundError, IOError_,
              FileNotFoundError_, PathTooLongError)


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------
class RwStatus:
    __slots__ = ("CanRead", "CanWrite", "CanModify")

    def __init__(self, can_read=False, can_write=False, can_modify=False):
        self.CanRead = can_read
        self.CanWrite = can_write
        self.CanModify = can_modify


class TextResult:
    __slots__ = ("MatchedStrings", "MatchContext")

    def __init__(self, matched_strings=None, match_context=""):
        self.MatchedStrings = matched_strings or []
        self.MatchContext = match_context


class AlternativeFileInfo:
    """Used when a file has to be reported under a name other than its own -
    the SCCM content library stores files under their hash."""

    __slots__ = ("AlternativeFileName", "AlternativeFullFileName", "AlternativeExtension")

    def __init__(self, alternative_full_file_name=None):
        mq = BlockingMq.get_mq()
        try:
            self.AlternativeFullFileName = alternative_full_file_name
            self.AlternativeFileName = dotnet.get_file_name(alternative_full_file_name)
            self.AlternativeExtension = dotnet.get_extension(alternative_full_file_name)
        except Exception as exc:
            self.AlternativeFullFileName = alternative_full_file_name
            self.AlternativeFileName = None
            self.AlternativeExtension = None
            mq.error("Error on creating alternativeFileInfo: " + str(exc))


class FileResult:
    __slots__ = ("FileInfo", "TextResult", "RwStatus", "MatchedRule", "AlternativeFileInfo")

    def __init__(self, file_info, alt_file_info=None, matched_rule=None, text_result=None):
        options = ctx.MyOptions
        # The C# probes with File.OpenRead() and treats success as "readable";
        # write/modify are never determined (the ACL code is commented out
        # upstream), so they are always false.
        try:
            can_read = file_info.can_read()
        except Exception:
            can_read = False
        self.RwStatus = RwStatus(can_read=can_read, can_modify=False, can_write=False)

        self.FileInfo = file_info
        self.MatchedRule = matched_rule
        self.TextResult = text_result

        if options.Snaffle:
            if options.MaxSizeToSnaffle >= file_info.Length and self.RwStatus.CanRead:
                try:
                    self.snaffle_file(file_info, options.SnafflePath)
                except Exception as exc:
                    BlockingMq.get_mq().error(
                        "Failed to snaffle %s: %s" % (file_info.FullName, exc))

        self.AlternativeFileInfo = alt_file_info

    @staticmethod
    def snaffle_file(file_info, snaffle_path):
        """Grab a copy of a matched file, mirroring the original's path mangling."""
        source_path = file_info.FullName
        cleaned = source_path.replace(":", ".").replace("$", ".").replace("\\\\", "\\")
        cleaned = cleaned.lstrip("\\")
        cleaned = cleaned.replace("\\", os.sep)
        snaffle_file_path = os.path.join(snaffle_path, cleaned)
        os.makedirs(os.path.dirname(snaffle_file_path), exist_ok=True)
        with open(snaffle_file_path, "wb") as fh:
            fh.write(file_info.read_all_bytes())


class DirResult:
    __slots__ = ("ScanDir", "DirPath", "Triage")

    def __init__(self, scan_dir=True, dir_path=None, triage=Triage.Green):
        self.ScanDir = scan_dir
        self.DirPath = dir_path
        self.Triage = triage


class ShareResult:
    __slots__ = ("Snaffle", "ScanShare", "SharePath", "ShareComment", "Listable",
                 "RootWritable", "RootReadable", "RootModifyable", "Triage")

    def __init__(self, share_path=None, share_comment=None, listable=False,
                 triage=Triage.Gray):
        self.Snaffle = False
        self.ScanShare = False
        self.SharePath = share_path
        self.ShareComment = share_comment
        self.Listable = listable
        self.RootWritable = False
        self.RootReadable = False
        self.RootModifyable = False
        self.Triage = triage


# ---------------------------------------------------------------------------
# TextClassifier
# ---------------------------------------------------------------------------
class TextClassifier:
    def __init__(self, rule):
        self.ClassifierRule = rule
        self.Mq = BlockingMq.get_mq()

    def text_match(self, input_str):
        """Returns a TextResult for the first regex that hits, else None.

        MatchedStrings holds the *pattern*, not the matched text - that is what
        the C# puts in the log line.
        """
        for regex in self.ClassifierRule.Regexes:
            try:
                if regex.search(input_str):
                    return TextResult(
                        matched_strings=[regex.pattern],
                        match_context=self.get_context_regex(input_str, regex))
            except Exception as exc:
                self.Mq.error(str(exc))
        return None

    def get_context_regex(self, original, match_regex):
        """GetContext(string, Regex)."""
        try:
            context_bytes = ctx.MyOptions.MatchContextBytes
            if context_bytes == 0:
                return ""

            if len(original) < 6 or len(original) < context_bytes * 2:
                # returned unescaped, as upstream does
                return original

            match = match_regex.search(original)
            found_index = match.start() if match else 0

            context_start = self.subtract_with_floor(found_index, context_bytes, 0)

            if len(original) <= context_start + (context_bytes * 2):
                return dotnet.regex_escape(original[context_start:])

            match_context = ""
            if context_bytes > 0:
                match_context = original[context_start:context_start + context_bytes * 2]

            return dotnet.regex_escape(match_context)
        except Exception as exc:
            self.Mq.error(str(exc))
        return ""

    @staticmethod
    def subtract_with_floor(num1, num2, floor):
        result = num1 - num2
        if result <= floor:
            return floor
        return result


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
def _resolve_names(file_info, alt_file_info):
    """Pick the real file's identity or the alternative one (SCCM)."""
    if alt_file_info is not None:
        return (alt_file_info.AlternativeFileName,
                alt_file_info.AlternativeFullFileName,
                alt_file_info.AlternativeExtension)
    return file_info.Name, file_info.FullName, file_info.Extension


def _string_to_match(rule, file_info, alt_file_info, mq):
    """The MatchLocation switch shared by FileClassifier and PostMatchClassifier.

    Returns (ok, string_to_match). ok=False means "this rule does not apply".
    """
    file_name, full_file_name, extension = _resolve_names(file_info, alt_file_info)
    loc = rule.MatchLocation

    if loc == MatchLoc.FileExtension:
        string_to_match = extension
        # special handling to treat files named like 'thing.kdbx.bak'
        if string_to_match == ".bak":
            sub_name = file_name[:len(file_name) - 4]
            string_to_match = dotnet.get_extension(sub_name)
            if string_to_match == "":
                string_to_match = ".bak"
        if string_to_match == "":
            return False, None
        return True, string_to_match

    if loc == MatchLoc.FileName:
        return True, file_name
    if loc == MatchLoc.FilePath:
        return True, full_file_name
    if loc == MatchLoc.FileLength:
        if rule.MatchLength != file_info.Length:
            return False, None
        return True, None

    mq.error("You've got a misconfigured file classifier rule named " + rule.RuleName + ".")
    return False, None


# ---------------------------------------------------------------------------
# FileClassifier
# ---------------------------------------------------------------------------
class FileClassifier:
    def __init__(self, rule):
        self.ClassifierRule = rule

    def classify_file(self, file_info, alt_file_info=None):
        """Returns True to stop processing this file entirely (a Discard hit)."""
        mq = BlockingMq.get_mq()
        rule = self.ClassifierRule

        ok, string_to_match = _string_to_match(rule, file_info, alt_file_info, mq)
        if not ok:
            return False

        text_result = None
        if string_to_match:
            text_result = TextClassifier(rule).text_match(string_to_match)
            if text_result is None:
                return False

        action = rule.MatchAction

        if action == MatchAction.Discard:
            return True

        if action == MatchAction.Snaffle:
            if len(ctx.MyOptions.PostMatchClassifiers) >= 1:
                for pm_rule in ctx.MyOptions.PostMatchClassifiers:
                    if PostMatchClassifier(pm_rule).classify_post_match(file_info, alt_file_info):
                        # only Discard is supported for PostMatch, so a hit means bail
                        return True

            file_result = FileResult(file_info, alt_file_info,
                                     matched_rule=rule, text_result=text_result)
            if not (file_result.RwStatus.CanRead or file_result.RwStatus.CanModify
                    or file_result.RwStatus.CanWrite):
                return False
            mq.file_result(file_result)
            return False

        if action == MatchAction.CheckForKeys:
            from .certs import x509_match
            x509_match_reason = x509_match(file_info, alt_file_info)
            # upstream tests `>= 0`, which is always true - kept as-is
            match_context = ",".join(x509_match_reason)
            file_result = FileResult(
                file_info, alt_file_info, matched_rule=rule,
                text_result=TextResult(matched_strings=[""], match_context=match_context))
            if not (file_result.RwStatus.CanRead or file_result.RwStatus.CanModify
                    or file_result.RwStatus.CanWrite):
                return False
            mq.file_result(file_result)
            return False

        if action == MatchAction.Relay:
            try:
                logged_content_size_warning = False
                for relay_target in (rule.RelayTargets or []):
                    next_rule = next(
                        (r for r in ctx.MyOptions.ClassifierRules if r.RuleName == relay_target),
                        None)
                    if next_rule is None:
                        raise KeyError(relay_target)

                    from .rules import EnumerationScope
                    if next_rule.EnumerationScope == EnumerationScope.ContentsEnumeration:
                        if file_info.Length > ctx.MyOptions.MaxSizeToGrep:
                            if not logged_content_size_warning:
                                mq.trace("The following file was bigger than the "
                                         "MaxSizeToGrep config parameter:" + file_info.FullName)
                                logged_content_size_warning = True
                            continue
                        ContentClassifier(next_rule).classify_content(file_info, alt_file_info)
                    elif next_rule.EnumerationScope == EnumerationScope.FileEnumeration:
                        FileClassifier(next_rule).classify_file(file_info, alt_file_info)
                    else:
                        mq.error("You've got a misconfigured file ClassifierRule named "
                                 + rule.RuleName + ".")
                return False
            except IOError_ as exc:
                mq.trace(str(exc))
            except Exception as exc:
                mq.error("You've got a misconfigured file ClassifierRule named "
                         + rule.RuleName + ".")
                mq.trace(str(exc))
            return False

        if action == MatchAction.EnterArchive:
            raise NotImplementedError(
                "Haven't implemented walking dir structures inside archives.")

        mq.error("You've got a misconfigured file ClassifierRule named " + rule.RuleName + ".")
        return False

    def size_match(self, file_info):
        return self.ClassifierRule.MatchLength == file_info.Length


# ---------------------------------------------------------------------------
# ContentClassifier
# ---------------------------------------------------------------------------
class ContentClassifier:
    def __init__(self, rule):
        self.ClassifierRule = rule

    def classify_content(self, file_info, alt_file_info=None):
        mq = BlockingMq.get_mq()
        rule = self.ClassifierRule
        try:
            if ctx.MyOptions.MaxSizeToGrep < file_info.Length:
                mq.trace("The following file was bigger than the MaxSizeToGrep "
                         "config parameter:" + file_info.FullName)
                return

            loc = rule.MatchLocation

            if loc == MatchLoc.FileContentAsBytes:
                file_bytes = file_info.read_all_bytes()
                if self.byte_match(file_bytes):
                    self._report(file_info, alt_file_info, mq)
                return

            if loc == MatchLoc.FileContentAsString:
                try:
                    file_string = file_info.read_all_text()
                except UnauthorizedAccessError:
                    return
                except IOError_:
                    return
                text_result = TextClassifier(rule).text_match(file_string)
                if text_result is not None:
                    self._report(file_info, alt_file_info, mq, text_result)
                return

            if loc == MatchLoc.FileLength:
                if self.size_match(file_info):
                    self._report(file_info, alt_file_info, mq)
                return

            if loc == MatchLoc.FileMD5:
                if self.md5_match(file_info):
                    self._report(file_info, alt_file_info, mq)
                return

            mq.error("You've got a misconfigured file ClassifierRule named "
                     + rule.RuleName + ".")
        except UnauthorizedAccessError:
            mq.error("Not authorized to access file: %s" % file_info.FullName)
        except IOError_ as exc:
            mq.error("IO Exception on file: %s. %s" % (file_info.FullName, exc))
        except NotImplementedError:
            raise
        except Exception as exc:
            mq.error(str(exc))

    def _report(self, file_info, alt_file_info, mq, text_result=None):
        file_result = FileResult(file_info, alt_file_info,
                                 matched_rule=self.ClassifierRule,
                                 text_result=text_result)
        if not (file_result.RwStatus.CanRead or file_result.RwStatus.CanModify
                or file_result.RwStatus.CanWrite):
            return
        mq.file_result(file_result)

    def size_match(self, file_info):
        return self.ClassifierRule.MatchLength == file_info.Length

    def md5_match(self, file_info):
        md5_sum = hashlib.md5(file_info.read_all_bytes()).hexdigest().upper()
        return md5_sum == (self.ClassifierRule.MatchMD5 or "").upper()

    def byte_match(self, file_bytes):
        raise NotImplementedError(
            "Haven't implemented byte-based content searching yet lol.")


# ---------------------------------------------------------------------------
# PostMatchClassifier
# ---------------------------------------------------------------------------
class PostMatchClassifier:
    def __init__(self, rule):
        self.ClassifierRule = rule

    def classify_post_match(self, file_info, alt_file_info=None):
        mq = BlockingMq.get_mq()
        rule = self.ClassifierRule

        if alt_file_info is not None:
            mq.trace("File " + file_info.FullName + " is now handled as "
                     + str(alt_file_info.AlternativeFullFileName))

        ok, string_to_match = _string_to_match(rule, file_info, alt_file_info, mq)
        if not ok:
            return False

        if string_to_match:
            if TextClassifier(rule).text_match(string_to_match) is None:
                return False

        if rule.MatchAction == MatchAction.Discard:
            return True

        mq.error("You've got a misconfigured PostMatch rule named " + rule.RuleName +
                 ". Only the Discard action is supported for PostMatch rules.")
        return False

    def size_match(self, file_info):
        return self.ClassifierRule.MatchLength == file_info.Length


# ---------------------------------------------------------------------------
# DirClassifier
# ---------------------------------------------------------------------------
class DirClassifier:
    def __init__(self, rule):
        self.ClassifierRule = rule

    def classify_dir(self, dir_path):
        mq = BlockingMq.get_mq()
        rule = self.ClassifierRule
        dir_result = DirResult(scan_dir=True, dir_path=dir_path, triage=rule.Triage)

        text_result = TextClassifier(rule).text_match(dir_path)
        if text_result is not None:
            if rule.MatchAction == MatchAction.Discard:
                dir_result.ScanDir = False
                return dir_result
            if rule.MatchAction == MatchAction.Snaffle:
                dir_result.Triage = rule.Triage
                mq.dir_result(dir_result)
                return dir_result
            mq.error("You've got a misconfigured file ClassifierRule named "
                     + rule.RuleName + ".")
            return None
        return dir_result


# ---------------------------------------------------------------------------
# ShareClassifier
# ---------------------------------------------------------------------------
class ShareClassifier:
    def __init__(self, rule):
        self.ClassifierRule = rule

    def classify_share(self, share):
        """True means 'a Discard rule matched, do not walk this share'."""
        mq = BlockingMq.get_mq()
        rule = self.ClassifierRule

        text_result = TextClassifier(rule).text_match(share)
        if text_result is not None:
            if rule.MatchAction == MatchAction.Discard:
                return True
            if rule.MatchAction == MatchAction.Snaffle:
                # here Snaffle means 'report it, and keep scanning it'
                if self.is_share_readable(share):
                    mq.share_result(ShareResult(
                        share_path=share, listable=True, triage=rule.Triage))
                return False
            mq.error("You've got a misconfigured share ClassifierRule named "
                     + rule.RuleName + ".")
            return False
        return False

    @staticmethod
    def is_share_readable(share):
        mq = BlockingMq.get_mq()
        try:
            ctx.FileSystem.list_directory(share)
            return True
        except UnauthorizedAccessError:
            return False
        except Exception as exc:
            mq.trace(str(exc))
        return False
