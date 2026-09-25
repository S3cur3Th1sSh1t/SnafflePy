"""
Port of Snaffler/SnaffleRunner.cs - the console/file logging front end.

The log templates, the message prefixes and the console colour rules are all
reproduced from the original so that output is drop-in compatible with anything
that already parses Snaffler logs.
"""
import json
import os
import re
import socket
import sys
import threading

from . import dotnet
from .concurrency import BlockingMq, SnafflerMessageType
from .context import ctx
from .options import LogType
from .progress import Heartbeat

# -- NLog levels -------------------------------------------------------------
TRACE, DEBUG, INFO, WARN, ERROR, FATAL = range(6)
LEVEL_NAMES = ["Trace", "Debug", "Info", "Warn", "Error", "Fatal"]

# -- ConsoleOutputColor -> ANSI ---------------------------------------------
_FG = {
    "Black": 30, "DarkRed": 31, "DarkGreen": 32, "DarkYellow": 33,
    "DarkBlue": 34, "DarkMagenta": 35, "DarkCyan": 36, "Gray": 37,
    "DarkGray": 90, "Red": 91, "Green": 92, "Yellow": 93, "Blue": 94,
    "Magenta": 95, "Cyan": 96, "White": 97,
}


def _ansi(fg, bg):
    return "\x1b[%d;%dm" % (_FG[fg], _FG[bg] + 10)


RESET = "\x1b[0m"

# The ConsoleWordHighlightingRules from SnaffleRunner, in the order NLog
# applies them. (literal_or_regex, is_regex, foreground, background)
HIGHLIGHT_RULES = [
    ("{Green}", False, "DarkGreen", "White"),
    ("{Yellow}", False, "DarkYellow", "White"),
    ("{Red}", False, "DarkRed", "White"),
    ("{Black}", False, "Black", "White"),
    ("[Trace]", False, "DarkGray", "Black"),
    ("[Degub]", False, "Gray", "Black"),
    ("[Info]", False, "White", "Black"),
    ("[Error]", False, "Magenta", "Black"),
    ("[Fatal]", False, "Red", "Black"),
    ("[File]", False, "Green", "Black"),
    ("[Share]", False, "Yellow", "Black"),
    (r"<.*\|.*\|.*\|.*?>", True, "Cyan", "Black"),
    (r"^\d\d\d\d-\d\d\-\d\d \d\d:\d\d:\d\d [\+-]\d\d:\d\d ", True, "DarkGray", "Black"),
    (r"\((?:[^\)]*\)){1}", True, "DarkMagenta", "Black"),
]

_COMPILED_HIGHLIGHTS = [
    (re.compile(re.escape(pattern) if not is_regex else pattern), fg, bg)
    for pattern, is_regex, fg, bg in HIGHLIGHT_RULES
]


def colorize(text):
    """Apply the word-highlighting rules, first rule wins on overlap."""
    spans = []
    taken = [False] * len(text)
    for regex, fg, bg in _COMPILED_HIGHLIGHTS:
        for match in regex.finditer(text):
            start, end = match.start(), match.end()
            if start == end:
                continue
            if any(taken[start:end]):
                continue
            for i in range(start, end):
                taken[i] = True
            spans.append((start, end, fg, bg))

    if not spans:
        return text

    spans.sort()
    out = []
    pos = 0
    for start, end, fg, bg in spans:
        out.append(text[pos:start])
        out.append(_ansi(fg, bg))
        out.append(text[start:end])
        out.append(RESET)
        pos = end
    out.append(text[pos:])
    return "".join(out)


def _load_banner():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "banner.txt")
    with open(path, encoding="utf-8") as fh:
        return fh.read().split("\n")


BANNER_LINES = _load_banner()

BANNER_COLORS = ["Red", "DarkYellow", "Yellow", "Green", "Blue", "DarkMagenta", "White"]


class SnaffleRunner:
    def __init__(self):
        self.Mq = None
        self.Options = None
        self.LogLevel = INFO
        self._host_string = None
        self.file_result_template = None
        self.share_result_template = None
        self.dir_result_template = None
        self._logfile = None
        self._lock = threading.Lock()
        self._json_entries = []
        self._heartbeat = None

    # -- prefix --------------------------------------------------------------
    def host_string(self):
        if not self._host_string:
            options = self.Options
            if options is not None and options.Username:
                domain = options.Domain or ""
                who = ("%s\\%s" % (domain, options.Username)) if domain else options.Username
            else:
                who = os.environ.get("USER", "")
            self._host_string = "[" + who + "@" + socket.gethostname() + "]"
        return self._host_string

    # -- setup ---------------------------------------------------------------
    def configure(self, options):
        self.Options = options
        self.Mq = BlockingMq.get_mq()

        sep = options.Separator
        if options.LogTSV:
            self.file_result_template = sep.join("{%d}" % i for i in range(11))
            self.share_result_template = sep.join("{%d}" % i for i in range(3))
            self.dir_result_template = sep.join("{%d}" % i for i in range(2))
        else:
            self.file_result_template = "{{{0}}}<{1}|{2}{3}{4}|{5}|{6}|{7}>({8}{9}) {10}"
            self.share_result_template = "{{{0}}}<{1}>({2}) {3}"
            self.dir_result_template = "{{{0}}}({1})"

        self.parse_log_level_string(options.LogLevelString)

        if options.LogToFile:
            self._logfile = open(options.LogFilePath, "w", encoding="utf-8")

        # only ever on an interactive console - it must not land in a pipe
        if options.LogToConsole and sys.stdout.isatty():
            self._heartbeat = Heartbeat(sys.stdout, self._lock)
            self._heartbeat.start()

    def parse_log_level_string(self, log_level_string):
        level = (log_level_string or "").lower()
        if level in ("debug", "degub"):
            self.LogLevel = DEBUG
            self.Mq.degub("Set verbosity level to degub.")
        elif level == "trace":
            self.LogLevel = TRACE
            self.Mq.degub("Set verbosity level to trace.")
        elif level == "data":
            self.LogLevel = WARN
            self.Mq.degub("Set verbosity level to data.")
        elif level == "info":
            self.LogLevel = INFO
            self.Mq.degub("Set verbosity level to info.")
        else:
            self.LogLevel = INFO
            self.Mq.error("Invalid verbosity level " + str(log_level_string) +
                          " falling back to default level (info).")

    def _enabled(self, level):
        # a 'data' run logs results and nothing else
        if self.LogLevel == WARN:
            return level == WARN
        return level >= self.LogLevel

    # -- output --------------------------------------------------------------
    def _write(self, level, text, message=None):
        if not self._enabled(level):
            return
        with self._lock:
            if self._heartbeat is not None:
                self._heartbeat.erase()
            if self.Options.LogToConsole:
                stream = sys.stdout
                if stream.isatty():
                    stream.write(colorize(text) + "\n")
                else:
                    stream.write(text + "\n")
                stream.flush()
            if self._logfile is not None:
                if self.Options.LogType == LogType.JSON:
                    self._logfile.write(json.dumps({
                        "time": message.DateTime.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                        "level": LEVEL_NAMES[level],
                        "message": text,
                        "eventProperties": _json_event_properties(message),
                    }) + "\n")
                else:
                    self._logfile.write(text + "\n")
                self._logfile.flush()

    def print_banner(self):
        for line, color in zip(BANNER_LINES, BANNER_COLORS):
            if sys.stdout.isatty():
                sys.stdout.write("\x1b[%dm%s%s\n" % (_FG[color], line, RESET))
            else:
                sys.stdout.write(line + "\n")
        sys.stdout.write("\n\n")
        sys.stdout.flush()

    # -- the message pump ----------------------------------------------------
    def handle_output(self):
        for message in self.Mq.consume():
            self.process_message(message)
            if message.Type in (SnafflerMessageType.Fatal, SnafflerMessageType.Finish):
                self.stop_heartbeat()
                return True
        return False

    def stop_heartbeat(self):
        if self._heartbeat is not None:
            self._heartbeat.stop()
            self._heartbeat = None

    def process_message(self, message):
        sep = self.Options.Separator
        datetime_prefix = "%s%s%s%s" % (
            self.host_string(), sep, dotnet.format_u(_to_utc(message.DateTime)), sep)

        t = message.Type
        if t == SnafflerMessageType.Trace:
            self._write(TRACE, datetime_prefix + "[Trace]" + sep + str(message.Message), message)
        elif t == SnafflerMessageType.Degub:
            self._write(DEBUG, datetime_prefix + "[Degub]" + sep + str(message.Message), message)
        elif t == SnafflerMessageType.Info:
            self._write(INFO, datetime_prefix + "[Info]" + sep + str(message.Message), message)
        elif t == SnafflerMessageType.FileResult:
            if ctx.Collector is not None:
                ctx.Collector.add_file_result(message)
            if self._heartbeat is not None:
                self._heartbeat.found += 1
            self._write(WARN, datetime_prefix + "[File]" + sep +
                        self.file_result_log_from_message(message), message)
        elif t == SnafflerMessageType.DirResult:
            if ctx.Collector is not None:
                ctx.Collector.add_dir_result(message)
            self._write(WARN, datetime_prefix + "[Dir]" + sep +
                        self.dir_result_log_from_message(message), message)
        elif t == SnafflerMessageType.ShareResult:
            if ctx.Collector is not None:
                ctx.Collector.add_share_result(message)
            self._write(WARN, datetime_prefix + "[Share]" + sep +
                        self.share_result_log_from_message(message), message)
        elif t == SnafflerMessageType.Error:
            self._write(ERROR, datetime_prefix + "[Error]" + sep + str(message.Message), message)
        elif t == SnafflerMessageType.Fatal:
            self._write(FATAL, datetime_prefix + "[Fatal]" + sep + str(message.Message), message)
        elif t == SnafflerMessageType.Finish:
            self._write(INFO, "Snaffler out.", message)
            if self.Options.LogType == LogType.JSON and self.Options.LogToFile:
                self._write(INFO, "Normalising output, please wait...", message)
                self.fix_json_output()

    # -- result formatting ---------------------------------------------------
    def share_result_log_from_message(self, message):
        share = message.ShareResult
        rw_string = ""
        if share.RootReadable:
            rw_string += "R"
        if share.RootWritable:
            rw_string += "W"
        if share.RootModifyable:
            rw_string += "M"
        return self.share_result_template.format(
            share.Triage.name, share.SharePath, rw_string, share.ShareComment or "")

    def dir_result_log_from_message(self, message):
        d = message.DirResult
        return self.dir_result_template.format(d.Triage.name, d.DirPath)

    def file_result_log_from_message(self, message):
        try:
            result = message.FileResult
            matched_classifier = result.MatchedRule.RuleName
            triage_string = result.MatchedRule.Triage.name
            modified_stamp = dotnet.format_u(_to_utc(result.FileInfo.LastWriteTime))

            canread = "R" if result.RwStatus.CanRead else ""
            canwrite = "W" if result.RwStatus.CanWrite else ""
            canmodify = "M" if result.RwStatus.CanModify else ""

            file_size = result.FileInfo.Length
            if self.Options.LogTSV:
                file_size_string = str(file_size)
            else:
                file_size_string = dotnet.bytes_to_string(file_size)

            filepath = result.FileInfo.FullName

            matchedstring = ""
            matchcontext = ""
            if result.TextResult is not None:
                matchedstring = result.TextResult.MatchedStrings[0] \
                    if result.TextResult.MatchedStrings else ""
                matchcontext = result.TextResult.MatchContext or ""
                # keep log lines on one line
                matchcontext = re.sub(r"\r\n?|\n", "\\\\n", matchcontext)

            altname = ""
            if result.AlternativeFileInfo is not None and \
                    result.AlternativeFileInfo.AlternativeFullFileName is not None:
                altname = "#_as_#" + result.AlternativeFileInfo.AlternativeFullFileName

            return self.file_result_template.format(
                triage_string, matched_classifier, canread, canwrite, canmodify,
                matchedstring, file_size_string, modified_stamp, filepath, altname,
                matchcontext)
        except Exception as exc:
            print(exc)
            try:
                print(message.FileResult.FileInfo.FullName)
            except Exception:
                pass
            return ""

    def fix_json_output(self):
        """Port of FixJSONOutput - wrap the per-line JSON objects into one doc."""
        path = self.Options.LogFilePath
        with self._lock:
            if self._logfile is not None:
                self._logfile.flush()
                self._logfile.close()
                self._logfile = None

            with open(path, encoding="utf-8") as fh:
                lines = [line for line in fh.read().split("\n") if line.strip()]

            with open(path, "w", encoding="utf-8") as fh:
                fh.write('{"entries": [\n')
                for line in lines[:-1]:
                    fh.write(line + ",\n")
                if lines:
                    fh.write(lines[-1] + "\n")
                fh.write("]\n}")

    def close(self):
        self.stop_heartbeat()
        if self._logfile is not None:
            try:
                self._logfile.close()
            except Exception:
                pass
            self._logfile = None


def _to_utc(dt):
    """message.DateTime.ToUniversalTime().

    A naive datetime is local time, and astimezone() resolves the offset that
    applied at that instant rather than the one that applies now, so timestamps
    from either side of a DST change convert correctly.
    """
    from datetime import timezone
    try:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    except (OverflowError, OSError, ValueError):
        return dt


def _json_event_properties(message):
    """Approximates NLog's IncludeAllProperties dump of the message object."""
    if message is None:
        return {}
    props = {"Type": message.Type.name}
    if message.FileResult is not None:
        r = message.FileResult
        props["FileResult"] = {
            "FullName": r.FileInfo.FullName,
            "Length": r.FileInfo.Length,
            "LastWriteTime": dotnet.format_u(_to_utc(r.FileInfo.LastWriteTime)),
            "RuleName": r.MatchedRule.RuleName if r.MatchedRule else None,
            "Triage": r.MatchedRule.Triage.name if r.MatchedRule else None,
            "CanRead": r.RwStatus.CanRead,
            "CanWrite": r.RwStatus.CanWrite,
            "CanModify": r.RwStatus.CanModify,
            "MatchedStrings": r.TextResult.MatchedStrings if r.TextResult else None,
            "MatchContext": r.TextResult.MatchContext if r.TextResult else None,
        }
    if message.ShareResult is not None:
        s = message.ShareResult
        props["ShareResult"] = {
            "SharePath": s.SharePath,
            "ShareComment": s.ShareComment,
            "Triage": s.Triage.name,
            "Listable": s.Listable,
            "RootReadable": s.RootReadable,
            "RootWritable": s.RootWritable,
            "RootModifyable": s.RootModifyable,
        }
    if message.DirResult is not None:
        d = message.DirResult
        props["DirResult"] = {"DirPath": d.DirPath, "Triage": d.Triage.name}
    return props
