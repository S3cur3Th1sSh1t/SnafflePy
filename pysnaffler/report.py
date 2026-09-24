"""
Result collection and HTML/JSON report generation.

This is additive to the C# original, which only ever writes log lines. The
collector sits on the same messages the logger sees, so the report contains
exactly the findings that were logged.
"""
import json
import os
import re
import threading
from datetime import datetime

from . import dotnet


def _split_unc(path):
    """\\\\HOST\\Share\\dir\\file -> ('HOST', '\\\\HOST\\Share')."""
    if not path or not path.startswith("\\\\"):
        return "", ""
    parts = path[2:].split("\\")
    host = parts[0] if parts else ""
    share = "\\\\%s\\%s" % (host, parts[1]) if len(parts) > 1 else "\\\\%s" % host
    return host, share


class ResultCollector:
    def __init__(self, options, command_line=""):
        self.options = options
        self.command_line = command_line
        self._lock = threading.Lock()
        self.files = []
        self.shares = []
        self.dirs = []
        self.start_time = datetime.now()
        self.end_time = None

    # -- ingestion -----------------------------------------------------------
    def add_file_result(self, message):
        result = message.FileResult
        try:
            path = result.FileInfo.FullName
            host, share = _split_unc(path)

            matched = ""
            context = ""
            if result.TextResult is not None:
                if result.TextResult.MatchedStrings:
                    matched = result.TextResult.MatchedStrings[0]
                context = result.TextResult.MatchContext or ""

            rw = ""
            if result.RwStatus.CanRead:
                rw += "R"
            if result.RwStatus.CanWrite:
                rw += "W"
            if result.RwStatus.CanModify:
                rw += "M"

            alt_name = None
            if result.AlternativeFileInfo is not None:
                alt_name = result.AlternativeFileInfo.AlternativeFullFileName

            entry = {
                "triage": result.MatchedRule.Triage.name if result.MatchedRule else "Gray",
                "rule": result.MatchedRule.RuleName if result.MatchedRule else "",
                "path": path,
                "host": host,
                "share": share,
                "name": result.FileInfo.Name,
                "ext": result.FileInfo.Extension,
                "size": result.FileInfo.Length,
                "sizeHuman": dotnet.bytes_to_string(result.FileInfo.Length),
                "modified": dotnet.format_u(_utc(result.FileInfo.LastWriteTime)),
                "rw": rw,
                "matched": matched,
                "context": context,
                "altName": alt_name,
                "ts": dotnet.format_u(_utc(message.DateTime)),
            }
        except Exception:
            return

        with self._lock:
            self.files.append(entry)

    def add_share_result(self, message):
        share = message.ShareResult
        rw = ""
        if share.RootReadable:
            rw += "R"
        if share.RootWritable:
            rw += "W"
        if share.RootModifyable:
            rw += "M"
        host, _ = _split_unc(share.SharePath or "")
        entry = {
            "triage": share.Triage.name,
            "path": share.SharePath,
            "host": host,
            "rw": rw,
            "comment": share.ShareComment or "",
            "ts": dotnet.format_u(_utc(message.DateTime)),
        }
        with self._lock:
            self.shares.append(entry)

    def add_dir_result(self, message):
        d = message.DirResult
        entry = {
            "triage": d.Triage.name,
            "path": d.DirPath,
            "ts": dotnet.format_u(_utc(message.DateTime)),
        }
        with self._lock:
            self.dirs.append(entry)

    # -- output --------------------------------------------------------------
    def build_data(self):
        with self._lock:
            files = list(self.files)
            shares = list(self.shares)
            dirs = list(self.dirs)

        counts = {"Black": 0, "Red": 0, "Yellow": 0, "Green": 0, "Gray": 0}
        for entry in files:
            counts[entry["triage"]] = counts.get(entry["triage"], 0) + 1

        end = self.end_time or datetime.now()
        options = self.options
        who = options.Username or ""
        if options.Domain and who:
            who = "%s\\%s" % (options.Domain, who)

        import socket
        return {
            "meta": {
                "generated": dotnet.format_u(_utc(datetime.now())),
                "user": who,
                "host": socket.gethostname(),
                "command": self.command_line,
                "startTime": dotnet.format_u(_utc(self.start_time)),
                "endTime": dotnet.format_u(_utc(end)),
                "duration": _duration(end - self.start_time),
                "counts": counts,
                "fileCount": len(files),
                "shareCount": len(shares),
                "dirCount": len(dirs),
            },
            "files": files,
            "shares": shares,
            "dirs": dirs,
        }

    def write_json(self, path):
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.build_data(), fh, indent=2)

    def write_html(self, path):
        template_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "report_template.html")
        with open(template_path, encoding="utf-8") as fh:
            template = fh.read()

        payload = json.dumps(self.build_data(), ensure_ascii=False)
        # keep the data from ever breaking out of the <script> block
        payload = payload.replace("</", "<\\/")

        token = "/*__SNAFFLER_DATA__*/null"
        if token not in template:
            raise RuntimeError("report template is missing the data placeholder")
        html = template.replace(token, payload)

        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html)


def _utc(dt):
    from .runner import _to_utc
    return _to_utc(dt)


def _duration(delta):
    total = int(delta.total_seconds())
    hours, rem = divmod(total, 3600)
    minutes, seconds = divmod(rem, 60)
    return "%02d:%02d:%02d" % (hours, minutes, seconds)
