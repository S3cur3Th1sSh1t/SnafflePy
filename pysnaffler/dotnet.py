"""
.NET / Win32 semantics that Snaffler's behaviour and output depend on.

Ports of System.IO.Path, System.Text.RegularExpressions.Regex.Escape,
DateTime's "u" format specifier and Snaffler's own BytesToString() so that
log lines produced by this tool are byte-identical to the C# original.
"""
import math
import re

# ---------------------------------------------------------------------------
# System.IO.Path
# ---------------------------------------------------------------------------
# Snaffler runs on Windows and walks UNC paths, so both separators count and
# ':' is the volume separator.
_SEPS = ("\\", "/")


def is_dir_separator(ch):
    return ch == "\\" or ch == "/"


def get_extension(path):
    """Path.GetExtension.

    Note this is NOT os.path.splitext: .NET does not special-case a leading
    dot, so ".bashrc" has the extension ".bashrc" (splitext says it has none).
    Snaffler's dotfile rules depend on this.
    """
    if path is None:
        return None
    length = len(path)
    for i in range(length - 1, -1, -1):
        ch = path[i]
        if ch == ".":
            if i != length - 1:
                return path[i:]
            return ""
        if is_dir_separator(ch):
            break
    return ""


def get_file_name(path):
    """Path.GetFileName - everything after the last separator or volume colon."""
    if path is None:
        return None
    for i in range(len(path) - 1, -1, -1):
        ch = path[i]
        if is_dir_separator(ch) or ch == ":":
            return path[i + 1:]
    return path


def get_file_name_without_extension(path):
    """Path.GetFileNameWithoutExtension."""
    name = get_file_name(path)
    if name is None:
        return None
    i = name.rfind(".")
    if i == -1:
        return name
    return name[:i]


def get_directory_name(path):
    """Path.GetDirectoryName (windows flavour, no trailing separator)."""
    if path is None:
        return None
    end = len(path)
    while end > 0 and not is_dir_separator(path[end - 1]):
        end -= 1
    if end == 0:
        return ""
    while end > 0 and is_dir_separator(path[end - 1]):
        end -= 1
    return path[:end] if end > 0 else path[:1]


def path_combine(*parts):
    """Path.Combine with backslashes (we only ever build windows-style paths)."""
    result = ""
    for p in parts:
        if not p:
            continue
        if not result:
            result = p
        elif is_dir_separator(result[-1]):
            result += p
        else:
            result += "\\" + p
    return result


# ---------------------------------------------------------------------------
# System.Text.RegularExpressions.Regex.Escape
# ---------------------------------------------------------------------------
# .NET's metachar set. Note it escapes ' ', '#' and ')' but deliberately does
# NOT escape ']' or '}' - Python's re.escape differs on every one of those, so
# match contexts would not line up if we used it.
_METACHARS = frozenset("\t\n\f\r #$()*+.?[\\^{|")
_ESCAPE_MAP = {"\n": "\\n", "\r": "\\r", "\t": "\\t", "\f": "\\f"}


def regex_escape(value):
    """Regex.Escape - used on every match context before it is logged."""
    if not value:
        return value or ""
    out = []
    for ch in value:
        if ch in _METACHARS:
            out.append(_ESCAPE_MAP.get(ch, "\\" + ch))
        else:
            out.append(ch)
    return "".join(out)


# ---------------------------------------------------------------------------
# DateTime
# ---------------------------------------------------------------------------
def format_u(dt):
    """DateTime's "u" (UniversalSortableDateTimePattern): 2009-06-15 13:45:30Z"""
    return dt.strftime("%Y-%m-%d %H:%M:%SZ")


# ---------------------------------------------------------------------------
# Snaffler's BytesToString
# ---------------------------------------------------------------------------
_SUFFIXES = ("B", "kB", "MB", "GB", "TB", "PB", "EB")


def _dotnet_double_to_string(num):
    """C# double.ToString() - 1.0 prints as "1", 3.5 prints as "3.5"."""
    if num == int(num):
        return str(int(num))
    return repr(num)


def bytes_to_string(byte_count):
    if byte_count == 0:
        return "0" + _SUFFIXES[0]
    count = abs(byte_count)
    place = int(math.floor(math.log(count, 1024)))
    # Guard against the log() edge cases .NET's doubles happen to survive.
    if place < 0:
        place = 0
    if place >= len(_SUFFIXES):
        place = len(_SUFFIXES) - 1
    num = round(count / math.pow(1024, place), 1)
    sign = -1 if byte_count < 0 else 1
    return _dotnet_double_to_string(sign * num) + _SUFFIXES[place]


# ---------------------------------------------------------------------------
# Regex construction
# ---------------------------------------------------------------------------
# RegexOptions.Compiled | IgnoreCase | CultureInvariant. Python has no culture
# sensitivity to disable, and re.I on str already does full Unicode casefolding
# the way .NET's invariant culture does.
REGEX_FLAGS = re.IGNORECASE


def compile_pattern(pattern, singleline=False):
    flags = REGEX_FLAGS
    if singleline:
        flags |= re.DOTALL
    return re.compile(pattern, flags)
