"""
Port of Snaffler/Config.cs - argument parsing.

Every flag from the original is kept with the same short and long name and the
same meaning. The only additions are the credential options, which the C#
doesn't need because it runs as a domain user on Windows and we don't.
"""
import argparse
import ipaddress
import os
import socket
import sys

from .concurrency import BlockingMq
from .options import LogType, Options
from .rules import (load_default_rules, load_extended_rules, load_rules_from_dir)


def _merge_rules(config, added):
    """Append rules, letting a later rule of the same name win the lookups.

    Duplicate RuleNames are dropped from the base so the added one takes effect
    (RelayTarget and relay lookups resolve by first match).
    """
    added_names = {r.RuleName for r in added}
    config.ClassifierRules = [r for r in config.ClassifierRules
                              if r.RuleName not in added_names] + added

USAGE_EPILOG = """
authentication (not in the original - the C# uses the caller's Windows token):
  --user USER              Username to authenticate with.
  --password PASS          Password. Omit with --no-pass to try a null session.
  --hashes LM:NT           NTLM hashes instead of a password.
  --aes-key KEY            AES key for Kerberos (128 or 256 bit).
  -K, --kerberos           Use Kerberos. Reads a ccache from KRB5CCNAME if set.
  --no-pass                Don't prompt for a password.
  --dc-ip IP               IP of the domain controller / KDC.
  --smb-port PORT          SMB port, default 445.
  --smb-timeout SECONDS    SMB socket timeout, default 30.
  --conns-per-host N       Max concurrent SMB connections per host.

reporting (additions):
  --html PATH              Write a filterable HTML report.
  --json-report PATH       Write the findings as JSON.
"""


def is_ip(host):
    try:
        socket.inet_aton(host)
        return True
    except OSError:
        return False


# a CIDR this big is almost always a typo; expanding it would exhaust memory
_MAX_CIDR_HOSTS = 4194304   # /10 v4


def expand_targets(tokens, mq=None):
    """Turn a mix of IPs, hostnames and CIDR ranges into a flat host list.

    - `10.0.0.0/24`  -> every usable host in the range
    - `10.0.0.5`     -> kept as-is
    - `fs01.corp.local` / `FS01` -> kept as-is
    Blank lines and `#` comments are ignored; duplicates are removed while
    preserving order.
    """
    out = []
    seen = set()
    for token in tokens:
        token = token.strip()
        if not token or token.startswith("#"):
            continue

        network = None
        if "/" in token:
            try:
                network = ipaddress.ip_network(token, strict=False)
            except ValueError:
                network = None   # not a CIDR (e.g. a UNC-ish hostname) - keep raw

        if network is not None:
            if network.num_addresses > _MAX_CIDR_HOSTS:
                raise ValueError(
                    "Refusing to expand %s: %d addresses is too many (limit %d). "
                    "Use a smaller range." % (token, network.num_addresses,
                                              _MAX_CIDR_HOSTS))
            # /31 and /32 have no "host" addresses in the usual sense - take all
            hosts = list(network) if network.num_addresses <= 2 else list(network.hosts())
            if mq is not None and len(hosts) > 256:
                mq.info("Expanded %s to %d hosts." % (token, len(hosts)))
            for ip in hosts:
                value = str(ip)
                if value not in seen:
                    seen.add(value)
                    out.append(value)
        else:
            if token not in seen:
                seen.add(token)
                out.append(token)
    return out


def build_parser():
    parser = argparse.ArgumentParser(
        prog="snaffler.py",
        description="Snaffler - a tool for pentesters to help find delicious "
                    "candy, by @l0ss and @Sh3r4 (Python port using impacket).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=USAGE_EPILOG,
        add_help=False)

    parser.add_argument("-h", "--help", action="store_true",
                        help="Displays this help.")
    parser.add_argument("-z", "--config", dest="config", metavar="PATH",
                        help="Path to a .toml config file. Run with 'generate' to "
                             "puke a sample config file into the working directory.")
    parser.add_argument("-o", "--outfile", dest="outfile", metavar="PATH",
                        help="Path for output file. You probably want this if "
                             "you're not using -s.")
    parser.add_argument("-v", "--verbosity", dest="verbosity", metavar="LEVEL",
                        help="Controls verbosity level, options are Trace (most "
                             "verbose), Debug (less verbose), Info (less verbose "
                             "still, default), and Data (results only). e.g '-v debug'")
    parser.add_argument("-s", "--stdout", dest="stdout", action="store_true",
                        help="Enables outputting results to stdout as soon as "
                             "they're found. You probably want this if you're not "
                             "using -o.")
    parser.add_argument("-b", "--interest", dest="interest", type=int, metavar="N",
                        help="Interest level to report (0-3)")
    parser.add_argument("-m", "--snaffle", dest="snaffle", metavar="PATH",
                        help="Enables and assigns an output dir for Snaffler to "
                             "automatically snaffle a copy of any found files.")
    parser.add_argument("-l", "--snafflesize", dest="snafflesize", type=int,
                        metavar="BYTES",
                        help="Maximum size of file to snaffle, in bytes. "
                             "Defaults to 10MB.")
    parser.add_argument("-i", "--dirtarget", dest="dirtarget", metavar="PATH",
                        help="Disables computer and share discovery, requires a "
                             "path to a directory in which to perform file discovery.")
    parser.add_argument("-d", "--domain", dest="domain", metavar="DOMAIN",
                        help="Domain to search for computers to search for shares "
                             "on to search for files in. Easy.")
    parser.add_argument("-c", "--domaincontroller", dest="domaincontroller",
                        metavar="HOST",
                        help="Domain controller to query for a list of domain computers.")
    parser.add_argument("-r", "--maxgrepsize", dest="maxgrepsize", type=int,
                        metavar="BYTES",
                        help="The maximum size file (in bytes) to search inside for "
                             "interesting strings. Defaults to 500k.")
    parser.add_argument("-j", "--grepcontext", dest="grepcontext", type=int,
                        metavar="N",
                        help="How many bytes of context either side of found "
                             "strings in files to show, e.g. -j 200")
    parser.add_argument("-u", "--domainusers", dest="domainusers", action="store_true",
                        help="Makes Snaffler grab a list of interesting-looking "
                             "accounts from the domain and uses them in searches.")
    parser.add_argument("-x", "--maxthreads", dest="maxthreads", type=int, metavar="N",
                        help="How many threads to be snaffling with. Any less than "
                             "4 and you're gonna have a bad time.")
    parser.add_argument("-y", "--tsv", dest="tsv", action="store_true",
                        help="Makes Snaffler output as tsv.")
    parser.add_argument("-f", "--dfs", dest="dfs", action="store_true",
                        help="Limits Snaffler to finding file shares via DFS, for "
                             "\"OPSEC\" reasons.")
    parser.add_argument("-a", "--sharesonly", dest="sharesonly", action="store_true",
                        help="Stops after finding shares, doesn't walk their "
                             "filesystems.")
    parser.add_argument("-k", "--exclusions", dest="exclusions", metavar="PATH",
                        help="Path to a file containing a list of computers to "
                             "exclude from scanning.")
    parser.add_argument("-n", "--comptarget", dest="comptarget", metavar="TARGETS",
                        help="Targets to scan instead of AD discovery: a single "
                             "IP/hostname, a CIDR range (10.0.0.0/24), a comma-"
                             "separated mix of those, or a path to a file with one "
                             "IP / hostname / CIDR per line (# comments allowed). "
                             "CIDRs are expanded to their host addresses.")
    parser.add_argument("-p", "--rulespath", dest="rulespath", metavar="DIR",
                        help="Path to a directory full of toml-formatted rules. "
                             "Snaffler will load all of these in place of the "
                             "default ruleset.")
    parser.add_argument("-P", "--plus", dest="plus", action="store_true",
                        help="Also load the bundled 'snaffleplus' extended rules "
                             "(GPP cpassword, modern cloud/CI tokens, GCP/Azure "
                             "keys, terraform state, kubeconfig, DB URIs, ...) on "
                             "top of whichever ruleset is in use.")
    parser.add_argument("--extra-rules", dest="extra_rules", metavar="DIR",
                        help="Path to a directory of toml rules to load IN "
                             "ADDITION to (merged onto) the base ruleset, rather "
                             "than replacing it like -p does.")
    parser.add_argument("-t", "--logtype", dest="logtype", metavar="TYPE",
                        help="Type of log you would like to output. Currently "
                             "supported options are plain and JSON. Defaults to plain.")
    parser.add_argument("-e", "--timeout", dest="timeout", metavar="MINUTES",
                        help="Interval between status updates (in minutes), also "
                             "acts as a timeout for AD data gathered via LDAP. "
                             "Default = 5")

    # -- credentials (port additions) ---------------------------------------
    parser.add_argument("--user", dest="user", metavar="USER")
    parser.add_argument("--password", dest="password", metavar="PASS")
    parser.add_argument("--hashes", dest="hashes", metavar="LM:NT")
    parser.add_argument("--aes-key", dest="aes_key", metavar="KEY")
    parser.add_argument("-K", "--kerberos", dest="kerberos", action="store_true")
    parser.add_argument("--no-pass", dest="no_pass", action="store_true")
    parser.add_argument("--dc-ip", dest="dc_ip", metavar="IP")
    parser.add_argument("--smb-port", dest="smb_port", type=int, default=445)
    parser.add_argument("--smb-timeout", dest="smb_timeout", type=int, default=30)
    parser.add_argument("--conns-per-host", dest="conns_per_host", type=int, default=0)
    parser.add_argument("--html", dest="html", metavar="PATH")
    parser.add_argument("--json-report", dest="json_report", metavar="PATH")

    return parser


def parse(argv):
    """Config.Parse - returns an Options, or None when the user wanted help."""
    mq = BlockingMq.get_mq()
    mq.info("Parsing args...")

    parser = build_parser()

    if (not argv or "--help" in argv or "/?" in argv or "help" in argv
            or "-h" in argv):
        parser.print_help()
        return None

    args = parser.parse_args(argv)
    if args.help:
        parser.print_help()
        return None

    parsed_config = Options()

    if args.timeout:
        try:
            timeout_val = int(args.timeout)
            mq.info("Set timeout/update interval to " + str(timeout_val) + " minutes.")
            parsed_config.TimeOut = timeout_val
        except ValueError:
            mq.error("Invalid timeout value passed, defaulting to 5 mins.")

    if args.logtype:
        parsed_config.LogType = LogType.Plain
        if args.logtype.lower() == "json":
            parsed_config.LogType = LogType.JSON
        else:
            mq.info("Invalid type argument passed (" + args.logtype +
                    ") defaulting to plaintext")

    if args.rulespath:
        parsed_config.RuleDir = args.rulespath

    if args.outfile:
        parsed_config.LogToFile = True
        parsed_config.LogFilePath = args.outfile
        mq.degub("Logging to file at " + parsed_config.LogFilePath)

    if args.dfs:
        parsed_config.DfsOnly = True

    if args.exclusions:
        comp_exclusions = []
        with open(args.exclusions) as fh:
            for line in fh.read().splitlines():
                line = line.strip()
                if not line:
                    continue
                if is_ip(line):
                    comp_exclusions.append(line)
                else:
                    try:
                        _n, _a, addresses = socket.gethostbyname_ex(line)
                        comp_exclusions.extend(addresses)
                    except Exception as exc:
                        print(exc)
                        continue
        if comp_exclusions:
            parsed_config.ComputerExclusions = comp_exclusions
            parsed_config.ComputerExclusionFile = args.exclusions
        else:
            raise ValueError("Failed to get a valid list of excluded computers "
                             "from the excluded computers list.")

    if args.comptarget:
        raw_tokens = []
        if os.path.isfile(args.comptarget):
            with open(args.comptarget) as fh:
                raw_tokens.extend(line.strip() for line in fh if line.strip())
        else:
            # a single value or a comma-separated list; each entry may itself be
            # an IP, a hostname, or a CIDR range
            raw_tokens.extend(x.strip() for x in args.comptarget.split(","))
        comp_targets = expand_targets(raw_tokens, mq)
        if not comp_targets:
            raise ValueError("No usable targets parsed from " + args.comptarget)
        parsed_config.ComputerTargets = comp_targets

    if args.sharesonly:
        parsed_config.ScanFoundShares = False

    if args.maxthreads:
        parsed_config.MaxThreads = args.maxthreads

    parsed_config.ShareThreads = parsed_config.MaxThreads // 3
    parsed_config.FileThreads = parsed_config.MaxThreads // 3
    parsed_config.TreeThreads = parsed_config.MaxThreads // 3

    if args.tsv:
        parsed_config.LogTSV = True
        if parsed_config.Separator == " ":
            parsed_config.Separator = "\t"

    if args.verbosity:
        parsed_config.LogLevelString = args.verbosity
        mq.degub("Requested verbosity level: " + parsed_config.LogLevelString)

    # results only go to the console when -s is given
    parsed_config.LogToConsole = bool(args.stdout)
    mq.degub("Enabled logging to stdout.")

    if args.domain:
        parsed_config.TargetDomain = args.domain
        parsed_config.Domain = args.domain
        mq.degub("Target domain is " + args.domain)

    if args.domaincontroller:
        parsed_config.TargetDc = args.domaincontroller
        mq.degub("Target DC is " + args.domaincontroller)

    if args.domainusers:
        parsed_config.DomainUserRules = True
        mq.degub("Enabled use of domain user accounts in rules.")

    if args.dirtarget:
        parsed_config.ShareFinderEnabled = False
        mq.degub("Disabled finding shares.")

        raw_targets = args.dirtarget.split(",") if "," in args.dirtarget \
            else [args.dirtarget]
        for path_target in raw_targets:
            if len(path_target) > 4:
                parsed_config.PathTargets.append(path_target.rstrip("\\"))
            else:
                parsed_config.PathTargets.append(path_target)

        for path_target in parsed_config.PathTargets:
            mq.degub("Targeting path:" + path_target)

    if args.maxgrepsize:
        parsed_config.MaxSizeToGrep = args.maxgrepsize
        mq.degub("We won't bother looking inside files if they're bigger than "
                 + str(parsed_config.MaxSizeToGrep) + " bytes")

    if args.snafflesize:
        parsed_config.MaxSizeToSnaffle = args.snafflesize

    if args.interest is not None:
        parsed_config.InterestLevel = args.interest
        mq.degub("Requested interest level: " + str(parsed_config.InterestLevel))

    if args.grepcontext is not None:
        parsed_config.MatchContextBytes = args.grepcontext
        mq.degub("We'll show you " + str(args.grepcontext) +
                 " bytes of context around matches inside files.")

    if args.snaffle:
        if len(args.snaffle) <= 0:
            mq.error("-m or -mirror arg requires a path value.")
            raise ValueError("Invalid argument combination.")
        parsed_config.Snaffle = True
        parsed_config.SnafflePath = args.snaffle.rstrip("\\")
        mq.degub("Mirroring matched files to path " + parsed_config.SnafflePath)

    if args.config:
        if args.config == "generate":
            write_default_toml(parsed_config, "default.toml")
            print("Wrote config values to ./default.toml")
            parsed_config.LogToConsole = True
            mq.degub("Enabled logging to stdout.")
            return None
        apply_toml_config(parsed_config, args.config)
        mq.info("Read config file from " + args.config)

    # -- credentials ---------------------------------------------------------
    parsed_config.Username = args.user or ""
    parsed_config.Password = args.password or ""
    if args.hashes:
        lm, _, nt = args.hashes.partition(":")
        parsed_config.LmHash = lm
        parsed_config.NtHash = nt
    parsed_config.AesKey = args.aes_key
    parsed_config.DoKerberos = bool(args.kerberos or args.aes_key)
    parsed_config.NoPass = bool(args.no_pass)
    parsed_config.DcIp = args.dc_ip or parsed_config.TargetDc
    parsed_config.SmbPort = args.smb_port
    parsed_config.SmbTimeout = args.smb_timeout
    parsed_config.MaxConnectionsPerHost = args.conns_per_host
    parsed_config.HtmlReportPath = args.html
    parsed_config.JsonReportPath = args.json_report

    if (parsed_config.Username and not parsed_config.Password
            and not parsed_config.NtHash and not parsed_config.NoPass
            and not parsed_config.DoKerberos):
        from getpass import getpass
        parsed_config.Password = getpass("Password: ")

    parsed_config.CurrentUser = (
        "%s\\%s" % (parsed_config.Domain, parsed_config.Username)
        if parsed_config.Domain and parsed_config.Username
        else parsed_config.Username)

    if not parsed_config.LogToConsole and not parsed_config.LogToFile:
        mq.error("\nYou didn't enable output to file or to the console so you "
                 "won't see any results or debugs or anything. Your l0ss.")
        raise ValueError("Pointless argument combination.")

    if len(parsed_config.ClassifierRules) <= 0:
        if not parsed_config.RuleDir or not parsed_config.RuleDir.strip():
            parsed_config.ClassifierRules = load_default_rules()
        else:
            parsed_config.ClassifierRules = load_rules_from_dir(parsed_config.RuleDir)

    # merge extra rules ON TOP of the base set (unlike -p, which replaced it)
    if args.plus:
        added = load_extended_rules()
        _merge_rules(parsed_config, added)
        mq.info("Loaded %d bundled snaffleplus rules." % len(added))
    if args.extra_rules:
        added = load_rules_from_dir(args.extra_rules)
        _merge_rules(parsed_config, added)
        mq.info("Loaded %d extra rules from %s." % (len(added), args.extra_rules))

    parsed_config.prepare_classifiers()

    mq.info("Parsed args successfully.")
    return parsed_config


# -- toml config in/out ------------------------------------------------------
_SCALAR_KEYS = [
    "ComputerTargetsLdapFilter", "ScanSysvol", "ScanNetlogon", "ScanFoundShares",
    "InterestLevel", "DfsOnly", "DfsShareDiscovery", "RuleDir", "TimeOut",
    "MaxThreads", "ShareThreads", "TreeThreads", "FileThreads", "MaxFileQueue",
    "MaxTreeQueue", "MaxShareQueue", "LogToFile", "LogFilePath", "LogTSV",
    "Separator", "LogToConsole", "LogLevelString", "ShareFinderEnabled",
    "TargetDomain", "TargetDc", "LogDeniedShares", "DomainUserRules",
    "DomainUserMinLen", "MaxSizeToGrep", "Snaffle", "MaxSizeToSnaffle",
    "SnafflePath", "MatchContextBytes",
]

_LIST_KEYS = [
    "PathTargets", "ComputerExclusions", "DfsNamespacePaths", "CertPasswords",
    "DomainUserMatchStrings", "DomainUserStrictStrings", "DomainUsersWordlistRules",
]


def apply_toml_config(options, path):
    """Toml.ReadFile<Options>() - config values override the parsed args."""
    import tomllib
    from .rules import ClassifierRule

    with open(path, "rb") as fh:
        data = tomllib.load(fh)

    for key in _SCALAR_KEYS + _LIST_KEYS:
        if key in data:
            setattr(options, key, data[key])

    if "LogType" in data:
        options.LogType = LogType.JSON \
            if str(data["LogType"]).lower() in ("json", "1") else LogType.Plain

    if "ComputerTargets" in data:
        options.ComputerTargets = data["ComputerTargets"]

    if "ClassifierRules" in data:
        options.ClassifierRules = [ClassifierRule(**r) for r in data["ClassifierRules"]]

    return options


def _toml_value(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        return "[" + ", ".join(_toml_value(v) for v in value) + "]"
    text = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return '"%s"' % text


def write_default_toml(options, path):
    """-z generate: dump the current config, rules included."""
    lines = []
    for key in _SCALAR_KEYS:
        value = getattr(options, key, None)
        if value is None:
            continue
        lines.append("%s = %s" % (key, _toml_value(value)))
    for key in _LIST_KEYS:
        value = getattr(options, key, None)
        if value is None:
            continue
        lines.append("%s = %s" % (key, _toml_value(value)))

    rules = options.ClassifierRules or load_default_rules()
    for rule in rules:
        lines.append("")
        lines.append("[[ClassifierRules]]")
        lines.append("EnumerationScope = %s" % _toml_value(rule.EnumerationScope.name))
        lines.append("RuleName = %s" % _toml_value(rule.RuleName))
        lines.append("MatchAction = %s" % _toml_value(rule.MatchAction.name))
        if rule.RelayTargets:
            lines.append("RelayTargets = %s" % _toml_value(rule.RelayTargets))
        lines.append("Description = %s" % _toml_value(rule.Description))
        lines.append("MatchLocation = %s" % _toml_value(rule.MatchLocation.name))
        lines.append("WordListType = %s" % _toml_value(rule.WordListType.name))
        lines.append("MatchLength = %s" % _toml_value(rule.MatchLength))
        lines.append("WordList = %s" % _toml_value(rule.WordList))
        lines.append("Triage = %s" % _toml_value(rule.Triage.name))

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
