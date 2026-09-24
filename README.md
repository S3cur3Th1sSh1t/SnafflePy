# Snaffler (Python)

A feature-for-feature Python port of [SnaffCon/Snaffler](https://github.com/SnaffCon/Snaffler),
using **impacket** for SMB share enumeration, file access and authentication, and
**ldap3/impacket LDAP** for Active Directory discovery.

It ships the **same 88 default rules with byte-identical regexes**, produces the
**same log line format**, and adds a filterable HTML report.

Unlike the original it does not need to run on a domain-joined Windows box — you
give it credentials and it runs from Linux/macOS.

```
 .::::::.:::.    :::.  :::.    .-:::::'.-:::::':::    .,:::::: :::::::..
;;;`    ``;;;;,  `;;;  ;;`;;   ;;;'''' ;;;'''' ;;;    ;;;;'''' ;;;;``;;;;
'[==/[[[[, [[[[[. '[[ ,[[ '[[, [[[,,== [[[,,== [[[     [[cccc   [[[,/[[['
  '''    $ $$$ 'Y$c$$c$$$cc$$$c`$$$'`` `$$$'`` $$'     $$""   $$$$$$c
 88b    dP 888    Y88 888   888,888     888   o88oo,.__888oo,__ 888b '88bo,
  'YMmMY'  MMM     YM YMM   ''` 'MM,    'MM,  ''''YUMMM''''YUMMMMMMM   'W'
```

![Snaffler HTML report](docs/img/report-overview.png)

## Why

The original Snaffler is a superb tool, but it's a Windows .NET binary that
expects to run as a domain user on a domain-joined host. This port lets you run
the exact same rules and get the exact same findings **from Linux/macOS with
explicit credentials** — over impacket, the way you'd run `secretsdump` or
`smbclient.py` — and adds a self-contained HTML report for triage and hand-off.

## Features

- **Identical findings.** The 88 default rules and all 385 regexes are the
  upstream `.toml` files, unmodified; output is [byte-for-byte identical](#fidelity)
  to the original (verified against a compiled C# oracle).
- **impacket everything.** SMB share enumeration (srvsvc `NetrShareEnum`), file
  reads, and LDAP AD discovery all go through impacket.
- **Auth: password, pass-the-hash, Kerberos, null session.**
- **Flexible targeting.** AD auto-discovery, or a single host, a CIDR range, a
  comma-list, or a file of IPs/hostnames/CIDRs.
- **Filterable HTML report** — offline, single file, triage tiles, share/host/
  rule/ext filters, search, sortable/expandable rows, CSV/JSON export.
- **`snaffleplus` extended rules** (opt-in) for GPP cpassword, modern cloud/CI
  tokens, GCP/Azure keys, terraform state, kubeconfig and more.
- Same TSV / JSON / plain log formats and console colours as upstream.

> [!IMPORTANT]
> For **authorized security testing only** — pentests, red-team engagements with
> a signed statement of work, CTFs, and lab/research use. Scanning file shares
> you have no permission to touch is likely illegal. You are responsible for
> staying in scope.

## Install

```bash
pip install -r requirements.txt     # impacket, cryptography
python3 snaffler.py --help
```

Python 3.11+ (uses `tomllib`).

### uv

[uv](https://docs.astral.sh/uv/) installs the tool into an isolated environment,
pulls in `impacket` and `cryptography`, and puts a `snaffler` executable on your
`PATH`:

```bash
uv tool install git+https://github.com/S3cur3Th1sSh1t/SnafflePy
snaffler --help
```

From a checkout, install the local project instead:

```bash
git clone https://github.com/S3cur3Th1sSh1t/SnafflePy
cd SnafflePy
uv tool install .
```

`uvx` runs it once without installing anything:

```bash
uvx --from git+https://github.com/S3cur3Th1sSh1t/SnafflePy snaffler --help
```

Upgrade with `uv tool upgrade pysnaffler`, remove with
`uv tool uninstall pysnaffler`.

## Usage

The flags are the originals. Credentials are the only addition, because the C#
version borrows the caller's Windows token and we have no token to borrow.

```bash
# full domain scan: find computers in AD, enumerate shares, walk them
python3 snaffler.py -s -d corp.local -c dc01.corp.local \
    --user svc_scan --password 'Passw0rd!' -o snaffler.log --html report.html

# target specific hosts, no AD discovery
python3 snaffler.py -s -n fs01,fs02.corp.local --user bob --password hunter2 \
    -d corp.local --html report.html

# target a CIDR range (expanded to its host addresses)
python3 snaffler.py -s -n 10.0.0.0/24 --user bob --password hunter2 -d corp.local

# target a file mixing IPs, CIDRs and hostnames (one per line, # comments ok)
python3 snaffler.py -s -n targets.txt --user bob --hashes :31d6cfe0d16ae931b73c59d7e0c089c0 -d corp.local

# pass-the-hash
python3 snaffler.py -s -n fs01 --user bob --hashes aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 -d corp.local

# kerberos (reads a ccache from KRB5CCNAME)
KRB5CCNAME=bob.ccache python3 snaffler.py -s -n fs01.corp.local -K -d corp.local --dc-ip 10.0.0.1

# scan specific share paths only
python3 snaffler.py -s -i '\\fs01\Finance$,\\fs01\HR$' --user bob --password hunter2 -d corp.local

# scan a local directory (no credentials needed)
python3 snaffler.py -s -i /mnt/loot -v data

# DFS-only, for quieter enumeration
python3 snaffler.py -s -d corp.local -f --user svc_scan --password 'Passw0rd!'

# only report the really juicy stuff, and grab copies of it
python3 snaffler.py -s -d corp.local --user bob --password hunter2 \
    -b 3 -m ./snaffled --html report.html
```

**You need `-s` (stdout) or `-o` (outfile) or both**, otherwise the tool refuses
to run — same as upstream.

### Original flags

| Flag | Meaning |
|---|---|
| `-s, --stdout` | print results to the console as they're found |
| `-o, --outfile` | write the log to a file |
| `-v, --verbosity` | `trace` \| `debug` \| `info` (default) \| `data` (results only) |
| `-t, --logtype` | `plain` (default) or `json` |
| `-y, --tsv` | tab-separated output instead of the pretty format |
| `-b, --interest` | 0–3; raise it to drop the lower-severity rules |
| `-i, --dirtarget` | scan these paths only; skips computer and share discovery |
| `-n, --comptarget` | targets to scan instead of AD discovery: an IP/hostname, a **CIDR range**, a comma-separated mix, or a file of them |
| `-k, --exclusions` | file of hosts to skip |
| `-d, --domain` | domain to enumerate |
| `-c, --domaincontroller` | DC to query |
| `-f, --dfs` | find shares via DFS only |
| `-a, --sharesonly` | stop after finding shares, don't walk them |
| `-u, --domainusers` | pull interesting account names from AD and hunt for them in file contents |
| `-m, --snaffle` | directory to copy matched files into |
| `-l, --snafflesize` | max size to copy, default 10MB |
| `-r, --maxgrepsize` | max size to search inside, default 1MB |
| `-j, --grepcontext` | bytes of context around content matches, default 200 |
| `-x, --maxthreads` | worker threads, default 60 (split 3 ways) |
| `-p, --rulespath` | load a directory of .toml rules instead of the defaults |
| `-z, --config` | read a .toml config; `-z generate` dumps a sample |
| `-e, --timeout` | minutes between status updates, default 5 |

### Added flags

| Flag | Meaning |
|---|---|
| `--user`, `--password` | credentials (prompts if a user is given with no secret) |
| `--hashes LM:NT` | pass-the-hash |
| `-K, --kerberos`, `--aes-key` | Kerberos; reads `KRB5CCNAME` if set |
| `--no-pass` | don't prompt, try a null session |
| `--dc-ip` | DC/KDC address if the name doesn't resolve |
| `--smb-port`, `--smb-timeout` | SMB transport tuning |
| `--conns-per-host` | cap concurrent SMB connections per host |
| `-P, --plus` | also load the bundled `snaffleplus` extended rules (see below) |
| `--extra-rules DIR` | merge a directory of rules *onto* the base set (vs `-p`, which replaces it) |
| `--html PATH` | write the HTML report |
| `--json-report PATH` | write the findings as JSON |

## Output

Identical to upstream. Plain format:

```
[CORP\svc_scan@kali] 2026-09-24 10:58:31Z [File] {Red}<KeepPassOrKeyInCode|R|passw?o?r?d\s*=\s*['"][^'"]....|3.4kB|2020-01-01 00:00:00Z>(\\FS01\Finance$\deploy.ps1) $password\ =\ "S3cret"
```

`{Triage}<Rule|RWM|MatchedPattern|Size|Modified>(Path) MatchContext`, with the
same triage colours on the console (`Black` > `Red` > `Yellow` > `Green`), the
same `[File]`/`[Share]`/`[Dir]` markers, and the same `-y` TSV layout.

## HTML report

`--html report.html` writes a single self-contained file (no CDN, works offline
from `file://`) with:

* clickable **Black / Red / Yellow / Green** tiles that toggle each triage level
* **share**, **host**, **rule** and **extension** filters
* free-text search across path, rule, matched pattern and match context
* sortable columns, expandable rows showing the full match context, copy-path
* CSV/JSON export of whatever is currently filtered
* Files / Shares / Directories tabs
* light / dark theme

Click a triage tile to filter to it; expand a row for the full match context and
a copy-path button:

![Filtering to Black findings with a row expanded](docs/img/report-filter-detail.png)

A rendered example you can open in a browser is checked in at
[`example-report.html`](example-report.html) (a `-P` scan of a demo corpus with
planted cpassword / cloud-token / GCP-key / terraform / kubeconfig bait).

## Rules

The 88 default rules are the upstream `.toml` files, copied verbatim into
`pysnaffler/rules/DefaultRules/`. All 385 patterns are used exactly as written —
no rewriting was needed, since the regex dialects agree on every one of them.

Point `-p` at your own directory of `.toml` files to replace the set.

### Extended rules (`snaffleplus`)

The upstream ruleset predates the modern secret-token era, so an opt-in pack in
`pysnaffler/rules/ExtendedRules/` adds the high-signal patterns it misses:

| Rule | Triage | Catches |
|---|---|---|
| `KeepSecretsPlusBlack` | Black | **GPP `cpassword`** on SYSVOL, GCP service-account private keys |
| `KeepSecretsPlusRed` | Red | GitHub/GitLab/Slack/Stripe/OpenAI/npm/SendGrid/Shopify tokens, Azure storage keys, DB connection URIs with inline creds, Ansible vaults, PowerShell secure strings, inline `net use`/`psexec` creds |
| `KeepSecretsPlusYellow` | Yellow | JWTs, `Authorization: Bearer` headers, generic secret/token assignments |
| `KeepTerraformState` | Red | `.tfstate` (holds the *resolved* secrets, unlike templated `.tfvars`) |
| `KeepKubeconfigByName` / `…ByPath` | Red | Kubernetes cluster configs and `.kube/` |
| `KeepWpConfigByName` | Red | `wp-config.php` |
| `KeepCloudCliCredsByPath` | Red | cached gcloud / azure / aws CLI token stores |

These are **strictly opt-in** — the default run is unchanged and still matches
the original byte-for-byte. Two ways to enable them:

```bash
# -P / --plus : layer the bundled snaffleplus pack onto whatever ruleset is in use
python3 snaffler.py -s -P -d corp.local --user bob --password hunter2 --html report.html

# --extra-rules DIR : layer YOUR OWN rules dir onto the base set
python3 snaffler.py -s --extra-rules ./my-rules -i /mnt/loot
```

Both **merge onto** the base ruleset. This is the key difference from `-p`,
which *replaces* it. A rule in the added set that reuses a base rule's name wins.

The relay note matters if you write your own content rules: a `ContentsEnumeration`
rule only runs if some `FileEnumeration` `Relay` rule lists it as a `RelayTarget`
(Snaffler only greps a file's contents via a relay). The pack ships its own
`RelayExtendedContentByExtension` that feeds the extended content rules; copy that
pattern for your own.

## How the port maps onto the original

| C# | Python |
|---|---|
| `NetShareEnum` (Win32 P/Invoke) | `impacket` srvsvc `NetrShareEnum` level 1 |
| `System.IO` over UNC paths | `impacket.smbconnection` behind a filesystem abstraction |
| `System.DirectoryServices` | `impacket.ldap` with paged searches |
| `Nett` TOML | `tomllib` |
| `NLog` coloured console | ANSI renderer reproducing NLog's highlighting rules |
| `LimitedConcurrencyLevelTaskScheduler` | `BlockingStaticTaskScheduler` in `concurrency.py` |
| the caller's Windows token | explicit credentials |

`pysnaffler/dotnet.py` reimplements the .NET behaviours the output depends on,
because Python's stdlib quietly disagrees with .NET on several of them:

* `Path.GetExtension(".bashrc")` is `".bashrc"` in .NET; `os.path.splitext` says
  there is no extension. Snaffler's dotfile rules depend on the .NET answer.
* `Regex.Escape` escapes space, `#` and `)` but not `]` or `}`; `re.escape` does
  the opposite on all five. Match contexts are escaped with it before logging.
* `BytesToString` and the `"u"` date format decide how sizes and timestamps print.

These are covered by `tests/test_dotnet.py`.

## Deliberate behaviour differences

Three, all of them either unobservable in the results or fixing something that
only hurts:

1. **The run ends when the work does.** Upstream only checks for completion on
   the status-update tick, so a scan that finishes in 8 seconds still sits there
   until the 5-minute timer fires. Status updates still happen on the `-e`
   interval; completion is checked separately.
2. **One directory listing per directory.** Upstream calls `Directory.GetFiles`
   then `Directory.GetDirectories`, enumerating each directory twice. One SMB
   listing gives both, for the same result at half the round trips. File sizes
   and timestamps come from that listing instead of a `stat` per file.
3. **Certificate password cracking doesn't leak.** Upstream appends each
   certificate's filename to the shared `CertPasswords` list and never removes
   it, so the list grows for the whole run. The filename is still tried; it just
   isn't kept.

Upstream quirks that were kept on purpose, because they change which findings you
get: the `x509MatchReason.Count >= 0` test that always fires, `IsInterest()`'s
handling of relay targets, the SYSVOL/NETLOGON "first replica wins" flag, and
unresolvable hosts being excluded by `CheckExclusions`.

Not implemented, because upstream doesn't implement it either: walking inside
archives (`EnterArchive`) and byte-based content matching (`FileContentAsBytes`)
both throw `NotImplementedException` in the C#.

## Fidelity

This was verified against the original, not just written to look like it. The C#
classifier code (16 of 18 files unmodified) was compiled into a reference
"oracle" that scans a directory and prints findings in Snaffler's exact format,
and its output was diffed against this port's:

| corpus | oracle | python | diff |
|---|---|---|---|
| upstream's `snafflertest/` (the shipped bait corpus) | 101 | 101 | **0** |
| the upstream repo itself (real `.cs`/`.toml`/`.git`) | 130 | 130 | **0** |
| this `pysnaffler/` package | 27 | 27 | **0** |

Byte-for-byte identical findings. A further 68-file adversarial corpus probing
`.bak` extension stripping, every `BytesToString` boundary, newline flattening,
match-context windows, `Regex.Escape` specials, six text encodings, the
`MaxSizeToGrep` cutoff, and PostMatch/Dir discard rules also matched exactly —
including the upstream quirk where a cracked cert password is reported twice.

The only divergences the adversarial corpus found were in symlink traversal and
certificate parsing; both were fixed and are now pinned by `tests/test_certs.py`.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

91 tests covering the .NET compatibility layer, rule loading and interest-level
filtering, the classifier pipeline end to end against an in-memory UNC
filesystem, the DFS v1 binary blob parser, certificate handling, the extended
rules pack, and CIDR/target expansion.

## Licence

Upstream Snaffler is GPL-3.0; this port follows it. Original tool by
[@l0ss](https://twitter.com/l0ss) and [@Sh3r4](https://twitter.com/sh3r4_hax).
