"""
Port of SnaffCore/ActiveDirectory/AdData.cs - the LDAP side of target discovery.
"""
import random
import socket
import uuid
from datetime import datetime, timedelta

from ..concurrency import BlockingMq
from ..context import ctx
from ..options import DomainUserNamesFormat
from .dfsfinder import DfsFinder
from .directorysearch import DirectorySearch


class UserAccountControlFlags:
    Script = 0x1
    AccountDisabled = 0x2
    HomeDirectoryRequired = 0x8
    AccountLockedOut = 0x10
    PasswordNotRequired = 0x20
    PasswordCannotChange = 0x40
    EncryptedTextPasswordAllowed = 0x80
    TempDuplicateAccount = 0x100
    NormalAccount = 0x200
    InterDomainTrustAccount = 0x800
    WorkstationTrustAccount = 0x1000
    ServerTrustAccount = 0x2000
    PasswordDoesNotExpire = 0x10000
    MnsLogonAccount = 0x20000
    SmartCardRequired = 0x40000
    TrustedForDelegation = 0x80000
    AccountNotDelegated = 0x100000
    UseDesKeyOnly = 0x200000
    DontRequirePreauth = 0x400000
    PasswordExpired = 0x800000
    TrustedToAuthenticateForDelegation = 0x1000000
    NoAuthDataRequired = 0x2000000


def from_file_time(filetime):
    """DateTime.FromFileTime - 100ns ticks since 1601, returned as local time."""
    try:
        epoch = datetime(1601, 1, 1)
        return epoch + timedelta(microseconds=filetime // 10)
    except (OverflowError, OSError, ValueError):
        return datetime(1601, 1, 1)


def get_ipv4_address(value):
    if not value or not value.strip():
        return None
    try:
        socket.inet_aton(value)
        return value
    except OSError:
        pass
    try:
        return socket.gethostbyname(value)
    except Exception as exc:
        print("Resolution failed for '%s': %s" % (value, exc))
        return None


class AdData:
    """Singleton, like AdData.AdDataInstance."""

    _instance = None

    def __init__(self):
        self._domain_computers = []
        self._domain_users = []
        self._dfs_shares_dict = {}
        self._dfs_namespace_paths = []
        self._target_domain = None
        self._target_dc = None
        self._target_domain_netbios_name = None
        self._directory_search = None
        self._creds = None
        self.Mq = BlockingMq.get_mq()

    @classmethod
    def instance(cls):
        if cls._instance is None:
            cls._instance = AdData()
        return cls._instance

    def get_domain_computers(self):
        return self._domain_computers

    def get_domain_users(self):
        return self._domain_users

    def get_dfs_shares_dict(self):
        return self._dfs_shares_dict

    def get_dfs_namespace_paths(self):
        return self._dfs_namespace_paths

    def get_directory_search(self):
        if self._directory_search is None:
            self.set_directory_search()
        return self._directory_search

    # -- setup ---------------------------------------------------------------
    def _get_netbios_domain_name(self):
        ldap_base = "CN=Partitions,CN=Configuration,DC=%s" % (
            self._target_domain.replace(".", ",DC="))
        ds = DirectorySearch(self._target_domain, self._target_dc, ldap_base,
                             creds=self._creds)
        ldap_filter = ("(&(objectcategory=Crossref)(dnsRoot=%s)(netBIOSName=*))"
                       % self._target_domain)
        try:
            for entry in ds.query_ldap(ldap_filter, ["netbiosname"]):
                return entry.get_property("netbiosname")
        except Exception as exc:
            self.Mq.trace("Failed to get NetBIOS domain name: " + str(exc))
        finally:
            ds.close()
        return None

    def set_directory_search(self):
        options = ctx.MyOptions
        from ..fs.smb import Credentials
        self._creds = Credentials(
            username=options.Username, password=options.Password,
            domain=options.Domain, lmhash=options.LmHash, nthash=options.NtHash,
            aes_key=options.AesKey, do_kerberos=options.DoKerberos,
            dc_ip=options.DcIp)

        if options.TargetDomain:
            self.Mq.trace("Target Domain specified: " + options.TargetDomain)
            self._target_domain = options.TargetDomain
            if options.TargetDc:
                self.Mq.trace("Target DC specified: " + options.TargetDc)
                self._target_dc = get_ipv4_address(options.TargetDc)
            else:
                self.Mq.trace("No target DC specified, using domain as DC.")
                self._target_dc = get_ipv4_address(options.TargetDomain)
        else:
            # The C# reads the current machine's domain from its own context;
            # we have no domain membership so we need to be told.
            if options.Domain:
                self._target_domain = options.Domain
                self._target_dc = get_ipv4_address(options.DcIp or options.Domain)
            else:
                raise ValueError(
                    "No domain specified. Pass -d/--domain (and optionally "
                    "-c/--domaincontroller), because this host is not domain joined.")

        if not self._creds.domain:
            self._creds.domain = self._target_domain

        self._target_domain_netbios_name = self._get_netbios_domain_name()
        self._directory_search = DirectorySearch(self._target_domain, self._target_dc,
                                                 creds=self._creds)

    # -- DFS -----------------------------------------------------------------
    def set_dfs_paths(self):
        ds = self.get_directory_search()
        try:
            self.Mq.degub("Starting DFS Enumeration.")

            dfs_shares = DfsFinder().find_dfs_shares(ds)

            # case-insensitive, as the C# uses InvariantCultureIgnoreCase
            self._dfs_shares_dict = _CaseInsensitiveDict()
            self._dfs_namespace_paths = []

            for dfs_share in dfs_shares:
                dfs_share_namespace_path = "\\\\%s\\%s" % (
                    self._target_domain, dfs_share.DFSFolderPath)
                hostnames = []

                if dfs_share_namespace_path not in self._dfs_namespace_paths:
                    self._dfs_namespace_paths.append(dfs_share_namespace_path)

                # Record both the short and FQDN forms of each real server, so
                # the ShareFinder can match whichever form its computer list has.
                hostnames.append(dfs_share.RemoteServerName)
                if dfs_share.RemoteServerName.lower().endswith(
                        self._target_domain.lower()):
                    hostnames.append(dfs_share.RemoteServerName.split(".")[0])
                else:
                    hostnames.append("%s.%s" % (dfs_share.RemoteServerName,
                                                self._target_domain))

                for host in hostnames:
                    real_path = "\\\\%s\\%s" % (host, dfs_share.RemoteShareName)
                    if real_path not in self._dfs_shares_dict:
                        self._dfs_shares_dict[real_path] = dfs_share_namespace_path

            self.Mq.info("Found " + str(len(self._dfs_shares_dict)) + " DFS Shares in "
                         + str(len(self._dfs_namespace_paths)) + " namespaces.")
            self.Mq.degub("Finished DFS Enumeration.")
        except Exception as exc:
            self.Mq.trace(str(exc))

    # -- computers -----------------------------------------------------------
    def set_domain_computers(self, ldap_filter):
        options = ctx.MyOptions
        ds = self.get_directory_search()
        domain_computers = []

        try:
            if not options.DfsOnly:
                ldap_properties = ["name", "dNSHostName", "lastLogonTimeStamp"]

                # Upstream's "extremely dirty hack to break a sig I once saw for
                # Snaffler's LDAP queries" - pad the attribute list with GUIDs.
                for _ in range(random.randint(1, 4)):
                    ldap_properties.append(str(uuid.uuid4()))

                entries = ds.query_ldap(ldap_filter, ldap_properties)

                # if a computer hasn't logged in for 4 months it's probably gone
                valid_llts_window = datetime.now() - timedelta(days=4 * 30)

                for entry in entries:
                    try:
                        uac_flags = int(entry.get_property("userAccountControl") or 0)
                    except (TypeError, ValueError):
                        uac_flags = 0

                    if uac_flags & UserAccountControlFlags.AccountDisabled:
                        continue

                    try:
                        llts_string = entry.get_property("lastlogontimestamp")
                        try:
                            llts_long = int(llts_string)
                        except (TypeError, ValueError):
                            llts_long = 0
                        llts_datetime = from_file_time(llts_long)
                        if llts_datetime <= valid_llts_window:
                            continue
                    except Exception:
                        self.Mq.error("Error calculating lastLogonTimeStamp for computer "
                                      "account " + entry.DistinguishedName)

                    dns_host_name = entry.get_property("dNSHostName")
                    if dns_host_name:
                        domain_computers.append(dns_host_name)
        except Exception as exc:
            self.Mq.trace(str(exc))

        self._domain_computers = domain_computers

    # -- users ---------------------------------------------------------------
    def set_domain_users(self):
        options = ctx.MyOptions
        ds = self.get_directory_search()
        domain_users = []

        ldap_properties = ["name", "adminCount", "sAMAccountName", "userAccountControl",
                           "servicePrincipalName", "userPrincipalName"]
        ldap_filter = "(&(objectClass=user)(objectCategory=person))"

        entries = ds.query_ldap(ldap_filter, ldap_properties)

        for entry in entries:
            keep_user = False
            try:
                user_name = entry.get_property("sAMAccountName")
                if not user_name:
                    continue

                try:
                    uac_flags = int(entry.get_property("userAccountControl") or 0)
                except (TypeError, ValueError):
                    uac_flags = 0

                if uac_flags & UserAccountControlFlags.AccountDisabled:
                    continue

                if user_name.endswith("$"):
                    self.Mq.trace("Skipping " + user_name +
                                  " because it appears to be a computer or trust account.")
                    continue

                lowered = user_name.lower()
                if "mailbox" in lowered:
                    self.Mq.trace("Skipping " + user_name +
                                  " because it appears to be a mailbox.")
                    continue
                if "mbx" in lowered:
                    self.Mq.trace("Skipping " + user_name +
                                  " because it appears to be a mailbox.")
                    continue

                if not keep_user and entry.get_property("servicePrincipalName") is not None:
                    self.Mq.trace("Adding " + user_name +
                                  " to target list because it has an SPN")
                    keep_user = True

                if not keep_user and entry.get_property("adminCount") == "1":
                    self.Mq.trace("Adding " + user_name +
                                  " to target list because it had adminCount=1.")
                    keep_user = True

                if not keep_user and uac_flags & UserAccountControlFlags.PasswordDoesNotExpire:
                    self.Mq.trace("Adding " + user_name + " to target list because password "
                                  "does not expire,  probably service account.")
                    keep_user = True

                if not keep_user and uac_flags & UserAccountControlFlags.DontRequirePreauth:
                    self.Mq.trace("Adding " + user_name + " to target list because it "
                                  "doesn't require Kerberos pre-auth.")
                    keep_user = True

                if not keep_user and uac_flags & UserAccountControlFlags.TrustedForDelegation:
                    self.Mq.trace("Adding " + user_name +
                                  " to target list because it is trusted for delegation.")
                    keep_user = True

                if not keep_user and uac_flags & \
                        UserAccountControlFlags.TrustedToAuthenticateForDelegation:
                    self.Mq.trace("Adding " + user_name +
                                  " to target list because it is trusted for delegation.")
                    keep_user = True

                if not keep_user:
                    for match in options.DomainUserMatchStrings:
                        if match.lower() in lowered:
                            self.Mq.trace("Adding " + user_name +
                                          " to target list because it contained "
                                          + match + ".")
                            keep_user = True
                            break

                if not keep_user:
                    continue

                # For common names, force fully-qualified strict formats.
                strict = [s.lower() for s in (options.DomainUserStrictStrings or [])]
                if lowered in strict:
                    self.Mq.trace("Using strict formats for " + user_name + ".")
                    domain_users.append("%s\\%s" % (self._target_domain_netbios_name,
                                                    user_name))
                    upn = entry.get_property("userPrincipalName")
                    if upn:
                        domain_users.append(upn)
                    continue

                for fmt in options.DomainUserNameFormats:
                    if fmt == DomainUserNamesFormat.NetBIOS:
                        domain_users.append("%s\\%s" % (self._target_domain_netbios_name,
                                                        user_name))
                    elif fmt == DomainUserNamesFormat.UPN:
                        upn = entry.get_property("userPrincipalName")
                        if upn:
                            domain_users.append(upn)
                        else:
                            self.Mq.trace("Adding " + user_name + " with simple "
                                          "sAMAccountName because UPN is missing.")
                            domain_users.append(user_name)
                    elif fmt == DomainUserNamesFormat.sAMAccountName:
                        domain_users.append(user_name)
            except Exception as exc:
                self.Mq.trace(str(exc))
                continue

        self._domain_users = domain_users


class _CaseInsensitiveDict(dict):
    """Dictionary<string,string>(StringComparer.InvariantCultureIgnoreCase)."""

    def __init__(self, *args, **kwargs):
        super().__init__()
        self._keys = {}
        for k, v in dict(*args, **kwargs).items():
            self[k] = v

    def __setitem__(self, key, value):
        lowered = key.lower()
        self._keys[lowered] = key
        super().__setitem__(lowered, value)

    def __getitem__(self, key):
        return super().__getitem__(key.lower())

    def __contains__(self, key):
        return super().__contains__(key.lower())

    def get(self, key, default=None):
        return super().get(key.lower(), default)

    def keys(self):
        return self._keys.values()
