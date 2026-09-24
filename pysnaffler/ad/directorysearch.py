"""
Port of SnaffCore/ActiveDirectory/DirectorySearch.cs on top of impacket's LDAP
client, so LDAP uses the same credentials (and the same Kerberos ticket) as SMB.
"""
from impacket.ldap import ldap as impacket_ldap
from impacket.ldap import ldapasn1

from ..concurrency import BlockingMq


class LdapEntry:
    """Thin wrapper giving the GetProperty* helpers the C# extension methods add."""

    __slots__ = ("DistinguishedName", "_attrs")

    def __init__(self, dn, attrs):
        self.DistinguishedName = dn
        self._attrs = attrs

    @classmethod
    def from_search_result(cls, entry):
        dn = str(entry["objectName"])
        attrs = {}
        for attribute in entry["attributes"]:
            name = str(attribute["type"]).lower()
            values = []
            for value in attribute["vals"]:
                values.append(bytes(value))
            attrs[name] = values
        return cls(dn, attrs)

    def get_property(self, name):
        values = self._attrs.get(name.lower())
        if not values:
            return None
        try:
            return values[0].decode("utf-8")
        except UnicodeDecodeError:
            return values[0].decode("utf-8", errors="replace")

    def get_property_as_array(self, name):
        values = self._attrs.get(name.lower())
        if not values:
            return None
        return [v.decode("utf-8", errors="replace") for v in values]

    def get_property_as_bytes(self, name):
        values = self._attrs.get(name.lower())
        if not values:
            return None
        return values[0]

    def get_property_as_array_of_bytes(self, name):
        return self._attrs.get(name.lower())

    def has(self, name):
        return name.lower() in self._attrs


class DirectorySearch:
    def __init__(self, domain_name, domain_controller, base_ldap_path=None,
                 creds=None, ldap_port=0, secure_ldap=False):
        self._domain_name = domain_name
        self._domain_controller = domain_controller
        self._base_ldap_path = base_ldap_path or self.default_base(domain_name)
        self._creds = creds
        self._ldap_port = ldap_port
        self._secure_ldap = secure_ldap
        self._connection = None
        self.Mq = BlockingMq.get_mq()

    @staticmethod
    def default_base(domain_name):
        return "DC=" + domain_name.replace(".", ",DC=")

    def _url(self):
        scheme = "ldaps" if self._secure_ldap else "ldap"
        target = self._domain_controller or self._domain_name
        if self._ldap_port:
            return "%s://%s:%d" % (scheme, target, self._ldap_port)
        return "%s://%s" % (scheme, target)

    def connection(self):
        if self._connection is not None:
            return self._connection

        creds = self._creds
        conn = impacket_ldap.LDAPConnection(self._url(), self._base_ldap_path,
                                            self._domain_controller)
        if creds is None:
            conn.login()
        elif creds.do_kerberos:
            conn.kerberosLogin(creds.username, creds.password, creds.domain,
                               creds.lmhash, creds.nthash, creds.aes_key, creds.dc_ip)
        else:
            conn.login(creds.username, creds.password, creds.domain,
                       creds.lmhash, creds.nthash)
        self._connection = conn
        return conn

    def query_ldap(self, ldap_filter, props, scope="wholeSubtree", ads_path=None):
        """Paged LDAP search, 500 records per page as the C# requests."""
        conn = self.connection()
        search_base = ads_path or self._base_ldap_path
        paged = ldapasn1.SimplePagedResultsControl(criticality=True, size=500)

        entries = []

        def per_record(item):
            if isinstance(item, ldapasn1.SearchResultEntry):
                entries.append(LdapEntry.from_search_result(item))

        conn.search(searchBase=search_base,
                    searchFilter=ldap_filter,
                    scope=ldapasn1.Scope(scope),
                    attributes=list(props) if props else [],
                    searchControls=[paged],
                    perRecordCallback=per_record)
        return entries

    def close(self):
        if self._connection is not None:
            try:
                self._connection.close()
            except Exception:
                pass
            self._connection = None
