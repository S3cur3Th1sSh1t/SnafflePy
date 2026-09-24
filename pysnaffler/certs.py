"""
Port of FileClassifier.x509Match() / parseCert() - the CheckForKeys action.

Certificates matched by RelayCertByExtension (.pem/.der/.pfx/.p12/...) are
parsed, weak passwords are tried against them, and whatever we learn about the
key is reported as the match context.
"""
from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12

from . import dotnet
from .concurrency import BlockingMq
from .context import ctx


class CryptographicError(Exception):
    """Stands in for System.Security.Cryptography.CryptographicException."""


class ParsedCert:
    __slots__ = ("cert", "has_private_key")

    def __init__(self, cert, has_private_key):
        self.cert = cert
        self.has_private_key = has_private_key


def _rfc2253(name):
    """Render a name the way X509Certificate2.Subject/Issuer does."""
    try:
        return name.rfc4514_string()
    except Exception:
        return str(name)


# The exact PEM headers Snaffler's Helpers.GetBytesFromPEM looks for. It does a
# literal IndexOf on these and nothing else, so a PKCS#8 ("BEGIN PRIVATE KEY")
# key is invisible to it - we must be blind to it too.
_PEM_CERT_HEADER = "-----BEGIN CERTIFICATE-----"
_PEM_CERT_FOOTER = "-----END CERTIFICATE-----"
_PEM_RSA_KEY_HEADER = "-----BEGIN RSA PRIVATE KEY-----"


def _get_bytes_from_pem(pem_string, header, footer):
    """Port of Helpers.GetBytesFromPEM - returns the DER bytes or None."""
    import base64
    start = pem_string.find(header)
    if start < 0:
        return None
    start += len(header)
    end = pem_string.find(footer, start)
    if end < 0:
        return None
    try:
        return base64.b64decode(pem_string[start:end])
    except Exception:
        return None


def parse_cert(data, extension, password=None):
    """parseCert().

    Raises CryptographicError when a password is needed (the non-PEM path).
    For a PEM with no CERTIFICATE block it returns None *without* raising, so
    the caller records no match - exactly as the C# does (parsedCert stays null
    and no exception fires).
    """
    pwd = None
    if password is not None:
        pwd = password.encode("utf-8") if password != "" else None

    if extension and extension.lower() == ".pem":
        try:
            pem_string = data.decode("utf-8", errors="replace")
        except Exception:
            return None
        cert_buffer = _get_bytes_from_pem(pem_string, _PEM_CERT_HEADER, _PEM_CERT_FOOTER)
        if cert_buffer is None:
            # GetBytesFromPEM returned null -> "Failure parsing", parsedCert null
            return None
        try:
            cert = x509.load_der_x509_certificate(cert_buffer)
        except Exception as exc:
            # new X509Certificate2(certBuffer) throwing lands in the caller's
            # CryptographicException handler
            raise CryptographicError(str(exc))
        # only a literal PKCS#1 RSA key counts as "has private key" here
        has_key = _PEM_RSA_KEY_HEADER in pem_string
        return ParsedCert(cert, has_key)

    # PKCS#12 first (.pfx/.p12/.pk12/.pkcs12), then bare DER
    try:
        key, cert, _extra = pkcs12.load_key_and_certificates(data, pwd)
        if cert is not None:
            return ParsedCert(cert, key is not None)
    except Exception as exc:
        # A DER cert is not a PKCS#12 container - fall through and try DER, but
        # only when no password was supplied. With a password, failure means
        # the password was wrong.
        if password:
            raise CryptographicError(str(exc))
        try:
            cert = x509.load_der_x509_certificate(data)
            return ParsedCert(cert, False)
        except Exception:
            raise CryptographicError(str(exc))

    try:
        cert = x509.load_der_x509_certificate(data)
        return ParsedCert(cert, False)
    except Exception as exc:
        raise CryptographicError(str(exc))


def _key_usage_string(ext_value):
    """Mirrors X509KeyUsageExtension.KeyUsages.ToString()."""
    names = []
    mapping = [
        ("digital_signature", "DigitalSignature"),
        ("content_commitment", "NonRepudiation"),
        ("key_encipherment", "KeyEncipherment"),
        ("data_encipherment", "DataEncipherment"),
        ("key_agreement", "KeyAgreement"),
        ("key_cert_sign", "KeyCertSign"),
        ("crl_sign", "CrlSign"),
    ]
    for attr, label in mapping:
        try:
            if getattr(ext_value, attr):
                names.append(label)
        except ValueError:
            continue
    try:
        if ext_value.key_agreement and ext_value.encipher_only:
            names.append("EncipherOnly")
        if ext_value.key_agreement and ext_value.decipher_only:
            names.append("DecipherOnly")
    except ValueError:
        pass
    return ", ".join(names) if names else "None"


def x509_match(file_info, alt_file_info=None):
    mq = BlockingMq.get_mq()

    if alt_file_info is not None:
        file_name = alt_file_info.AlternativeFileName
        full_file_name = alt_file_info.AlternativeFullFileName
        extension = alt_file_info.AlternativeExtension
    else:
        file_name = file_info.Name
        full_file_name = file_info.FullName
        extension = file_info.Extension

    match_reasons = []
    parsed_cert = None
    nopwrequired = False

    try:
        data = file_info.read_all_bytes()
    except Exception as exc:
        mq.error("Unhandled exception parsing cert: %s %s" % (full_file_name, exc))
        return match_reasons

    try:
        parsed_cert = parse_cert(data, extension)
        nopwrequired = True
    except CryptographicError as exc:
        mq.trace(str(exc))

        # the filename itself is worth a try as a password
        passwords = list(ctx.MyOptions.CertPasswords)
        passwords.append(dotnet.get_file_name_without_extension(file_name))

        for password in passwords:
            try:
                parsed_cert = parse_cert(data, extension, password)
                if password == "":
                    match_reasons.append("PasswordBlank")
                else:
                    match_reasons.append("PasswordCracked: " + password)
            except CryptographicError as exc2:
                mq.trace("Password " + str(password) + " invalid for cert file "
                         + full_file_name + " " + str(exc2))

        if not match_reasons:
            match_reasons.append("HasPassword")
            match_reasons.append("LookNearbyFor.txtFiles")
    except Exception as exc:
        mq.error("Unhandled exception parsing cert: %s %s" % (full_file_name, exc))

    if parsed_cert is not None and parsed_cert.has_private_key:
        match_reasons.append("HasPrivateKey")
        if nopwrequired:
            match_reasons.append("NoPasswordRequired")

        cert = parsed_cert.cert
        match_reasons.append("Subject:" + _rfc2253(cert.subject))

        for ext in cert.extensions:
            try:
                if isinstance(ext.value, x509.BasicConstraints):
                    if ext.value.ca:
                        match_reasons.append("IsCACert")
                elif isinstance(ext.value, x509.KeyUsage):
                    match_reasons.append(_key_usage_string(ext.value))
                elif isinstance(ext.value, x509.ExtendedKeyUsage):
                    ekus = [getattr(oid, "_name", None) or oid.dotted_string
                            for oid in ext.value]
                    match_reasons.append("|".join(ekus))
                elif isinstance(ext.value, x509.SubjectAlternativeName):
                    sans = []
                    for gn in ext.value:
                        try:
                            sans.append(str(gn.value))
                        except Exception:
                            continue
                    match_reasons.append(", ".join(sans))
            except Exception:
                continue

        # X509Certificate2.GetExpirationDateString() is DateTime.ToString() under
        # the machine's culture, so there is no single "correct" string. We use
        # the invariant-culture form (MM/dd/yyyy HH:mm:ss), which is what a real
        # .NET run under invariant globalization produces, and include the time
        # component (dropping it matches no culture at all).
        try:
            expiry = cert.not_valid_after_utc
        except AttributeError:
            expiry = cert.not_valid_after
        match_reasons.append("Expiry:" + expiry.strftime("%m/%d/%Y %H:%M:%S"))
        match_reasons.append("Issuer:" + _rfc2253(cert.issuer))

    return match_reasons
