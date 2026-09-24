"""
Regression tests for the cert / CheckForKeys behaviour, pinning the three
divergences from the C# that the differential test caught:

  * a PEM with no CERTIFICATE block must NOT invent "HasPassword"
  * a PKCS#8 key must be invisible (only literal PKCS#1 counts)
  * a non-PEM garbage file still reports "HasPassword"
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from memfs import MemoryFileSystem

from pysnaffler import certs
from pysnaffler.concurrency import BlockingMq
from pysnaffler.context import ctx
from pysnaffler.options import Options


def match(fs, path):
    BlockingMq.make_mq()
    ctx.MyOptions = Options()
    ctx.FileSystem = fs
    return certs.x509_match(fs.get_file_info(path))


class TestX509Match(unittest.TestCase):
    def test_pem_without_cert_block_reports_nothing(self):
        fs = MemoryFileSystem()
        # a bare private key, no CERTIFICATE block
        path = r"\\HOST\share\key_nopass.pem"
        fs.add(path, "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")
        self.assertEqual(match(fs, path), [])

    def test_pkcs1_key_pem_without_cert_reports_nothing(self):
        fs = MemoryFileSystem()
        path = r"\\HOST\share\key_pkcs1.pem"
        fs.add(path, "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n")
        self.assertEqual(match(fs, path), [])

    def test_garbage_pem_reports_nothing(self):
        fs = MemoryFileSystem()
        path = r"\\HOST\share\garbage.pem"
        fs.add(path, "this is not a certificate at all")
        self.assertEqual(match(fs, path), [])

    def test_garbage_der_reports_haspassword(self):
        # the non-PEM branch really does throw, so this one keeps HasPassword
        fs = MemoryFileSystem()
        path = r"\\HOST\share\garbage.der"
        fs.add(path, b"\x00\x01\x02not a der cert")
        self.assertEqual(match(fs, path), ["HasPassword", "LookNearbyFor.txtFiles"])

    def test_get_bytes_from_pem_pkcs8_is_invisible(self):
        pem = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
        # the PKCS#1 header is what we look for, and it isn't here
        self.assertNotIn(certs._PEM_RSA_KEY_HEADER, pem)
        self.assertIsNone(
            certs._get_bytes_from_pem(pem, certs._PEM_CERT_HEADER, certs._PEM_CERT_FOOTER))


class TestRealCertificate(unittest.TestCase):
    """Generate a real self-signed cert and check the reported reasons."""

    @classmethod
    def setUpClass(cls):
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives.serialization import pkcs12
            import datetime
        except ImportError:
            raise unittest.SkipTest("cryptography not available")

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "snaffler-test")])
        cert = (x509.CertificateBuilder()
                .subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime(2020, 1, 1))
                .not_valid_after(datetime.datetime(2030, 1, 1))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
                .sign(key, hashes.SHA256()))
        cls.pfx = pkcs12.serialize_key_and_certificates(
            b"test", key, cert, None,
            serialization.BestAvailableEncryption(b"password"))
        cls.pfx_nopass = pkcs12.serialize_key_and_certificates(
            b"test", key, cert, None, serialization.NoEncryption())

    def test_pfx_with_no_password_reports_private_key(self):
        fs = MemoryFileSystem()
        path = r"\\HOST\share\nopass.pfx"
        fs.add(path, self.pfx_nopass)
        reasons = match(fs, path)
        self.assertIn("HasPrivateKey", reasons)
        self.assertIn("NoPasswordRequired", reasons)
        self.assertTrue(any(r.startswith("Subject:") for r in reasons))
        self.assertIn("IsCACert", reasons)
        self.assertTrue(any(r.startswith("Expiry:") for r in reasons))

    def test_pfx_password_is_cracked(self):
        fs = MemoryFileSystem()
        path = r"\\HOST\share\secret.pfx"
        fs.add(path, self.pfx)
        reasons = match(fs, path)
        self.assertIn("PasswordCracked: password", reasons)
        self.assertIn("HasPrivateKey", reasons)


if __name__ == "__main__":
    unittest.main()
