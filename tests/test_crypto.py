import datetime
from unittest import TestCase
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from cryptography.x509.oid import NameOID  # type: ignore

from registration_ref.crypto import sign_device_csr


class TestCrypo(TestCase):
    def setUp(self):
        p = patch("registration_ref.crypto.Settings")
        settings = p.start()
        self.addCleanup(p.stop)

        key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        settings.CA_KEY = key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption(),
        ).decode()

        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "acme-corp"),
            ]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.BasicConstraints(
                    ca=True, path_length=0
                ),  # sign CSRs from devices but not create new CAs
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=True,
            )
            .sign(key, SHA256())
        )
        settings.CA_CRT = cert.public_bytes(Encoding.PEM).decode()

    @staticmethod
    def _csr(key, uuid: str, factory: str) -> str:
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, factory),
                        x509.NameAttribute(NameOID.COMMON_NAME, uuid),
                    ]
                )
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=True,
            )
            .sign(key, SHA256(), default_backend())
        )
        return csr.public_bytes(Encoding.PEM).decode()

    def test_bad_csr_format(self):
        with self.assertRaises(ValueError) as e:
            sign_device_csr("not a valid csr")
        self.assertIn("Unable to load PEM file.", str(e.exception))

    def test_invalid_factory(self):
        key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        csr = self._csr(key, "uuid", "blah")
        with self.assertRaises(ValueError) as e:
            sign_device_csr(csr)
        self.assertIn("Invalid factory(blah) must be acme-corp", str(e.exception))

    def test_simple(self):
        key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        csr = self._csr(key, "12-34-56", "acme-corp")
        fields = sign_device_csr(csr)
        self.assertEqual("acme-corp", fields.namespace)
