import datetime
from typing import NamedTuple, Tuple

from cryptography import x509
from cryptography.x509.oid import NameOID  # type: ignore
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_private_key,
)
from cryptography.x509 import (
    Certificate,
    load_pem_x509_csr,
    load_pem_x509_certificate,
)

from registration_ref.settings import Settings


class DeviceInfo(NamedTuple):
    namespace: str
    root_crt: str
    pubkey: str
    client_crt: str
    uuid: str


def _key_pair() -> Tuple[EllipticCurvePrivateKey, Certificate]:
    try:
        return _key_pair._cached  # type: ignore
    except AttributeError:
        pass

    ca = load_pem_x509_certificate(Settings.CA_CRT.encode())
    pk = load_pem_private_key(Settings.CA_KEY.encode(), None)

    # Make sure the Factory owner gave us a cert capable of signing CSRs
    try:
        ext = ca.extensions.get_extension_for_class(x509.BasicConstraints)
        if not ext.value.ca:
            raise ValueError("Factory not allowed to sign Device CSRs")
    except x509.extensions.ExtensionNotFound:
        raise ValueError("Factory not allowed to sign Device CSRs")

    _key_pair._cached = (pk, ca)  # type: ignore
    return _key_pair._cached  # type: ignore


def sign_device_csr(csr: str) -> DeviceInfo:
    cert = load_pem_x509_csr(csr.encode())
    factory = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[
        0
    ].value
    if isinstance(factory, bytes):
        factory = factory.decode()
    uuid = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    if isinstance(uuid, bytes):
        uuid = uuid.decode()

    pk, ca = _key_pair()
    actual_factory = ca.subject.get_attributes_for_oid(
        NameOID.ORGANIZATIONAL_UNIT_NAME
    )[0].value
    if isinstance(actual_factory, bytes):
        actual_factory = actual_factory.decode()

    if factory != actual_factory:
        raise ValueError(f"Invalid factory({factory}) must be {actual_factory}")

    signed = (
        x509.CertificateBuilder()
        .subject_name(cert.subject)
        .serial_number(int("0x" + uuid.replace("-", ""), 16))
        .issuer_name(ca.subject)
        .public_key(cert.public_key())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=7300))
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
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
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(pk.public_key()),
            critical=False,
        )
        .sign(pk, SHA256(), default_backend())
    )
    signed_bytes = signed.public_bytes(encoding=Encoding.PEM)
    public_bytes = cert.public_key().public_bytes(
        format=PublicFormat.SubjectPublicKeyInfo, encoding=Encoding.PEM
    )

    return DeviceInfo(
        factory, Settings.ROOT_CRT, public_bytes.decode(), signed_bytes.decode(), uuid
    )
