import datetime
import hashlib
import os
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.x509.oid import NameOID

from icegate_sign import text


class FakeKey:
    """Software stand-in for token.Key."""

    def __init__(self):
        self.priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(self.priv.public_key())
                .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
                .sign(self.priv, hashes.SHA256()))
        self.cert_der = cert.public_bytes(serialization.Encoding.DER)

    def sign_hashed(self, hash_name, digest):
        h = {"sha1": hashes.SHA1, "sha256": hashes.SHA256}[hash_name]()
        return self.priv.sign(digest, padding.PKCS1v15(), Prehashed(h))


def test_roundtrip_and_body_trimmed():
    out = text.sign(b"\r\n  HDR\x1dBODY \n", FakeKey())
    assert out.startswith(b"HDR\x1dBODY\n<START-SIGNATURE>") and out.endswith(b"V-NCODE_01.05.2013</SIGNER-VERSION>")
    assert text.verify(out) == b"HDR\x1dBODY"


def test_xml_utf8_signed_as_is():
    xml = '\ufeff<?xml version="1.0" encoding="UTF-8"?>\r\n<a>caf\u00e9</a>\n'.encode()
    out = text.sign(xml, FakeKey())
    assert out.startswith(xml.rstrip()) and text.verify(out) == xml.strip(bytes(range(33)))


def test_tampered_body_fails():
    out = text.sign(b"abc", FakeKey())
    with pytest.raises(ValueError):
        text.verify(out.replace(b"abc", b"abd", 1))


@pytest.mark.parametrize("bad", [b"", b"  \n", b"a\0b", b"x<START-SIGNATURE>"])
def test_rejects(bad):
    with pytest.raises(ValueError):
        text.sign(bad, FakeKey())


# Golden: real nCode output must verify (set ICEGATE_GOLDEN to a folder of *[signed].sb/.be files).
GOLDEN = Path(os.environ["ICEGATE_GOLDEN"]) if os.environ.get("ICEGATE_GOLDEN") else None


@pytest.mark.skipif(GOLDEN is None or not GOLDEN.is_dir(), reason="no ICEGATE_GOLDEN folder")
def test_golden_ncode_files():
    files = [p for p in GOLDEN.iterdir() if "[signed]" in p.name and p.suffix.lower() in {".sb", ".be", ".txt"}]
    assert files
    for p in files:
        assert text.verify(p.read_bytes())
