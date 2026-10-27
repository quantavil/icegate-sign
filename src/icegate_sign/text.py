"""BE/SB/TXT/XML signing in the nCode text format (ICEGATE's "Text or XML" signer).

Reproduces nCode's signTextFiles/signTextSHA2: RSA PKCS#1 v1.5 (SHA-1 DigestInfo) over the
32-byte SHA-256 digest of the file with leading/trailing bytes <= 0x20 trimmed, wrapped in tags.
XML gets no special treatment from nCode: the tags are simply appended after the document.
Bytes are signed as they are on disk. Verified against files signed by nCode.
"""
import base64
import hashlib
import re

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

VERSION = "V-NCODE_01.05.2013"
# nCode refuses input containing any of these (isInputFilefilesigned).
_MARKERS = (b"<START-SIGNATURE>", b"</START-SIGNATURE>", b"<START-CERTIFICATE>", b"</START-CERTIFICATE>", b"</SIGNER-VERSION>")
_SIGNED = re.compile(rb"(.*?)\n<START-SIGNATURE>(.*?)</START-SIGNATURE>\n<START-CERTIFICATE>(.*?)</START-CERTIFICATE>\n"
                     rb"<SIGNER-VERSION>" + re.escape(VERSION.encode()) + rb"</SIGNER-VERSION>", re.S)


def check(data: bytes) -> bytes:
    """Return the trimmed text nCode would sign, or raise ValueError."""
    text = data.strip(bytes(range(33)))
    if not text:
        raise ValueError("file is empty")
    if b"\0" in text:
        raise ValueError("binary file (contains NUL bytes)")
    if any(m in text for m in _MARKERS):
        raise ValueError("file already signed")
    return text


def _digest(text: bytes) -> bytes:
    return hashlib.sha1(hashlib.sha256(text).digest()).digest()


def sign(data: bytes, key) -> bytes:
    """`key` has cert_der and sign_hashed(hash_name, digest)."""
    text = check(data)
    sig = key.sign_hashed("sha1", _digest(text))
    b64 = lambda b: base64.b64encode(b)
    return (text + b"\n<START-SIGNATURE>" + b64(sig) + b"</START-SIGNATURE>\n"
            b"<START-CERTIFICATE>" + b64(key.cert_der) + b"</START-CERTIFICATE>\n"
            b"<SIGNER-VERSION>" + VERSION.encode() + b"</SIGNER-VERSION>")


def verify(signed: bytes) -> bytes:
    """Check a signed file against its embedded certificate; return the body. Raises ValueError."""
    m = _SIGNED.fullmatch(signed)
    if not m:
        raise ValueError("not an nCode-signed text file")
    try:
        sig, der = base64.b64decode(m[2], validate=True), base64.b64decode(m[3], validate=True)
        x509.load_der_x509_certificate(der).public_key().verify(
            sig, _digest(m[1]), padding.PKCS1v15(), Prehashed(hashes.SHA1()))
    except Exception as e:
        raise ValueError(f"signature invalid: {e}") from e
    return m[1]
