"""PKCS#11 token access.

Signatures use CKM_RSA_PKCS with a DigestInfo we build ourselves, so the result does not
depend on which hash mechanisms the token offers and no hash is ever silently swapped.
"""
import getpass
import os
import sys
from contextlib import contextmanager
from datetime import datetime, timezone

import pkcs11
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass, TokenFlag

# The HYP2003 (Feitian ePass2003, ENTERSAFE-ESPK layout) is not readable by OpenSC, so the
# vendor's libcastle_v2 is preferred when present. It is proprietary and never lives in the repo.
VENDOR_MODULES = [os.path.expanduser(p) for p in (
    "~/.local/lib/hyp2003/libcastle_v2.so.1.0.0",
    "~/Documents/hyp2003-linux-driver/libcastle_v2.so.1.0.0",
)]
OPENSC_MODULE = "/usr/lib/opensc-pkcs11.so"
DEFAULT_MODULE = (os.environ.get("ICEGATE_PKCS11_MODULE")
                  or next((m for m in VENDOR_MODULES if os.path.exists(m)), OPENSC_MODULE))
DIGEST_INFO = {
    "sha1": bytes.fromhex("3021300906052b0e03021a05000414"),
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
}
_HASHES = {"sha1": hashes.SHA1, "sha256": hashes.SHA256}


class Key:
    """A token key plus its certificate. Every signature is verified before it is returned."""

    def __init__(self, private_key, cert_der: bytes):
        self._key, self.cert_der = private_key, cert_der
        self._pub = x509.load_der_x509_certificate(cert_der).public_key()

    def sign_hashed(self, hash_name: str, digest: bytes) -> bytes:
        """RSA PKCS#1 v1.5 signature over `digest`, already computed with hash_name (sha1/sha256)."""
        sig = self._key.sign(DIGEST_INFO[hash_name] + digest, mechanism=Mechanism.RSA_PKCS)
        self._pub.verify(sig, digest, padding.PKCS1v15(), Prehashed(_HASHES[hash_name]()))
        return sig


def _cn(cert: x509.Certificate) -> str:
    attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return attrs[0].value if attrs else cert.subject.rfc4514_string()


def _pkcs11_token(module):
    lib = pkcs11.lib(module)
    tokens = list(lib.get_tokens())
    if not tokens:
        raise RuntimeError("no token found (plugged in? visible to pcscd/OpenSC? Wine token manager closed?)")
    if len(tokens) > 1:
        raise RuntimeError("several tokens present; unplug all but one")
    return tokens[0]


def describe(cert: x509.Certificate, label=None) -> dict:
    now = datetime.now(timezone.utc)
    issuer = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return {"label": label, "cn": _cn(cert), "issuer": issuer[0].value if issuer else cert.issuer.rfc4514_string(),
            "serial": format(cert.serial_number, "x"), "not_after": cert.not_valid_after_utc,
            "days_left": (cert.not_valid_after_utc - now).days, "rsa": isinstance(cert.public_key(), rsa.RSAPublicKey)}


def token_info(module=DEFAULT_MODULE) -> dict:
    """Token label, PIN-state flags and its certificates. Needs no PIN."""
    token = _pkcs11_token(module)
    with token.open() as s:
        certs = [describe(x509.load_der_x509_certificate(bytes(c[Attribute.VALUE])), c[Attribute.LABEL])
                 for c in s.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE})]
    f = token.flags
    return {"label": token.label, "model": token.model, "serial": token.serial, "certs": certs,
            "pin_locked": bool(f & TokenFlag.USER_PIN_LOCKED), "pin_final_try": bool(f & TokenFlag.USER_PIN_FINAL_TRY),
            "pin_count_low": bool(f & TokenFlag.USER_PIN_COUNT_LOW)}


@contextmanager
def session(module=DEFAULT_MODULE, label=None, pin=None):
    """Open the only token, log in once, and yield the Key for its usable certificate."""
    token = _pkcs11_token(module)
    flags = token.flags
    if flags & TokenFlag.USER_PIN_LOCKED:
        raise RuntimeError("token PIN is locked")
    if flags & TokenFlag.USER_PIN_FINAL_TRY:
        if input("FINAL PIN TRY: one wrong PIN locks the token. Type YES to continue: ").strip() != "YES":
            raise RuntimeError("aborted before the last PIN try")
    elif flags & TokenFlag.USER_PIN_COUNT_LOW:
        print("WARNING: PIN retry counter is low.")
    pin = pin if pin is not None else getpass.getpass("Token PIN: ")
    with token.open(user_pin=pin) as s:  # no retry: a wrong PIN raises and we stop
        keys = {int.from_bytes(k[Attribute.MODULUS], "big"): k
                for k in s.get_objects({Attribute.CLASS: ObjectClass.PRIVATE_KEY, Attribute.KEY_TYPE: KeyType.RSA})}
        now, usable = datetime.now(timezone.utc), []
        for c in s.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE}):
            der = bytes(c[Attribute.VALUE])
            cert = x509.load_der_x509_certificate(der)
            pub = cert.public_key()
            key = keys.get(pub.public_numbers().n) if isinstance(pub, rsa.RSAPublicKey) else None
            if key is None or cert.not_valid_after_utc < now or cert.not_valid_before_utc > now:
                continue
            if label and label not in (c[Attribute.LABEL], _cn(cert)):
                continue
            usable.append((_cn(cert), key, der))
        if not usable:
            raise RuntimeError("no valid certificate with a matching RSA key on the token")
        if len(usable) > 1:
            raise RuntimeError("several certificates, choose one with --cert: " + ", ".join(n for n, _, _ in usable))
        cn, key, der = usable[0]
        left = describe(x509.load_der_x509_certificate(der))["days_left"]
        if left < 30:
            print(f"WARNING: certificate {cn!r} expires in {left} days", file=sys.stderr)
        yield Key(key, der)
