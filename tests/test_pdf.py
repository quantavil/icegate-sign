import datetime
import shutil
import subprocess

import pikepdf
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.x509.oid import NameOID

from icegate_sign.pdf import sign_pdf


class FakeKey:
    def __init__(self):
        self._k = rsa.generate_private_key(65537, 2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Signer")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(self._k.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .sign(self._k, hashes.SHA256())
        )
        self.cert_der = cert.public_bytes(serialization.Encoding.DER)

    def sign_hashed(self, hash_name, digest):
        h = {"sha1": hashes.SHA1(), "sha256": hashes.SHA256()}[hash_name]
        return self._k.sign(digest, padding.PKCS1v15(), utils.Prehashed(h))


@pytest.fixture(scope="module")
def key():
    return FakeKey()


@pytest.fixture
def src(tmp_path):
    p = pikepdf.new()
    for _ in range(3):
        p.add_blank_page(page_size=(595, 842))
    f = tmp_path / "in.pdf"
    p.save(f)
    return f


def sigs(path):
    with pikepdf.open(path) as pdf:
        out = []
        for i, page in enumerate(pdf.pages, 1):
            for a in page.get("/Annots", []):
                if a.get("/FT") == "/Sig":
                    out.append((i, a.V))
        return [(i, {k: (str(v) if not isinstance(v, pikepdf.Name) else str(v))
                     for k, v in dict(v).items() if k != "/Contents" and k != "/ByteRange"})
                for i, v in out]


def test_all_pages(src, tmp_path, key):
    dest = tmp_path / "out.pdf"
    assert sign_pdf(src, dest, key, "A") == 3
    s = sigs(dest)
    assert [p for p, _ in s] == [1, 2, 3]
    d = s[0][1]
    assert d["/Reason"] == "" and d["/Location"] == ""
    assert d["/SubFilter"] == "/adbe.pkcs7.detached"
    assert d["/Filter"] == "/Adobe.PPKLite"
    assert "(n)Code Solutions" in d["/Name"]


def test_signature_appearance(src, tmp_path, key):
    dest = tmp_path / "styled.pdf"
    sign_pdf(src, dest, key, "F")
    with pikepdf.open(dest) as document:
        appearance = document.pages[0]["/Annots"][0]["/AP"]["/N"].read_bytes()
        assert b"Digitally signed" in appearance
        assert b"Test Signer" in appearance
        assert b"1 1 1 rg" in appearance
        assert b"Reason" in appearance and b"Location" in appearance
        assert b"0 0.6 0 rg" not in appearance


def test_signature_is_below_original_page(src, tmp_path, key):
    dest = tmp_path / "footer.pdf"
    sign_pdf(src, dest, key, "F")
    with pikepdf.open(src) as original, pikepdf.open(dest) as signed:
        before = original.pages[0].MediaBox
        page = signed.pages[0]
        rect = page["/Annots"][0]["/Rect"]
        assert rect[2] - rect[0] >= 330
        assert rect[3] - rect[1] >= 85
        assert page.MediaBox[1] < before[1]
        assert rect[3] <= before[1]
        assert page.MediaBox[0] == before[0] and page.MediaBox[2] == before[2]


def test_later_signatures_do_not_alter_page_content(src, tmp_path, key):
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.diff_analysis import ModificationLevel
    from pyhanko.sign.validation import validate_pdf_signature
    from pyhanko_certvalidator import ValidationContext

    dest = tmp_path / 'multiple.pdf'
    sign_pdf(src, dest, key, 'A')
    with dest.open('rb') as f:
        signatures = PdfFileReader(f, strict=False).embedded_signatures
        for sig in signatures:
            status = validate_pdf_signature(sig, ValidationContext(trust_roots=[], allow_fetching=False))
            assert status.intact and status.valid
            assert status.modification_level != ModificationLevel.OTHER


@pytest.mark.parametrize('rotation', [90, 180, 270])
def test_rotated_pages_can_be_signed(tmp_path, key, rotation):
    source = tmp_path / 'rotated.pdf'
    dest = tmp_path / 'signed.pdf'
    document = pikepdf.new()
    document.add_blank_page(page_size=(595, 842)).Rotate = rotation
    document.save(source)
    assert sign_pdf(source, dest, key, 'F') == 1
    with pikepdf.open(dest) as signed:
        assert int(signed.pages[0].Rotate) == rotation
        assert len(signed.pages[0]['/Annots']) == 1


def test_last_and_list(src, tmp_path, key):
    d1 = tmp_path / "l.pdf"
    assert sign_pdf(src, d1, key, "L") == 1
    assert [p for p, _ in sigs(d1)] == [3]
    d2 = tmp_path / "x.pdf"
    assert sign_pdf(src, d2, key, "3,1,1") == 2
    assert [p for p, _ in sigs(d2)] == [1, 3]


@pytest.mark.parametrize("bad", ["4", "0", "x", "1,,2", "-1", "1.5"])
def test_bad_specs(src, tmp_path, key, bad):
    dest = tmp_path / "o.pdf"
    with pytest.raises(ValueError):
        sign_pdf(src, dest, key, bad)
    assert not dest.exists()


def test_dest_exists(src, tmp_path, key):
    dest = tmp_path / "o.pdf"
    dest.write_bytes(b"keep")
    with pytest.raises(FileExistsError):
        sign_pdf(src, dest, key, "A")
    assert dest.read_bytes() == b"keep"
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".icegate")] == []


@pytest.mark.skipif(shutil.which("pdfsig") is None, reason="pdfsig missing")
def test_pdfsig(src, tmp_path, key):
    dest = tmp_path / "o.pdf"
    sign_pdf(src, dest, key, "A")
    out = subprocess.run(["pdfsig", str(dest)], capture_output=True, text=True).stdout
    assert out.count("Signature is Valid.") == 3
    assert "Signature Validation: Signature is Valid." in out or "Signature is Valid." in out
    assert out.count("Total document signed") == 1 or out.count("Total document signed") == 3
    last = out.split("Signature #3")[1]
    assert "Total document signed" in last
    assert "Signature is Invalid" not in out and "Digest Mismatch" not in out
