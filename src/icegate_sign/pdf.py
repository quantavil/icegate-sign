"""nCode/ICEGATE-style PDF signing: one visible incremental signature per page."""
from __future__ import annotations

import hashlib
import io
import logging
import time
from dataclasses import dataclass, replace
from pathlib import Path

from asn1crypto import x509 as asn1_x509
from asn1crypto.algos import SignedDigestAlgorithm
from . import files
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.font.basic import SimpleFontEngineFactory
from pyhanko.pdf_utils.layout import AxisAlignment, BoxConstraints, SimpleBoxLayoutRule
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.text import TextBoxStyle
from pyhanko.pdf_utils import generic
from pyhanko.sign import fields, signers
from pyhanko.sign.signers import pdf_signer as _pdf_signer_mod
from pyhanko.sign.fields import SigFieldSpec
from pyhanko.stamp import TextStamp, TextStampStyle


class _WhiteTextStamp(TextStamp):
    def render(self):
        box = self.box
        rotation = self.style.rotation
        if rotation in (90, 270):
            self.box = BoxConstraints(width=box.height, height=box.width)
        content = super().render()
        w, h = self.box.width, self.box.height
        background = b'q 1 1 1 rg 0 0 %g %g re f 0 g 0 G ' % (w, h)
        self.box = box
        transform = {0: b'', 90: b'0 1 -1 0 %g 0 cm ' % h,
                     180: b'-1 0 0 -1 %g %g cm ' % (w, h),
                     270: b'0 -1 1 0 0 %g cm ' % w}[rotation]
        return b'q ' + transform + background + content + b' Q Q'


@dataclass(frozen=True)
class _SignatureStyle(TextStampStyle):
    rotation: int = 0

    def create_stamp(self, writer, box, text_params):
        return _WhiteTextStamp(writer=writer, style=self, box=box, text_params=text_params)


class TokenSigner(signers.Signer):
    """pyHanko Signer delegating RSA PKCS#1 v1.5 / SHA-256 to a token key object."""

    def __init__(self, key):
        self._key = key
        super().__init__(
            signing_cert=asn1_x509.Certificate.load(key.cert_der),
            signature_mechanism=SignedDigestAlgorithm({"algorithm": "sha256_rsa"}),
        )

    async def async_sign_raw(
        self, data: bytes, digest_algorithm: str, dry_run=False
    ) -> bytes:
        if digest_algorithm.lower() != "sha256":
            raise ValueError(f"unsupported digest algorithm {digest_algorithm!r}")
        if dry_run:
            bits = self.signing_cert.public_key.bit_size
            return b"\x00" * ((bits + 7) // 8)
        digest = hashlib.sha256(data).digest()
        return self._key.sign_hashed("sha256", digest)


class _SigObject(_pdf_signer_mod.SignatureObject):
    """pyHanko signature dict that keeps /Reason and /Location present (empty),
    as nCode does."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for k in ("/Reason", "/Location"):
            if k not in self:
                self[generic.pdf_name(k)] = generic.pdf_string("")


def parse_pages(spec: str, total: int) -> list[int]:
    if total < 1:
        raise ValueError("PDF has no pages")
    s = (spec or "").strip()
    u = s.upper()
    if not s or u == "F":
        return [1]
    if u == "A":
        return list(range(1, total + 1))
    if u == "L":
        return [total]
    out: set[int] = set()
    for part in s.split(","):
        part = part.strip()
        if not part.isascii() or not part.isdigit():
            raise ValueError(f"invalid page number {part!r} in {spec!r}")
        n = int(part)
        if not 1 <= n <= total:
            raise ValueError(f"page {n} out of range 1..{total}")
        out.add(n)
    return sorted(out)


def check(src: Path, pages: str = "A") -> None:
    """Raise ValueError/OSError if src cannot be signed with this page spec (no token needed)."""
    try:
        total = int(PdfFileReader(io.BytesIO(Path(src).read_bytes()), strict=False).root["/Pages"]["/Count"])
    except Exception as e:
        raise ValueError(f"unreadable PDF: {e}") from e
    parse_pages(pages, total)


def sign_pdf(src: Path, dest: Path, key, pages: str = "A", box=None) -> int:
    """Sign src into dest (must not exist). Returns the number of signatures."""
    src, dest = Path(src), Path(dest)
    if dest.exists():
        raise FileExistsError(str(dest))
    data = src.read_bytes()
    total = int(PdfFileReader(io.BytesIO(data), strict=False).root["/Pages"]["/Count"])
    plist = parse_pages(pages, total)
    signer = TokenSigner(key)
    # common name only: subject_name would append the certificate holder's email to every stamp
    cn = signer.signing_cert.subject.native.get("common_name") or "signer"
    style = _SignatureStyle(
        stamp_text="Digitally signed\nDigitally signed by " + cn.replace("%", "%%") + "\nDate: %(ts)s\nReason:\nLocation:",
        text_box_style=TextBoxStyle(font=SimpleFontEngineFactory("Helvetica", avg_width=0.5),
                                    font_size=11, text_color=(0, 0, 0)),
        inner_content_layout=SimpleBoxLayoutRule(
            x_align=AxisAlignment.ALIGN_MIN, y_align=AxisAlignment.ALIGN_MID,
        ),
        border_width=1,
        border_color=(0, 0, 0),
    )
    cur = io.BytesIO(data)
    stamp = int(time.time() * 1000)
    orig_cls = _pdf_signer_mod.SignatureObject
    _pdf_signer_mod.SignatureObject = _SigObject
    try:
        cur = _sign_pages(cur, plist, signer, style, stamp, box)
    finally:
        _pdf_signer_mod.SignatureObject = orig_cls
    files.publish(cur.getvalue(), dest)  # raises FileExistsError rather than overwriting
    return len(plist)


def _inherited(page, key, default=None):
    while page is not None:
        if isinstance(page, generic.IndirectObject):
            page = page.get_object()
        if key in page:
            return page[key]
        page = page.get('/Parent')
    return default


def _footer_box(writer, page_index):
    page_ref, _ = writer.find_page_for_modification(page_index)
    page = page_ref.get_object()
    rotation = int(_inherited(page, '/Rotate', 0)) % 360
    if rotation not in (0, 90, 180, 270):
        raise ValueError('page rotation must be a multiple of 90 degrees')
    media = list(_inherited(page, '/MediaBox'))
    crop = list(_inherited(page, '/CropBox', media))
    left, bottom, right, top = map(float, crop)
    if (top - bottom if rotation in (90, 270) else right - left) < 350:
        raise ValueError('page is too narrow for the signature footer')
    index = {0: 1, 90: 2, 180: 3, 270: 0}[rotation]
    edge = (min if rotation in (0, 270) else max)(float(media[index]), float(crop[index]))
    edge += -100 if rotation in (0, 270) else 100
    media[index] = crop[index] = generic.FloatObject(edge)
    page[generic.pdf_name('/MediaBox')] = generic.ArrayObject(media)
    page[generic.pdf_name('/CropBox')] = generic.ArrayObject(crop)
    writer.mark_update(page_ref)
    boxes = {0: (left+5, edge+5, left+345, edge+95),
             90: (edge-95, bottom+5, edge-5, bottom+345),
             180: (right-345, edge-95, right-5, edge-5),
             270: (edge+5, top-345, edge+95, top-5)}
    return boxes[rotation], rotation


def _sign_pages(cur, plist, signer, style, stamp, box):
    boxes = {}
    if box is None:
        writer = IncrementalPdfFileWriter(cur, strict=False)
        boxes = {pg: _footer_box(writer, pg - 1) for pg in plist}
        prepared = io.BytesIO()
        writer.write(prepared)
        prepared.seek(0)
        cur = prepared
    for i, pg in enumerate(plist):
        name = f"{pg}Ncode{stamp + i}"
        w = IncrementalPdfFileWriter(cur, strict=False)
        signature_box, rotation = (box, 0) if box is not None else boxes[pg]
        meta = signers.PdfSignatureMetadata(
            field_name=name,
            md_algorithm="sha256",
            subfilter=fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED,
            reason="",
            location="",
            name="(n)Code Solutions",
            embed_validation_info=False,
            use_pades_lta=False,
            certify=False,
        )
        pdf_signer = signers.PdfSigner(
            meta,
            signer=signer,
            stamp_style=replace(style, rotation=rotation),
            new_field_spec=SigFieldSpec(
                sig_field_name=name, on_page=pg - 1, box=signature_box
            ),
        )
        out = io.BytesIO()
        pdf_signer.sign_pdf(w, output=out)
        out.seek(0)
        cur = out
    return cur


def verify(path: Path) -> list[dict]:
    """Integrity check of every signature (no trust/revocation checking, no network)."""
    from pyhanko.sign.validation import validate_pdf_signature
    from pyhanko.sign.validation.status import SignatureCoverageLevel
    from pyhanko_certvalidator import ValidationContext

    # Trust-path failures are expected (integrity only) and pyHanko logs them loudly.
    for name in ("pyhanko", "pyhanko_certvalidator"):
        logging.getLogger(name).setLevel(logging.CRITICAL)
    with open(path, "rb") as fh:
        reader = PdfFileReader(fh, strict=False)
        out = []
        for sig in reader.embedded_signatures:
            st = validate_pdf_signature(sig, ValidationContext(trust_roots=[], allow_fetching=False))
            cert = st.signing_cert
            out.append({"field": sig.field_name, "intact": bool(st.intact), "valid": bool(st.valid),
                        "whole_file": st.coverage == SignatureCoverageLevel.ENTIRE_FILE,
                        "signer": cert.subject.native.get("common_name", "?") if cert else "?"})
        return out
