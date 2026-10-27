# AGENTS.md

Guidance for work in this repository: a Linux-native CLI that signs ICEGATE files with a PKCS#11 USB token (Hypersecu HYP2003 / Feitian ePass2003 family). It replaces a Wine + nCode PKI Component workflow (kept for reference in `~/Documents/ICEGATE-HyperPKI-Linux`).

## Layout

- `src/icegate_sign/text.py`: BE/SB/TXT/XML signer and verifier (nCode text format).
- `src/icegate_sign/pdf.py`: PDF signer (pyHanko, one visible incremental signature per page) with a small `Signer` subclass.
- `src/icegate_sign/token.py`: PKCS#11 session, certificate/key selection, `Key.sign_hashed`.
- `src/icegate_sign/cli.py`: subcommands `sign` (`-n` dry run, `-o` output dir, `--pages`, `--cert`, `--module`), `verify`, `certs`, `doctor`; validation before the PIN prompt.
- `src/icegate_sign/files.py`: `publish`, the only way outputs are written (temp file + hard link, exclusive-create fallback for FAT/exFAT).
- `tests/`: software-key tests only (`FakeKey`); no token is needed. Run `uv run pytest -q`. Set `ICEGATE_GOLDEN=<folder>` to also verify real nCode-signed `*[signed].sb/.be` files.

## Invariants (do not break)

- Never store, log or pass the PIN via argv/env; prompt once per run; never retry `C_Login`.
- Never overwrite an output; write via temp file + `os.link`; refuse symlinked inputs; validate every file before asking for the PIN.
- Sign with `CKM_RSA_PKCS` and our own DigestInfo (`token.DIGEST_INFO`). No silent hash fallback: text uses SHA-1 DigestInfo over the 32-byte SHA-256 digest, PDF uses SHA-256, exactly as nCode does. Every signature is verified against the certificate before it is returned.
- Text/XML files are signed as raw bytes with leading/trailing bytes <= 0x20 trimmed. ICEGATE gives XML no special format: the tags are appended after the document (no XMLDSig).
- PDF defaults follow ICEGATE's website except a compact stamp (box `5,8,185,52`, common name only, no email), all pages, detached CMS (`adbe.pkcs7.detached`), empty Reason/Location, creator `(n)Code Solutions`.
- Don't add `pyhanko[pkcs11]` (its `python-pkcs11` pin conflicts); the token code is our own.
- Don't bypass TLS verification (`curl -k`, `--ignore-https-errors`) when reading ICEGATE pages.

## Status and what is unverified

Verified: text format against the official utility's output (`110Signed.be`) and real nCode `.sb` files; PDF and text signing with software keys; on a real HYP2003 token, `certs`, `doctor` and PDF signing (`pdfsig` valid), and ICEGATE accepted a signed file (user-reported 2026-10-27).
Token: OpenSC cannot read the HYP2003 (Feitian ENTERSAFE-ESPK layout, not PKCS#15), so the default module is the vendor `libcastle_v2.so.1.0.0` (searched in `~/.local/lib/hyp2003/`, then `~/Documents/hyp2003-linux-driver/`; override with `--module` or `ICEGATE_PKCS11_MODULE`). It is proprietary and must never be committed.
Not verified: signing `.be`/`.sb`/`.txt`/`.xml` on a real token (compare one byte for byte with a known nCode output), real signed XML, and whether anything checks the PDF stamp's look.
Not implemented: nCode's JSON signer (`digSign` block), encrypted PDFs. `verify` is integrity-only (no trust or revocation checks).

## Gotchas

- Skipped outputs (already exist) and any failure make `sign` exit 1.
- `.gitignore` globs: `[signed]` is a character class, so the output pattern is written `*\[signed\].*`. An unescaped version silently ignored `cli.py` and `token.py`.
- `pdf.py` temporarily swaps pyHanko's `SignatureObject` to keep empty `/Reason` and `/Location`; revisit when upgrading pyHanko.
- The signing certificate on the maintainer's token expires 2026-12-10.
- Reverse-engineering notes: ICEGATE's JS calls the nCode local server (`signservice/signdata`); methods `icegatetextSigning` and `signPdfFileClientIcegate` map to `PKICtrl.signTextFiles` and `signPDFFile`. Decompiled with `jadx` from `nCodePkiComponentV4.jar` (vendor file, never commit it).
