# icegate-sign

Sign ICEGATE files (BE, SB, TXT, XML and PDF) with a PKCS#11 USB DSC token from the Linux command line.

## Install

```sh
uv tool install git+https://github.com/quantavil/icegate-sign     # remove: uv tool uninstall icegate-sign
```

Token driver:

- **Hypersecu HYP2003** (USB `2ccf:080a`): OpenSC cannot read it. Install the vendor library from [hyp2003-linux-driver](https://github.com/quantavil/hyp2003-linux-driver) into `~/.local/lib/hyp2003/`; it is found automatically.
- **Other tokens:** `opensc` (default module `/usr/lib/opensc-pkcs11.so`), or pass the vendor library with `--module PATH` or `ICEGATE_PKCS11_MODULE`.

Check with `icegate-sign doctor`. Optional: `poppler` (`pdfsig`) to cross-check PDFs.

## Usage

```sh
icegate-sign certs                          # certificate and days until expiry (no PIN)
icegate-sign invoice.pdf *.sb *.be          # "sign" is optional; one PIN prompt; writes name_Signed.ext beside each file
icegate-sign sign -n *.pdf                  # dry run: no token, no PIN
icegate-sign sign -o out/ --pages L a.pdf   # other folder; PDF pages A (all, default), F, L or 1,3,5
icegate-sign verify name_Signed.pdf        # integrity check, no token needed
```

Other options: `--cert NAME` (several certificates), `--pin-stdin` (read the PIN from stdin for scripts).

All files are validated before the PIN prompt. Outputs are never overwritten, spaces become underscores, and a wrong PIN is not retried. The PIN is never stored. `verify` checks integrity only, not certificate trust or ICEGATE acceptance.

## Formats

| Type | Output |
|---|---|
| `.be` `.sb` `.txt` `.xml` | ICEGATE "Text or XML" format: the text plus `<START-SIGNATURE>`, `<START-CERTIFICATE>` and `<SIGNER-VERSION>` tags (RSA PKCS#1 v1.5, SHA-1 DigestInfo over the SHA-256 of the trimmed text). XML is signed the same way, not with XMLDSig. |
| `.pdf` | One detached CMS signature (SHA-256) per page, with a small visible stamp (name and date) at the bottom left. |

These formats were derived by analysing ICEGATE's signing page and the nCode PKI component it calls, and checked against real files from the official utility. No vendor code is included. Not implemented: the JSON signer and encrypted PDFs.

Status: PDF signing on a real HYP2003 token is verified and accepted by ICEGATE. Text formats match the official output in tests but have not been signed on a real token yet.

## Develop

```sh
uv run pytest -q          # ICEGATE_GOLDEN=<folder of real signed files> adds the golden test
```

## License

AGPL-3.0-or-later. See `LICENSE`.
