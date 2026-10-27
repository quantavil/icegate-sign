"""icegate-sign: sign and check ICEGATE files with a PKCS#11 USB token."""
import argparse
import re
import shutil
import subprocess
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

import pkcs11

from . import files, pdf, text, token

TEXT_SUFFIXES = {".be", ".sb", ".txt", ".xml"}


def output_path(path: Path, outdir: Path | None = None) -> Path:
    return (outdir or path.parent) / (re.sub(r"\s+", "_", path.stem) + "[signed]" + path.suffix)


def _version():
    try:
        return version("icegate-sign")
    except PackageNotFoundError:
        return "dev"


# ---- sign ----------------------------------------------------------------

def cmd_sign(args) -> int:
    outdir = args.output_dir
    if outdir is not None and not outdir.is_dir():
        print(f"output directory {outdir} does not exist", file=sys.stderr)
        return 1
    # Validate everything before asking for the PIN.
    jobs, rc, claimed = [], 0, set()
    for f in args.files:
        dest = output_path(f, outdir)
        try:
            if f.is_symlink() or not f.is_file():
                raise ValueError("not a regular file")
            kind = f.suffix.lower()
            if kind != ".pdf" and kind not in TEXT_SUFFIXES:
                raise ValueError("unsupported type (use .pdf, .be, .sb, .txt or .xml)")
            if dest.exists() or dest.is_symlink():
                print(f"{f}: skipped, {dest} exists", file=sys.stderr)
                rc = 1  # not signed by this run
                continue
            if dest in claimed:
                raise ValueError(f"would write {dest.name}, which another input already maps to")
            claimed.add(dest)
            if kind == ".pdf":
                pdf.check(f, args.pages)
                data = None
            else:
                data = f.read_bytes()
                text.check(data)
            jobs.append((f, dest, data))
        except (ValueError, OSError) as e:
            print(f"{f}: failed ({e})", file=sys.stderr); rc = 1
    if not jobs:
        return rc or 1
    if args.dry_run:
        for f, dest, _ in jobs:
            print(f"{f}: would sign -> {dest}")
        return rc
    try:
        return _sign_all(args, jobs, rc)
    except (RuntimeError, pkcs11.PKCS11Error) as e:
        print(f"token error: {type(e).__name__}: {e}", file=sys.stderr)
        return 1


def _sign_all(args, jobs, rc):
    pin = sys.stdin.readline().rstrip("\r\n") if args.pin_stdin else None
    with token.session(args.module, args.cert, pin) as key:
        for f, dest, data in jobs:
            try:
                if data is None:
                    n = pdf.sign_pdf(f, dest, key, args.pages)
                    print(f"{f}: signed ({n} signature{'s' * (n != 1)}) -> {dest}")
                else:
                    files.publish(text.sign(data, key), dest)
                    print(f"{f}: signed -> {dest}")
            except Exception as e:  # one bad file must not abort the batch
                print(f"{f}: failed ({type(e).__name__}: {e})", file=sys.stderr); rc = 1
    return rc


# ---- verify --------------------------------------------------------------

def cmd_verify(args) -> int:
    rc = 0
    for f in args.files:
        try:
            if f.suffix.lower() == ".pdf":
                sigs = pdf.verify(f)
                if not sigs:
                    raise ValueError("no signatures")
                if not all(s["intact"] and s["valid"] for s in sigs) or not sigs[-1]["whole_file"]:
                    raise ValueError("signature invalid, or the last one does not cover the whole file")
                print(f"{f}: OK, {len(sigs)} signature{'s' * (len(sigs) != 1)} intact; signer {sigs[-1]['signer']}")
            else:
                text.verify(f.read_bytes())
                print(f"{f}: OK, signature matches the embedded certificate")
        except Exception as e:
            print(f"{f}: FAILED ({e})", file=sys.stderr); rc = 1
    print("(integrity only: certificate trust and ICEGATE acceptance are not checked)", file=sys.stderr)
    return rc


# ---- certs / doctor --------------------------------------------------------

def _print_certs(info):
    for c in info["certs"]:
        flag = "" if c["rsa"] else "  [not RSA, unusable]"
        warn = "  [EXPIRED]" if c["days_left"] < 0 else "  [expires soon]" if c["days_left"] < 30 else ""
        print(f"  {c['cn']}  (issuer {c['issuer']}, serial {c['serial']}, valid until {c['not_after']:%Y-%m-%d}, "
              f"{c['days_left']} days left){warn}{flag}")


def cmd_certs(args) -> int:
    try:
        info = token.token_info(args.module)
    except (RuntimeError, pkcs11.PKCS11Error) as e:
        print(f"token error: {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    print(f"Token: {info['label'] or '?'} ({info['model'] or '?'}, serial {info['serial'] or '?'})")
    _print_certs(info)
    return 0 if info["certs"] else 1


def cmd_doctor(args) -> int:
    ok = True

    def line(good, msg, hint=""):
        nonlocal ok
        ok = ok and good
        print(("ok   " if good else "FAIL ") + msg + (f"\n     -> {hint}" if hint and not good else ""))

    line(Path(args.module).is_file(), f"PKCS#11 module {args.module}",
         "install opensc, or pass the vendor library with --module")
    for unit in ("pcscd.socket", "pcscd.service"):
        if shutil.which("systemctl"):
            r = subprocess.run(["systemctl", "is-active", unit], capture_output=True, text=True)
            if r.stdout.strip() == "active":
                line(True, f"{unit} active")
                break
    else:
        line(False, "pcscd is not running", "sudo systemctl enable --now pcscd.socket")
    line(bool(shutil.which("pdfsig")), "pdfsig (optional, cross-checks PDFs)", "sudo pacman -S poppler")
    try:
        info = token.token_info(args.module)
    except Exception as e:
        line(False, f"token: {e}", "plug it in; check `pcsc_scan -r` and that no Wine token manager is running")
    else:
        line(True, f"token {info['label'] or '?'} ({info['model'] or '?'})")
        line(not info["pin_locked"], "PIN not locked")
        if info["pin_final_try"]:
            line(False, "PIN has one try left", "do not sign until you are sure of the PIN")
        elif info["pin_count_low"]:
            print("warn PIN retry counter is low")
        usable = [c for c in info["certs"] if c["rsa"] and c["days_left"] >= 0]
        line(bool(usable), f"{len(usable)} usable RSA certificate(s)", "see `icegate-sign certs`")
        _print_certs({"certs": usable})
    return 0 if ok else 1


# ---- entry point -------------------------------------------------------------

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="icegate-sign", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  icegate-sign certs                        show the token's certificate and days until expiry
  icegate-sign invoice.pdf *.sb             sign files (asks for the PIN once; same as 'icegate-sign sign ...')
  icegate-sign sign -n *.be                 dry run: check files, no token, no PIN
  icegate-sign verify invoice[signed].pdf   check signatures
  icegate-sign doctor                       diagnose the setup

Signed files are written as name[signed].ext beside the originals; existing files are never overwritten.
Use 'icegate-sign COMMAND --help' for a command's options.""")
    ap.add_argument("--version", action="version", version=f"%(prog)s {_version()}")
    sub = ap.add_subparsers(dest="command", required=True, metavar="command")

    def with_module(p):
        p.add_argument("--module", default=token.DEFAULT_MODULE, help=f"PKCS#11 module (default {token.DEFAULT_MODULE})")
        return p

    p = with_module(sub.add_parser("sign", help="sign BE/SB/TXT/XML and PDF files (writes name[signed].ext)"))
    p.add_argument("files", nargs="+", type=Path, metavar="FILE", help="files to sign: .be .sb .txt .xml .pdf")
    p.add_argument("--cert", help="certificate label or common name, if the token has several")
    p.add_argument("--pin-stdin", action="store_true", help="read the PIN from stdin instead of prompting (never pass it as an argument)")
    p.add_argument("--pages", default="A", help="PDF signature pages: A all (default), F first, L last, or 1,3,5")
    p.add_argument("-o", "--output-dir", type=Path, help="write signed files here instead of beside the originals")
    p.add_argument("-n", "--dry-run", action="store_true", help="validate and show what would be written; no PIN, no token")
    p.set_defaults(func=cmd_sign)

    p = sub.add_parser("verify", help="check signatures of signed files (integrity only, no token needed)")
    p.add_argument("files", nargs="+", type=Path, metavar="FILE", help="signed files to check")
    p.set_defaults(func=cmd_verify)

    p = with_module(sub.add_parser("certs", help="list the token's certificates and expiry (no PIN)"))
    p.set_defaults(func=cmd_certs)

    p = with_module(sub.add_parser("doctor", help="diagnose pcscd, PKCS#11 module, token and certificate"))
    p.set_defaults(func=cmd_doctor)

    argv = sys.argv[1:] if argv is None else list(argv)
    if argv and argv[0] not in (*sub.choices, "-h", "--help", "--version"):
        argv.insert(0, "sign")  # `icegate-sign file.pdf` is shorthand for `icegate-sign sign file.pdf`
    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
