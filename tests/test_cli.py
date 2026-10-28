import contextlib
import os
import stat

import pikepdf
import pytest
from test_text import FakeKey

from icegate_sign import cli, text, token


@pytest.fixture
def fake_token(monkeypatch):
    key = FakeKey()
    calls = []

    @contextlib.contextmanager
    def session(module, label=None, pin=None):
        calls.append(1)
        yield key

    monkeypatch.setattr(token, "session", session)
    return calls


def make_pdf(path, pages=2):
    pdf = pikepdf.new()
    for _ in range(pages):
        pdf.add_blank_page()
    pdf.save(path)


def test_batch_signs_all_types_and_leaves_originals(tmp_path, fake_token):
    be, xml, pdf = tmp_path / "a b.be", tmp_path / "x.xml", tmp_path / "r.pdf"
    be.write_bytes(b"HDR\x1dBODY\n")
    xml.write_text('<?xml version="1.0"?><a>café</a>', encoding="utf-8")
    make_pdf(pdf)
    before = {p: p.read_bytes() for p in (be, xml, pdf)}
    assert cli.main(["sign", str(be), str(xml), str(pdf)]) == 0
    assert len(fake_token) == 1  # one session (one PIN) for the whole batch
    assert text.verify((tmp_path / "a_b_Signed.be").read_bytes()) == b"HDR\x1dBODY"
    assert text.verify((tmp_path / "x_Signed.xml").read_bytes()).startswith(b"<?xml")
    assert (tmp_path / "r_Signed.pdf").stat().st_size > before[pdf].__len__()
    assert all(p.read_bytes() == b for p, b in before.items())
    # outputs follow the umask, not mkstemp's 0600
    assert stat.S_IMODE((tmp_path / "x_Signed.xml").stat().st_mode) != 0o600
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".icegate-")]


def test_rerun_skips_existing(tmp_path, fake_token):
    f = tmp_path / "a.be"; f.write_bytes(b"x")
    assert cli.main(["sign", str(f)]) == 0
    first = (tmp_path / "a_Signed.be").read_bytes()
    assert cli.main(["sign", str(f)]) == 1  # nothing to do
    assert (tmp_path / "a_Signed.be").read_bytes() == first


def test_bad_inputs_fail_before_pin_but_good_ones_still_sign(tmp_path, fake_token):
    good, bad_pdf, empty = tmp_path / "g.be", tmp_path / "bad.pdf", tmp_path / "e.be"
    good.write_bytes(b"ok"); bad_pdf.write_bytes(b"not a pdf"); empty.write_bytes(b"  \n")
    assert cli.main(["sign", str(bad_pdf), str(empty), str(good)]) == 1
    assert (tmp_path / "g_Signed.be").exists()
    assert not (tmp_path / "bad_Signed.pdf").exists() and not (tmp_path / "e_Signed.be").exists()


def test_symlink_input_refused(tmp_path, fake_token):
    real = tmp_path / "real.be"; real.write_bytes(b"x")
    link = tmp_path / "link.be"; link.symlink_to(real)
    assert cli.main(["sign", str(link)]) == 1 and not fake_token


def test_signing_error_does_not_abort_batch(tmp_path, monkeypatch, fake_token):
    from icegate_sign import pdf
    boom = tmp_path / "boom.pdf"; make_pdf(boom)
    ok = tmp_path / "ok.be"; ok.write_bytes(b"x")
    monkeypatch.setattr(pdf, "sign_pdf", lambda *a, **k: (_ for _ in ()).throw(KeyError("pyhanko internal")))
    assert cli.main(["sign", str(boom), str(ok)]) == 1
    assert (tmp_path / "ok_Signed.be").exists()


def test_token_error_is_clean(tmp_path, monkeypatch, capsys):
    @contextlib.contextmanager
    def session(*a, **k):
        raise RuntimeError("no token found")
        yield
    monkeypatch.setattr(token, "session", session)
    f = tmp_path / "a.be"; f.write_bytes(b"x")
    assert cli.main(["sign", str(f)]) == 1
    assert "no token found" in capsys.readouterr().err


def test_colliding_outputs_rejected_before_signing(tmp_path, fake_token):
    a, b = tmp_path / "a b.be", tmp_path / "a_b.be"
    a.write_bytes(b"1"); b.write_bytes(b"2")
    assert cli.main(["sign", str(a), str(b), str(a)]) == 1
    assert (tmp_path / "a_b_Signed.be").read_bytes().startswith(b"1")  # first claim wins, once


def test_skip_makes_exit_nonzero(tmp_path, fake_token):
    s, t = tmp_path / "s.be", tmp_path / "t.be"
    s.write_bytes(b"1"); t.write_bytes(b"2"); (tmp_path / "s_Signed.be").write_bytes(b"old")
    assert cli.main(["sign", str(s), str(t)]) == 1
    assert (tmp_path / "t_Signed.be").exists() and (tmp_path / "s_Signed.be").read_bytes() == b"old"


def test_zero_page_pdf_rejected(tmp_path, fake_token):
    z = tmp_path / "z.pdf"; make_pdf(z, pages=0)
    assert cli.main(["sign", str(z)]) == 1 and not (tmp_path / "z_Signed.pdf").exists()


def test_publish_falls_back_without_hardlinks(tmp_path, monkeypatch):
    from icegate_sign import files
    monkeypatch.setattr(os, "link", lambda *a, **k: (_ for _ in ()).throw(PermissionError("no hard links")))
    files.publish(b"data", tmp_path / "o.be")
    assert (tmp_path / "o.be").read_bytes() == b"data"
    with pytest.raises(FileExistsError):
        files.publish(b"x", tmp_path / "o.be")
    assert [p.name for p in tmp_path.iterdir()] == ["o.be"]


def test_verify_text_and_pdf_and_tamper(tmp_path, fake_token, capsys):
    be, pdf_in = tmp_path / "a.be", tmp_path / "r.pdf"
    be.write_bytes(b"BODY"); make_pdf(pdf_in)
    assert cli.main(["sign", str(be), str(pdf_in)]) == 0
    be_s, pdf_s = tmp_path / "a_Signed.be", tmp_path / "r_Signed.pdf"
    assert cli.main(["verify", str(be_s), str(pdf_s)]) == 0
    be_s.write_bytes(be_s.read_bytes().replace(b"BODY", b"B0DY", 1))
    assert cli.main(["verify", str(be_s)]) == 1
    assert cli.main(["verify", str(pdf_in)]) == 1  # unsigned PDF
    assert "FAILED" in capsys.readouterr().err


def test_dry_run_touches_nothing_and_needs_no_token(tmp_path, fake_token, capsys):
    f = tmp_path / "a.be"; f.write_bytes(b"x")
    assert cli.main(["sign", "--dry-run", str(f)]) == 0
    assert not fake_token and not (tmp_path / "a_Signed.be").exists()
    assert "would sign" in capsys.readouterr().out


def test_output_dir(tmp_path, fake_token):
    out = tmp_path / "out"; out.mkdir()
    f = tmp_path / "a.be"; f.write_bytes(b"x")
    assert cli.main(["sign", "-o", str(out), str(f)]) == 0
    assert (out / "a_Signed.be").exists() and not (tmp_path / "a_Signed.be").exists()
    assert cli.main(["sign", "-o", str(tmp_path / "missing"), str(f)]) == 1


def test_certs_and_doctor_report_without_token(tmp_path, monkeypatch, capsys):
    import datetime
    info = {"label": "T", "model": "M", "serial": "1", "pin_locked": False, "pin_final_try": False, "pin_count_low": False,
            "certs": [{"label": "c", "cn": "ACME", "issuer": "CA", "serial": "ab", "rsa": True,
                       "not_after": datetime.datetime(2030, 1, 1), "days_left": 900}]}
    monkeypatch.setattr(token, "token_info", lambda module: info)
    assert cli.main(["certs"]) == 0 and "ACME" in capsys.readouterr().out
    mod = tmp_path / "m.so"; mod.write_bytes(b"")
    assert cli.main(["doctor", "--module", str(mod)]) in (0, 1)  # pcscd state is host-dependent
    out = capsys.readouterr().out
    assert "usable RSA certificate" in out and "PIN not locked" in out

    def boom(module):
        raise RuntimeError("no token found")
    monkeypatch.setattr(token, "token_info", boom)
    assert cli.main(["certs"]) == 1 and cli.main(["doctor", "--module", str(mod)]) == 1


def test_command_word_is_optional(tmp_path, fake_token, capsys):
    f = tmp_path / "a.be"; f.write_bytes(b"x")
    assert cli.main(["-n", str(f)]) == 0  # options or files first means `sign`
    assert cli.main([str(f), "--dry-run"]) == 0
    assert capsys.readouterr().out.count("would sign") == 2
