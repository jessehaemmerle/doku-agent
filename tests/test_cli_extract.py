"""Kommandozeile (bisher ohne Tests) und Textgewinnung aus hochgeladenen Dateien."""

import io

import pytest

from doku_agent import cli
from doku_agent.extract import ExtractError, extract_text
from doku_agent.pages import Block, PageDraft, propose_page


def run(monkeypatch, ctx, *argv) -> int:
    monkeypatch.setattr(cli, "_ctx", lambda args: ctx)
    with pytest.raises(SystemExit) as exit_info:
        cli.main(list(argv))
    return exit_info.value.code


def _wiki_proposal(ctx) -> int:
    return propose_page(ctx, PageDraft(doc_type="freeform", title="Backup", description="d", target_path="it/backup",
                                       blocks=[Block("b", "Ablauf", "Veeam, täglich 22 Uhr")], source="test"))


def _netbox_proposal(ctx) -> int:
    changes = [{"key": k, "category": "network", "label": f"Änderung {k}", "before": "–", "after": "x", "steps": [],
                "requires": []} for k in ("c1", "c2")]
    return ctx.store.add_proposal("netbox_plan", "Netbox: srv1", {"changes": changes, "hints": ["Hinweis A"],
                                                                 "target": {"name": "srv1"}}, summary="2 Änderungen")


def test_proposals_show_and_reject(ctx, monkeypatch, capsys):
    pid = _wiki_proposal(ctx)
    assert run(monkeypatch, ctx, "proposals") == 0
    assert f"#{pid}" in capsys.readouterr().out
    assert run(monkeypatch, ctx, "show", str(pid)) == 0
    out = capsys.readouterr().out
    assert "Backup" in out and "+Veeam, täglich 22 Uhr" in out
    assert run(monkeypatch, ctx, "show", "999") == 1
    assert run(monkeypatch, ctx, "reject", str(pid), "--ignore") == 0
    assert ctx.store.get_proposal(pid).status == "rejected" and ctx.store.is_ignored("wiki:it/backup")
    assert run(monkeypatch, ctx, "proposals", "--status", "rejected") == 0
    assert f"#{pid}" in capsys.readouterr().out


def test_approve_writes_wiki_and_refuses_twice(ctx, monkeypatch, capsys, fake_wiki):
    pid = _wiki_proposal(ctx)
    assert run(monkeypatch, ctx, "approve", str(pid)) == 0
    assert any(p["path"] == "it/backup" for p in fake_wiki.pages.values())
    capsys.readouterr()
    assert run(monkeypatch, ctx, "approve", str(pid)) == 1  # schon übernommen: klare Meldung statt Traceback
    assert "Nicht übernommen" in capsys.readouterr().err
    assert run(monkeypatch, ctx, "reject", str(pid)) == 1
    assert "Nicht abgelehnt" in capsys.readouterr().err
    assert run(monkeypatch, ctx, "approve", "999") == 1


def test_approve_nur_validates_selection(ctx, monkeypatch, capsys):
    pid = _netbox_proposal(ctx)
    assert run(monkeypatch, ctx, "show", str(pid)) == 0
    out = capsys.readouterr().out
    assert "[c1] Änderung c1" in out and "Hinweis: Hinweis A" in out
    assert run(monkeypatch, ctx, "approve", str(pid), "--nur", "gibtsnicht") == 1
    assert ctx.store.get_proposal(pid).status == "pending"
    assert run(monkeypatch, ctx, "approve", str(_wiki_proposal(ctx)), "--nur", "c1") == 2  # --nur nur für Netbox


def test_run_rejects_unknown_job_and_malformed_param(ctx, monkeypatch, capsys):
    assert run(monkeypatch, ctx, "run", "gibtsnicht") == 2
    assert run(monkeypatch, ctx, "run", "netbox_device", "--param", "id42") == 2
    assert "schlüssel=wert" in capsys.readouterr().err


def test_conventions_and_config_error(ctx, monkeypatch, capsys, tmp_path):
    assert run(monkeypatch, ctx, "conventions") == 0
    monkeypatch.undo()
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["-c", str(tmp_path / "fehlt.yaml"), "proposals"])
    assert exit_info.value.code == 2 and "Konfigurationsfehler" in capsys.readouterr().err


# --- Textgewinnung ---------------------------------------------------------------------------------

def test_extract_text_files_and_encodings(tmp_path):
    (tmp_path / "a.txt").write_text("Größe: 5 GB", encoding="utf-8")
    (tmp_path / "b.cfg").write_bytes("Größe".encode("cp1252"))
    assert extract_text(tmp_path / "a.txt") == "Größe: 5 GB" and extract_text(tmp_path / "b.cfg") == "Größe"
    (tmp_path / "c.bin").write_bytes(b"MZ\x00\x00\x01")
    with pytest.raises(ExtractError, match="Binärdatei"):
        extract_text(tmp_path / "c.bin")


def test_extract_reports_files_without_text(tmp_path):
    """Gescanntes PDF oder leere Datei: nicht stillschweigend als berücksichtigt führen."""
    from pypdf import PdfWriter
    writer = PdfWriter()
    writer.add_blank_page(width=200, height=200)
    buf = io.BytesIO()
    writer.write(buf)
    (tmp_path / "scan.pdf").write_bytes(buf.getvalue())
    (tmp_path / "leer.txt").write_text("  \n")
    for name in ("scan.pdf", "leer.txt"):
        with pytest.raises(ExtractError, match="kein auslesbarer Text"):
            extract_text(tmp_path / name)


def test_extract_docx_with_table(tmp_path):
    import docx
    doc = docx.Document()
    doc.add_paragraph("Backup läuft täglich.")
    table = doc.add_table(rows=1, cols=2)
    table.rows[0].cells[0].text, table.rows[0].cells[1].text = "Job", "FS-Daily"
    doc.save(str(tmp_path / "x.docx"))
    assert extract_text(tmp_path / "x.docx") == "Backup läuft täglich.\nJob | FS-Daily"


def test_freeform_material_names_skipped_files(ctx, tmp_path):
    from doku_agent.generators.freeform import gather_material
    (tmp_path / "leer.txt").write_text("")
    (tmp_path / "ok.txt").write_text("Server srv1")
    material, hints = gather_material(ctx, "Notiz", [tmp_path / "leer.txt", tmp_path / "ok.txt"])
    assert "Server srv1" in material and "leer.txt" not in material
    assert any("leer.txt übersprungen" in h for h in hints)
