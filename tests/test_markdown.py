from doku_agent import markdown

PAGE = """Einleitung

## Zweck

Webserver für das Intranet.

## Betrieb

```bash
# kein Heading, sondern Kommentar
systemctl restart nginx
```

### Wartung

Monatlich.
"""


def test_sections_ignore_code_fences():
    titles = [(s.level, s.title) for s in markdown.sections(PAGE)]
    assert titles == [(2, "Zweck"), (2, "Betrieb"), (3, "Wartung")]


def test_upsert_block_appends_then_replaces_only_block():
    md = markdown.upsert_block(PAGE, "netbox-device", "| a | b |", heading="Steckbrief")
    assert "## Steckbrief" in md and "<!-- doku-agent:begin netbox-device -->" in md
    md2 = markdown.upsert_block(md, "netbox-device", "| neu |", heading="Steckbrief")
    assert "| neu |" in md2 and "| a | b |" not in md2
    # menschlicher Inhalt bleibt unverändert
    assert "Webserver für das Intranet." in md2 and "systemctl restart nginx" in md2
    assert md2.count("## Steckbrief") == 1


def test_upsert_block_into_existing_section():
    md = markdown.upsert_block(PAGE, "x", "Neu", heading="Zweck")
    zweck = markdown.find_section(md, "Zweck")
    body = "\n".join(md.splitlines()[zweck.start:zweck.end])
    assert "Webserver für das Intranet." in body and "Neu" in body


def test_apply_operations_never_deletes():
    ops = [
        {"op": "append_to_section", "heading": "Betrieb", "content": "Logs unter /var/log/nginx."},
        {"op": "add_section", "heading": "Backup", "after": "Zweck", "content": "Täglich 22 Uhr."},
        {"op": "append_to_section", "heading": "Gibt es nicht", "content": "Text"},
        {"op": "delete_section", "heading": "Zweck", "content": "x"},
    ]
    md, notes = markdown.apply_operations(PAGE, ops)
    for original_line in PAGE.splitlines():
        assert original_line in md
    assert md.index("## Backup") < md.index("## Betrieb")
    assert "Logs unter /var/log/nginx." in md
    assert any("nicht gefunden" in n for n in notes)
    assert any("ignoriert" in n for n in notes)


def test_apply_operations_skips_duplicates():
    md, notes = markdown.apply_operations(PAGE, [{"op": "append_to_section", "heading": "Zweck",
                                                  "content": "Webserver für das Intranet."}])
    assert md == PAGE
    assert notes


def test_ensure_sections_and_table_escaping():
    md = markdown.ensure_sections("## Zweck\n\nx\n", ["Zweck", "Ansprechpartner"])
    assert md.count("## Zweck") == 1 and "## Ansprechpartner" in md
    table = markdown.table(["A", "B"], [["a|b", "z1\nz2"], [None, ""]])
    assert "a\\|b" in table and "z1<br>z2" in table and "| – | – |" in table


def test_unified_diff_new_page():
    diff = markdown.unified_diff("", "neu\n", "x")
    assert "+neu" in diff
