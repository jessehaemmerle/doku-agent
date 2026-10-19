from doku_agent.conventions import detect_slug_style, slugify


def _seed(fake_wiki):
    body = "Intro\n\n## Zweck\n\nx\n\n## Hardware\n\ny\n\n## Ansprechpartner\n\nz\n"
    fake_wiki.add("infrastruktur/server/srv-web01", "srv-web01", body, ["server", "linux"], "Webserver")
    fake_wiki.add("infrastruktur/server/srv-db01", "srv-db01", body, ["server", "linux"], "Datenbank")
    fake_wiki.add("infrastruktur/server/srv-mail01", "srv-mail01", "## Zweck\n\nMail\n", ["server"], "")
    fake_wiki.add("handbuch/vpn-einrichten", "VPN einrichten", "## Schritte\n", ["anleitung"])


def test_profile_learns_tags_sections_and_style(ctx, fake_wiki):
    _seed(fake_wiki)
    conv = ctx.conventions
    assert conv.area_for("infrastruktur/server/srv-neu") == "infrastruktur/server"
    prof = conv.profile_for_path("infrastruktur/server/srv-neu")
    assert prof.page_count == 3
    assert prof.common_tags[0] == "server" and "linux" in prof.common_tags
    # "Zweck" auf 3/3 Seiten, "Hardware" und "Ansprechpartner" auf 2/3 (>= 60 %)
    assert prof.required_sections == ["Zweck", "Hardware", "Ansprechpartner"]  # Reihenfolge der Vorbilder
    assert prof.slug_style == "kebab"
    assert "Bereich: /infrastruktur/server" in prof.summary()


def test_unknown_area_falls_back_to_parent(ctx, fake_wiki):
    _seed(fake_wiki)
    assert ctx.conventions.area_for("infrastruktur/netz/switch01") == "infrastruktur"
    assert ctx.conventions.area_for("neu/bereich/seite") == ""


def test_similar_and_find_by_name(ctx, fake_wiki):
    _seed(fake_wiki)
    conv = ctx.conventions
    assert conv.similar("Wie richte ich das VPN ein?")[0].path == "handbuch/vpn-einrichten"
    assert conv.find_by_name("SRV-DB01").path == "infrastruktur/server/srv-db01"
    assert conv.find_by_name("gibtsnicht") is None


def test_slugify_styles():
    assert slugify("Größe & Übersicht 2.0") == "groesse-uebersicht-2.0"
    assert slugify("Mein Server", "snake") == "mein_server"
    assert detect_slug_style(["a_b", "c_d", "e-f"]) == "snake"
    assert detect_slug_style(["MyPage", "OtherPage"]) == "mixed"
