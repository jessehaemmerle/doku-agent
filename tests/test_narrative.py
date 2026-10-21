"""Fließtext: Faktenprüfung, zweiter Versuch, feste Vorlage, Cache und Platzierung über den Tabellen."""

import httpx
import pytest

from doku_agent.connectors.netbox import NetboxClient
from doku_agent.egress import EgressGuard
from doku_agent.generators import narrative
from doku_agent.pages import Block, merge_into
from tests.conftest import FakeNetbox

FACTS = """Name: srv01
Plattform: Ubuntu 24.04
Primäre IP: 10.20.0.5/24
Arbeitsspeicher: 16384 MB (16 GB)
Erstellt: 2026-01-15
Regel 7 web-in: eingehend, Dienst HTTPS
UPN: anna@firma.at"""


class SeqLLM:
    """Liefert die vorbereiteten Texte der Reihe nach und merkt sich die Prompts."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.prompts = []

    def text(self, system, user):
        self.prompts.append(user)
        return self.answers.pop(0)

    def fit(self, text, max_chars=None):
        return text


@pytest.mark.parametrize("text", [
    "**srv01** läuft mit Ubuntu 24.04 und 16 GB Arbeitsspeicher unter 10.20.0.5/24.",
    "Eingetragen am 15.01.2026, z.B. für Web (Regel 7, „web-in“); Kontakt anna@firma.at, d.h. IPv4 und 16GB.",
    "Die Maschine ist ein **wichtiger** Server, der über das Netz erreichbar ist.",
    "Die Richtlinie gilt für „allen Cloud-Apps“ und die „Conditional-Access-Richtlinie“ betrifft „IP-Adressen“.",
])
def test_belegte_angaben_bestehen(text):
    assert narrative.unverified(text, FACTS) == []


@pytest.mark.parametrize("text, claim", [
    ("Er läuft mit Ubuntu 22.04.", "22.04"),
    ("Er hat 32 GB Arbeitsspeicher.", "32"),
    ("Erreichbar unter 10.20.0.6.", "10.20.0.6"),
    ("Der Webserver lauscht auf Port 443.", "443"),
    ("Er heißt auch srv02.", "srv02"),
    ("Teil von srv01.firma.local.", "srv01.firma.local"),
    ("Er gehört zur Gruppe „Webfarm-01“.", "Webfarm-01"),
    ("Seit 01.02.2025 im Einsatz.", "01.02.2025"),
    ("Admin ist **max@firma.at**.", "max@firma.at"),
    ("Erreichbar unter 10.20.0.50.", "10.20.0.50"),       # kein Teilstring-Treffer in 10.20.0.5
    ("Er heißt auch srv0.", "srv0"),                        # nicht in srv01
    ("Er läuft mit Ubuntu 24.10.", "24.10"),                # andere Version als 24.04
    ("Er hat 20 Interfaces.", "20"),                        # Oktett von 10.20.0.5 ist keine Zahl-Angabe
    ("Aktualisiert um 05:00 Uhr.", "05:00"),                # ganzes Token wird gemeldet
    ("Es gibt 1.000 Einträge.", "1.000"),                   # deutsche Tausender, nicht 1
])
def test_unbelegte_angaben_werden_erkannt(text, claim):
    assert claim in narrative.unverified(text, FACTS)


def test_zweiter_versuch_mit_liste_der_unbelegten_angaben(ctx):
    llm = SeqLLM("srv01 nutzt Port 8443 und 64 GB.", "srv01 hat 16 GB Arbeitsspeicher und läuft mit Ubuntu 24.04.")
    ctx.__dict__["llm"] = llm
    text = narrative.narrate(ctx, "t1", expert="IT", task="Beschreibe.", facts=FACTS, fallback="VORLAGE")
    assert text == "srv01 hat 16 GB Arbeitsspeicher und läuft mit Ubuntu 24.04."
    assert "Diese Angaben stehen nicht in den Daten: 8443, 64" in llm.prompts[1]
    # Zweiter Aufruf mit denselben Daten: aus dem Cache, kein LLM-Aufruf
    assert narrative.narrate(ctx, "t1", expert="IT", task="Beschreibe.", facts=FACTS, fallback="VORLAGE") == text
    assert len(llm.prompts) == 2


def test_vorlage_wenn_auch_der_zweite_versuch_erfindet(ctx, caplog):
    llm = SeqLLM("srv01 hat 64 GB.", "srv01 hat 32 GB.")
    ctx.__dict__["llm"] = llm
    text = narrative.narrate(ctx, "t2", expert="IT", task="Beschreibe.", facts=FACTS, fallback="VORLAGE")
    assert text == "VORLAGE" and "nicht belegt: 32" in caplog.text
    assert narrative.narrate(ctx, "t2", expert="IT", task="Beschreibe.", facts=FACTS, fallback="VORLAGE") == "VORLAGE"
    assert len(llm.prompts) == 2  # Ergebnis (auch die Vorlage) ist zwischengespeichert


def test_aufzaehlung_wird_zu_fliesstext_und_ueberschriften_entfallen(ctx):
    llm = SeqLLM("- srv01\n- Ubuntu 24.04\n- 16 GB", "## Überblick\nsrv01 läuft mit Ubuntu 24.04.")
    ctx.__dict__["llm"] = llm
    text = narrative.narrate(ctx, "t3", expert="IT", task="Beschreibe.", facts=FACTS, fallback="VORLAGE")
    assert text == "srv01 läuft mit Ubuntu 24.04." and "Fließtext statt einer Aufzählung" in llm.prompts[1]


def test_ohne_faktenpruefung_wird_nicht_geprueft(ctx):
    ctx.cfg.narrative.fact_check = False
    ctx.__dict__["llm"] = SeqLLM("srv01 hat 64 GB.")
    assert narrative.narrate(ctx, "t4", expert="IT", task="x", facts=FACTS, fallback="V") == "srv01 hat 64 GB."


def test_fakten_aus_markdown_tabellen():
    md = ("<!-- doku-agent:begin x -->\n### Rolle X\n\n| Wer | Art |\n|---|---|\n| [Anna](/a) | Benutzer<br>aktiv |\n"
          "| B \\| C | – |\n<!-- doku-agent:end x -->")
    assert narrative.facts_from_markdown(md) == "Rolle X\nWer: Anna; Art: Benutzer, aktiv\nWer: B | C"


def test_neuer_textblock_kommt_ueber_die_bestehenden_tabellen():
    old = ("Eigene Einleitung.\n\n## Steckbrief\n\n<!-- doku-agent:begin netbox-device -->\n| a | b |\n"
           "<!-- doku-agent:end netbox-device -->\n\n## Notizen\n\nVon Hand.\n")
    new, _ = merge_into(old, [Block("netbox-summary", "Überblick", "Fließtext."),
                              Block("netbox-device", "Steckbrief", "| a | c |")], [])
    assert new.index("## Überblick") < new.index("## Steckbrief") < new.index("## Notizen")
    assert new.startswith("Eigene Einleitung.") and "Von Hand." in new and "| a | c |" in new


@pytest.fixture
def nb(ctx):
    nbf = FakeNetbox()
    ctx.__dict__["netbox"] = NetboxClient(ctx.cfg.netbox, EgressGuard.from_config(ctx.cfg),
                                          transport=httpx.MockTransport(nbf.handler))
    dev = nbf.add("dcim/devices", {"name": "srv01", "serial": "S1", "role": {"name": "Server", "slug": "server"},
                                   "site": {"name": "Zentrale", "slug": "hq"}, "platform": {"name": "Ubuntu 24.04"},
                                   "status": {"value": "active", "label": "Aktiv"}})
    nbf.add("dcim/interfaces", {"device": dev["id"], "name": "eth0", "type": {"label": "1000BASE-T"}})
    return nbf, dev


def test_steckbrief_hat_ueberblick_oben_mit_vorlage_bei_erfindungen(ctx, nb, fake_wiki):
    from doku_agent.generators.netbox_docs import document_object

    nbf, dev = nb
    ctx.__dict__["llm"] = SeqLLM("srv01 steht in Rack 7.", "srv01 steht in Rack 9.")
    content = ctx.store.get_proposal(document_object(ctx, "device", dev["id"])).payload["content"]
    assert content.index("## Überblick") < content.index("## Steckbrief")
    assert "**srv01** ist ein Gerät mit der Rolle Server am Standort Zentrale. Plattform: Ubuntu 24.04." in content


def test_steckbrief_ohne_ueberblick_wenn_abgeschaltet(ctx, nb, fake_wiki):
    from doku_agent.generators.netbox_docs import document_object

    nbf, dev = nb
    ctx.cfg.narrative.areas = ["audit", "overview"]
    content = ctx.store.get_proposal(document_object(ctx, "device", dev["id"])).payload["content"]
    assert "## Überblick" not in content and "## Steckbrief" in content


def test_pruef_und_uebersichtsseiten_haben_text_ueber_den_tabellen(ctx, fake_wiki):
    from tests.test_entra import FakeEntraGraph, _pages
    from doku_agent.connectors.entra import EntraClient
    from doku_agent.generators import entra_docs

    fake = FakeEntraGraph()
    ctx.cfg.entra.enabled = True
    ctx.__dict__["entra"] = EntraClient(ctx.cfg.entra, ctx.cfg.intune,
                                        EgressGuard({"graph.microsoft.com", "login.microsoftonline.com"}),
                                        transport=httpx.MockTransport(fake.handler))
    pages = _pages(ctx, entra_docs.document_entra(ctx))
    audit = pages["identitaet/entra/pruefung"]
    assert audit.index("## Bewertung") < audit.index("## Übersicht") < audit.index("## Befunde")
    for slug in ("conditional-access", "authentifizierungsmethoden", "mandant", "rollen"):
        page = pages[f"identitaet/entra/{slug}"]
        assert page.index("## Zusammenfassung") < page.index("| ")  # Text vor der ersten Tabelle
    # Die Bewertung bekommt die Befunde als Fakten
    prompt = next(u for kind, u in ctx.llm.calls if "automatischen Prüfung von Entra ID" in u)
    assert "Richtlinien nicht durchgesetzt: 1 Befunde" in prompt and "Länder blockieren" in prompt
    assert "Befunde gesamt: " in prompt  # Summe vorgegeben, damit das Modell nicht selbst rechnet


def test_fortigate_pruefung_und_abdeckung_haben_bewertung(ctx, fake_wiki):
    from doku_agent.generators import fortigate_docs as fd
    from tests.test_fortigate import _audit_data, _p

    data = _audit_data([_p(30, ["all"], ["all"], ["ALL"], sintf="wan1", dintf="internal")],
                       interfaces=[{"name": "wan1", "role": "wan"}])
    intro, blocks = fd.audit_page(ctx, data)
    assert [b.heading for b in blocks] == ["Bewertung", "Übersicht", "Befunde"]
    ctx.cfg.narrative.areas = []
    assert [b.heading for b in fd.audit_page(ctx, data)[1]] == ["Übersicht", "Befunde"]


def test_neuer_block_bleibt_unter_der_seitenueberschrift():
    old = ("# srv01\n\nEigene Notizen.\n\n## Steckbrief\n\n<!-- doku-agent:begin netbox-device -->\n| a | b |\n"
           "<!-- doku-agent:end netbox-device -->\n")
    new, _ = merge_into(old, [Block("netbox-summary", "Überblick", "Text."),
                              Block("netbox-device", "Steckbrief", "| a | b |")], [])
    assert new.index("# srv01") < new.index("Eigene Notizen.") < new.index("## Überblick") < new.index("## Steckbrief")


class DownLLM:
    def __init__(self):
        self.calls = 0

    def text(self, system, user):
        from doku_agent.llm import LLMError
        self.calls += 1
        raise LLMError("Ollama nicht erreichbar")

    def fit(self, text, max_chars=None):
        return text


def test_ohne_sprachmodell_entsteht_der_steckbrief_ohne_ueberblick(ctx, nb, fake_wiki, caplog):
    from doku_agent.generators.netbox_docs import document_object

    nbf, dev = nb
    llm = DownLLM()
    ctx.__dict__["llm"] = llm
    content = ctx.store.get_proposal(document_object(ctx, "device", dev["id"])).payload["content"]
    assert "## Steckbrief" in content and "## Überblick" not in content
    assert narrative.narrate(ctx, "x", expert="IT", task="t", facts=FACTS, fallback="V") is None
    assert llm.calls == 1 and "Sprachmodell nicht erreichbar" in caplog.text  # nur einmal je Lauf versucht


def test_vorlage_wird_nach_einer_woche_erneut_versucht(ctx, monkeypatch):
    import time as real_time

    ctx.__dict__["llm"] = SeqLLM("srv01 hat 64 GB.", "srv01 hat 32 GB.", "srv01 läuft mit Ubuntu 24.04.")
    assert narrative.narrate(ctx, "t5", expert="IT", task="x", facts=FACTS, fallback="VORLAGE") == "VORLAGE"
    assert narrative.narrate(ctx, "t5", expert="IT", task="x", facts=FACTS, fallback="VORLAGE") == "VORLAGE"
    later = real_time.time() + 8 * 86400
    monkeypatch.setattr(narrative.time, "time", lambda: later)
    assert narrative.narrate(ctx, "t5", expert="IT", task="x", facts=FACTS, fallback="VORLAGE") == \
        "srv01 läuft mit Ubuntu 24.04."


def test_speichergroessen_ohne_null_gb():
    from doku_agent.generators.netbox_docs import _size

    assert _size(512, "RAM") == "512 MB" and _size(1536, "RAM") == "1536 MB (1.5 GB)"
    assert _size(16384, "RAM") == "16384 MB (16 GB)" and _size(100000, "Disk") == "100000 MB (100 GB)"


def test_fortigate_ohne_vpn_ruft_kein_sprachmodell(ctx):
    from doku_agent.generators import fortigate_docs as fd

    llm = SeqLLM()
    ctx.__dict__["llm"] = llm
    data = fd.FortiData("fw", "root", {"hostname": "fw"})
    intro, blocks = fd.vpn_page(ctx, data)
    assert llm.prompts == [] and blocks[0].content.startswith("| Eigenschaft")


def test_entra_bewertung_nennt_fehlende_pim_daten(ctx, fake_wiki):
    from tests.test_entra import FakeEntraGraph
    from doku_agent.connectors.entra import EntraClient
    from doku_agent.generators import entra_docs

    fake = FakeEntraGraph()
    fake.unlicensed = {"/v1.0/roleManagement/directory/roleAssignmentSchedule",
                       "/v1.0/roleManagement/directory/roleEligibility"}
    ctx.cfg.entra.enabled = True
    ctx.__dict__["entra"] = EntraClient(ctx.cfg.entra, ctx.cfg.intune,
                                        EgressGuard({"graph.microsoft.com", "login.microsoftonline.com"}),
                                        transport=httpx.MockTransport(fake.handler))
    entra_docs.document_entra(ctx, ["audit"])
    prompt = next(u for kind, u in ctx.llm.calls if "automatischen Prüfung von Entra ID" in u)
    assert "PIM-Daten fehlen" in prompt and "Keine Notfallkonten konfiguriert" in prompt
