"""Tests für die drei AD-Erweiterungen: DNS-Parser, AD-CS-Prüfung, wirksame GPOs (RSoP), Änderungsbericht,
AD im Abdeckungsbericht und der DNS-Netbox-Abgleich."""

from __future__ import annotations

import struct
from datetime import date, datetime, timezone

from doku_agent import ad_dns, changes
from doku_agent.ad_acl import (ALLOWED, ALLOWED_OBJECT, CONTAINER_INHERIT, CONTROL_ACCESS, FULL_CONTROL,
                               WRITE_PROP, Ace, sd_bytes, sid_to_bytes)
from doku_agent.connectors.ad import Entry
from tests.test_ad import DOM, BASE, CFG_NC, FakeAd

GPO_A = "{AAAAAAAA-0000-0000-0000-000000000001}"
GPO_B = "{BBBBBBBB-0000-0000-0000-000000000002}"


# --- DNS-Parser (MS-DNSP dnsRecord) ---------------------------------------------------------------

def _name(fqdn: str) -> bytes:
    raw = b"".join(bytes([len(p)]) + p.encode() for p in fqdn.split(".")) + b"\x00"
    return bytes([len(raw), fqdn.count(".") + 1]) + raw


def _blob(rtype: int, data: bytes, ttl: int = 3600, stamp_hours: int = 0) -> bytes:
    head = struct.pack("<HH", len(data), rtype) + bytes([5, 0]) + struct.pack("<H", 0) + struct.pack("<I", 0) \
        + struct.pack(">I", ttl) + struct.pack("<I", 0) + struct.pack("<I", stamp_hours)
    return head + data


def test_dns_record_parsing():
    a = ad_dns.parse_dns_record(_blob(1, bytes([10, 0, 0, 5])))
    assert a.type == "A" and a.value == "10.0.0.5" and a.static
    aaaa = ad_dns.parse_dns_record(_blob(28, bytes(range(16))))
    assert aaaa.type == "AAAA" and aaaa.value == "1:203:405:607:809:a0b:c0d:e0f"
    cname = ad_dns.parse_dns_record(_blob(5, _name("www.corp.example.test")))
    assert cname.type == "CNAME" and cname.value == "www.corp.example.test"
    srv = ad_dns.parse_dns_record(_blob(33, struct.pack(">HHH", 0, 100, 389) + _name("dc1.corp.example.test")))
    assert srv.type == "SRV" and srv.value == "dc1.corp.example.test:389 (Priorität 0, Gewicht 100)"
    soa_data = struct.pack(">IIIII", 73, 900, 600, 86400, 3600) + _name("dc1.corp.example.test") \
        + _name("hostmaster.corp.example.test")
    soa = ad_dns.parse_dns_record(_blob(6, soa_data))
    assert "primär dc1.corp.example.test" in soa.value and "Serien-Nr. 73" in soa.value


def test_dns_timestamp_dynamic():
    hours = int((datetime(2026, 1, 1, tzinfo=timezone.utc) - ad_dns.EPOCH).total_seconds() // 3600)
    rec = ad_dns.parse_dns_record(_blob(1, bytes([10, 0, 0, 9]), stamp_hours=hours))
    assert not rec.static and rec.stamp.year == 2026


def _prop(pid: int, data: bytes) -> bytes:
    """dnsProperty wie von Windows/Samba geschrieben: NameLength 1, Version 1, am Ende das 1-Byte-Feld Name."""
    return struct.pack("<IIIII", len(data), 1, 0, 1, pid) + data + b"\x00"


def test_dns_properties():
    props = ad_dns.parse_properties([_prop(0x01, struct.pack("<I", 1)), _prop(0x02, b"\x02"),  # 1 Byte!
                                     _prop(0x40, struct.pack("<I", 1))])  # DSPROPERTY_ZONE_AGING_STATE
    assert props == {"zone_type": "primär", "allow_update": "nur sicher", "aging": True}


def test_dns_properties_defaults_and_garbage():
    # DataLength 0 -> Vorgabewerte laut MS-DNSP (primär, Alterung aus); für ALLOW_UPDATE gibt es keine Vorgabe
    assert ad_dns.parse_properties([_prop(0x01, b""), _prop(0x40, b""), _prop(0x02, b"")]) == {
        "zone_type": "primär", "aging": False}
    # abgeschnittene Daten und Eigenschaften, die keine Zahl sind (Serverlisten), werden übergangen
    cut = struct.pack("<IIIII", 4, 1, 0, 1, 0x01) + b"\x01"
    servers = _prop(0x11, struct.pack("<I", 2) + bytes([10, 0, 0, 1, 10, 0, 0, 2]))
    assert ad_dns.parse_properties([cut, servers, b"\x00" * 7]) == {}
    # 0x05 ist keine Eigenschaft (früher fälschlich als Alterung gelesen)
    assert ad_dns.parse_properties([_prop(0x05, struct.pack("<I", 1))]) == {}


# --- AD CS: Prüfung über LDAP ---------------------------------------------------------------------

def _template(cn, *, enroll_sid="S-1-5-21-1-2-3-513", ekus=("1.3.6.1.5.5.7.3.2",), name_flag=1, enroll_flag=0,
              ra_sig=0, schema=2, write_sid=None, policy=None):
    aces = [Ace(ALLOWED, CONTAINER_INHERIT, FULL_CONTROL, f"{DOM}-512")]
    if enroll_sid:  # Registrierungsrecht über das erweiterte Recht "Enroll"
        aces.append(Ace(ALLOWED_OBJECT, 0, CONTROL_ACCESS, enroll_sid, "0e10c968-78fb-11d2-90d4-00c04f79dc55"))
    if write_sid:
        aces.append(Ace(ALLOWED, 0, WRITE_PROP, write_sid))
    values = {"cn": cn, "displayName": cn, "msPKI-Certificate-Name-Flag": name_flag,
              "msPKI-Enrollment-Flag": enroll_flag, "msPKI-RA-Signature": ra_sig, "pKIExtendedKeyUsage": list(ekus),
              "msPKI-Template-Schema-Version": schema, "nTSecurityDescriptor": sd_bytes(aces, owner=f"{DOM}-512")}
    if policy:
        values["msPKI-Certificate-Policy"] = policy
    return Entry.make(f"CN={cn},CN=Certificate Templates,CN=Public Key Services,CN=Services,{CFG_NC}", values)


class AdcsAd(FakeAd):
    def __init__(self, templates, published):
        super().__init__()
        self._tmpl = templates
        ca = Entry.make(f"CN=corp-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,{CFG_NC}", {
            "cn": "corp-CA", "dNSHostName": "ca1.corp.example.test", "certificateTemplates": published,
            "nTSecurityDescriptor": sd_bytes([Ace(ALLOWED, 0, FULL_CONTROL, f"{DOM}-512")], owner=f"{DOM}-512")})
        self._cas = [ca]

    def cert_templates(self):
        return self._tmpl

    def enrollment_services(self):
        return self._cas

    def nt_auth_certificates(self):
        return None

    def pki_oids(self):
        return []


def _adcs_ctx(ctx, templates, published):
    ctx.cfg.ad.enabled = True
    ctx.cfg.ad.domain = "corp.example.test"
    ctx.__dict__["ad"] = AdcsAd(templates, published)
    return ctx


def _findings(ctx, templates, published):
    from doku_agent.generators import adcs_docs
    from doku_agent.generators.ad_common import AdNames, fetch
    _adcs_ctx(ctx, templates, published)
    data, errors = fetch(ctx, {"base", "adcs", "acl"})
    assert errors == {}
    return {f"{r[0]}:{r[1]}": r[2] for r in adcs_docs.audit(ctx, data, AdNames(ctx, data))}


def test_adcs_esc1_detected(ctx):
    t = _template("UserAuth", name_flag=1)  # Enrollee supplies subject + client auth + no approval, Domain Users
    found = _findings(ctx, [t], ["UserAuth"])
    assert "ESC1:UserAuth" in found and "frei wählen" in found["ESC1:UserAuth"]


def test_adcs_approval_and_unpublished_are_safe(ctx):
    approved = _template("Approved", enroll_flag=0x2)  # Genehmigung nötig
    unpublished = _template("Hidden")  # nicht veröffentlicht
    found = _findings(ctx, [approved, unpublished], ["Approved"])  # nur Approved veröffentlicht
    assert not any(k.startswith("ESC1") for k in found)


def test_adcs_esc2_any_purpose_and_esc4_write(ctx):
    # ESC2 braucht keinen frei wählbaren Namen (name_flag=0); "keine Einschränkung" zählt wie "beliebiger Zweck"
    anyp = _template("AnyPurpose", ekus=("2.5.29.37.0",), name_flag=0)
    noeku = _template("NoEku", ekus=(), name_flag=0)
    writable = _template("Writable", enroll_sid=None, write_sid="S-1-5-11")
    found = _findings(ctx, [anyp, noeku, writable], ["AnyPurpose", "NoEku", "Writable"])
    assert "ESC2:AnyPurpose" in found and "ESC2:NoEku" in found
    assert "ESC1:AnyPurpose" not in found and "ESC1:NoEku" not in found
    assert "ESC4:Writable" in found and "Authentifizierte Benutzer" in found["ESC4:Writable"]


def test_adcs_any_purpose_with_free_name_is_esc1_and_esc2(ctx):
    from doku_agent.generators import adcs_docs
    from doku_agent.generators.ad_common import AdNames, fetch
    _adcs_ctx(ctx, [_template("Both", ekus=("2.5.29.37.0",), name_flag=1)], ["Both"])
    data, _ = fetch(ctx, {"base", "adcs", "acl"})
    rows = adcs_docs.audit(ctx, data, AdNames(ctx, data))
    assert sorted(r[0] for r in rows if r[1] == "Both") == ["ESC1", "ESC2"]  # je einmal, nicht zweimal ESC2


def test_adcs_esc9_no_security_extension(ctx):
    t = _template("NoSid", enroll_flag=0x00080000)
    found = _findings(ctx, [t], ["NoSid"])
    assert "ESC9:NoSid" in found


# --- Wirksame GPOs (RSoP-Näherung) ----------------------------------------------------------------

def _effective_order(ctx, links_by_dn, blocked=(), site_gplink=""):
    """Baut eine minimale AD-Struktur und gibt die Reihenfolge der wirksamen GPO-Namen zurück."""
    from doku_agent import ad_effective
    comp = Entry.make(f"CN=PC1,OU=Clients,OU=Firma,{BASE}",
                      {"objectClass": ["computer"], "sAMAccountName": "PC1$", "objectSid": sid_to_bytes(f"{DOM}-1150"),
                       "userAccountControl": 4096})

    class St:
        def __init__(self):
            from doku_agent.generators.ad_common import AdData
            self.data = AdData()
            self.data.root = {"defaultnamingcontext": BASE, "rootdomainnamingcontext": BASE}
            self.data.domain = Entry.make(BASE, {"objectSid": sid_to_bytes(DOM), "gPLink": links_by_dn.get(BASE, ""),
                                                 "gPOptions": 0})
            self.data.crossref = Entry.make("x", {"dnsRoot": "corp.example.test"})
            self.data.ous = [Entry.make(dn, {"name": dn.split(",")[0][3:], "gPLink": gp,
                                             "gPOptions": 1 if dn in blocked else 0})
                             for dn, gp in links_by_dn.items() if dn.startswith("OU=")]
            self.data.sites = [Entry.make(f"CN=Wien,CN=Sites,{CFG_NC}", {"name": "Wien", "gPLink": site_gplink})]
            self.gpos = {g.str("cn").upper(): g for g in ctx.ad.gpos()}
            self.by_dn = {e.dn.lower(): e for e in [self.data.domain, *self.data.ous]}
            self.primary_groups: dict[str, set[str]] = {}

        def via_primary(self, sid):
            return self.primary_groups.get(sid, set())

        def computer(self, name):
            return comp

        def site_for(self, ips):
            return self.data.sites[0] if site_gplink else None

        def loopback(self, guid):
            return 0
    ctx.__dict__["_ad_structure"] = St()
    eff = ad_effective.effective(ctx, comp, ["10.1.0.9"])
    return [a.name for a in eff.applied], [s[0] for s in eff.skipped]


def test_effective_gpo_precedence(ctx):
    from doku_agent.generators import gpo_docs
    ctx.cfg.ad.enabled = True
    ad = FakeAd()
    ctx.__dict__["ad"] = ad
    ad.groups_of = lambda dn: [ad.gg]  # Mitglied von GG-Clients (GPO_B gilt)
    # Default Domain Policy an der Domäne (GPO_A), Clients-GPO (GPO_B) an der OU Clients
    def gplink(*entries):
        return "".join(f"[LDAP://cn={g},cn=policies,cn=system,{BASE};{o}]" for g, o in entries)
    links = {BASE: gplink((GPO_A, 0)), f"OU=Firma,{BASE}": "",
             f"OU=Clients,OU=Firma,{BASE}": gplink((GPO_B, 0))}
    applied, skipped = _effective_order(ctx, links)
    # OU gewinnt gegenüber Domäne → Clients-GPO zuerst (höchste Priorität)
    assert applied[0] == "Clients - Sicherheit" and "Default Domain Policy" in applied
    assert gpo_docs  # importierbar


def test_effective_blocked_inheritance_and_enforced(ctx):
    ctx.cfg.ad.enabled = True
    ad = FakeAd()
    ctx.__dict__["ad"] = ad
    ad.groups_of = lambda dn: [ad.gg]

    def gplink(*entries):
        return "".join(f"[LDAP://cn={g},cn=policies,cn=system,{BASE};{o}]" for g, o in entries)
    # Domäne erzwingt GPO_A (option 2); OU Clients blockiert Vererbung → erzwungene bleibt trotzdem
    links = {BASE: gplink((GPO_A, 2)), f"OU=Firma,{BASE}": "", f"OU=Clients,OU=Firma,{BASE}": gplink((GPO_B, 0))}
    applied, _ = _effective_order(ctx, links, blocked={f"OU=Clients,OU=Firma,{BASE}"})
    assert "Default Domain Policy" in applied  # erzwungen überlebt die Blockade
    # erzwungene GPO gewinnt (steht in der Prioritätsreihenfolge vorne)
    assert applied[0] == "Default Domain Policy"


# --- Änderungsbericht ----------------------------------------------------------------------------

def _page(block_id, rows):
    from doku_agent import markdown
    begin, end = markdown.block_markers(block_id)
    table = markdown.table(["A", "B"], rows)
    return f"## X\n\n{begin}\n{table}\n{end}\n"


def test_change_log_records_added_and_removed(ctx):
    ctx.cfg.changes.enabled = True
    sid = "ad:gpo:{G}"
    changes.record(ctx, sid, "GPO X", _page("ad-gpo-list", [["a", "1"], ["b", "2"]]), ["ad-gpo-list"])
    # erster Lauf = nur Baseline, keine Ereignisse
    assert not (ctx.store.kv_get(changes.LOG_KEY) or [])
    changes.record(ctx, sid, "GPO X", _page("ad-gpo-list", [["a", "1"], ["c", "3"]]), ["ad-gpo-list"])
    log = ctx.store.kv_get(changes.LOG_KEY)
    kinds = sorted((e["kind"], e["detail"]) for e in log)
    assert ("Eintrag entfällt", "b | 2") in kinds and ("neuer Eintrag", "c | 3") in kinds  # ohne Pipes


def test_change_log_findings_wording(ctx):
    ctx.cfg.changes.enabled = True
    sid = "ad:pruefung"
    changes.record(ctx, sid, "Prüfung", _page("ad-audit-findings", [["x", "1"]]), ["ad-audit-findings"])
    changes.record(ctx, sid, "Prüfung", _page("ad-audit-findings", [["x", "1"], ["y", "2"]]), ["ad-audit-findings"])
    changes.record(ctx, sid, "Prüfung", _page("ad-audit-findings", [["y", "2"]]), ["ad-audit-findings"])
    kinds = [e["kind"] for e in ctx.store.kv_get(changes.LOG_KEY)]
    assert "neuer Befund" in kinds and "behobener Befund" in kinds


def test_change_prose_blocks_are_ignored(ctx):
    ctx.cfg.changes.enabled = True
    sid = "entra:rollen"
    changes.record(ctx, sid, "Rollen", _page("entra-roles-summary", [["text", "a"]]), ["entra-roles-summary"])
    changes.record(ctx, sid, "Rollen", _page("entra-roles-summary", [["text", "b"]]), ["entra-roles-summary"])
    assert not (ctx.store.kv_get(changes.LOG_KEY) or [])  # Fließtext zählt nicht


def test_change_log_keeps_sections_not_in_draft(ctx):
    """Fehlt ein Abschnitt im Entwurf (Firewall/AD gerade nicht lesbar – der Abschnitt bleibt im Wiki stehen),
    entfällt nichts; kommt er zurück, ist auch nichts neu."""
    ctx.cfg.changes.enabled = True
    sid = "netbox:device:7"
    both = _page("netbox-device", [["Name", "srv1"]]) + _page("netbox-firewall", [["fw1", "Regel 5"]])
    changes.record(ctx, sid, "srv1", both, ["netbox-device", "netbox-firewall"])
    changes.record(ctx, sid, "srv1", both, ["netbox-device"])  # Firewall diesmal nicht lesbar
    changes.record(ctx, sid, "srv1", both, ["netbox-device", "netbox-firewall"])
    assert not (ctx.store.kv_get(changes.LOG_KEY) or [])
    # ist der Abschnitt im Entwurf, wird er wie bisher verglichen
    changes.record(ctx, sid, "srv1", _page("netbox-device", [["Name", "srv1"]]) + _page("netbox-firewall", []),
                   ["netbox-device", "netbox-firewall"])
    assert [(e["kind"], e["detail"]) for e in ctx.store.kv_get(changes.LOG_KEY)] == [("Eintrag entfällt", "fw1 | Regel 5")]


def test_change_log_reports_new_pages(ctx):
    """Neue Seiten einer schon erfassten Seitenart melden; eine Seitenart, die heute zum ersten Mal erfasst wird,
    nur als Ausgangsstand merken (kein Schwall, wenn eine Quelle später eingeschaltet wird)."""
    from datetime import timedelta
    ctx.cfg.changes.enabled = True
    yesterday = (date.today() - timedelta(days=1)).isoformat()
    ctx.store.kv_set(changes.KINDS_KEY, {"ad:gpo": yesterday})
    changes.record(ctx, "ad:gpo:{NEU}", "GPO Neu", _page("ad-gpo-basics", [["Name", "Neu"]]), ["ad-gpo-basics"])
    changes.record(ctx, "addns:zone:corp", "DNS-Zone corp", _page("dns-records", [["a", "A"]]), ["dns-records"])
    log = ctx.store.kv_get(changes.LOG_KEY)
    assert [(e["kind"], e["title"]) for e in log] == [("neue Seite", "GPO Neu")]
    assert ctx.store.kv_get(changes.KINDS_KEY)["addns:zone"] == date.today().isoformat()
    # Seite ohne Tabellenzeilen bekommt Zeilen: neue Einträge, aber keine "neue Seite"
    changes.record(ctx, "addns:zone:leer", "DNS-Zone leer", _page("dns-records", []), ["dns-records"])
    changes.record(ctx, "addns:zone:leer", "DNS-Zone leer", _page("dns-records", [["x", "A"]]), ["dns-records"])
    assert [e["kind"] for e in ctx.store.kv_get(changes.LOG_KEY)][1:] == ["neuer Eintrag"]


def test_weekly_report(ctx):
    ctx.cfg.changes.enabled = True
    today = date.today().isoformat()
    ctx.store.kv_set(changes.LOG_KEY, [
        {"at": today, "area": "Firewall", "title": "fw1", "block": "b", "kind": "neuer Eintrag", "detail": "Regel X"},
        {"at": today, "area": "Active Directory", "title": "Prüfung", "block": "a", "kind": "neuer Befund",
         "detail": "krbtgt alt"}])
    pid = changes.document_week(ctx, date.today())
    assert pid
    content = next(p.payload["content"] for p in ctx.store.list_proposals() if p.id == pid)
    assert "Regel X" in content and "krbtgt alt" in content and "Firewall" in content


def test_ref_from_slug_roundtrip():
    ref = date(2026, 10, 20)
    _, _, slug = changes.week_bounds(ref)
    back = changes.ref_from_slug(slug)
    assert changes.week_bounds(back)[2] == slug


# --- AD im Abdeckungsbericht ----------------------------------------------------------------------

class CovNetbox:
    def __init__(self, objects):
        self.objects = objects


def test_coverage_ad_sections(ctx):
    from doku_agent.coverage import ad_report
    from doku_agent.discovery import NetboxIndex
    ctx.cfg.ad.enabled = True
    ad = FakeAd()
    ctx.__dict__["ad"] = ad
    index = NetboxIndex.__new__(NetboxIndex)
    index.objects = {
        ("dcim/devices", 1): {"id": 1, "name": "srv01", "platform": {"name": "Windows Server 2019",
                                                                     "slug": "windows-server-2019"}},
        ("dcim/devices", 2): {"id": 2, "name": "nas01", "platform": {"name": "Linux", "slug": "linux"}},
        ("virtualization/virtual-machines", 3): {"id": 3, "name": "pc-ghost",
                                                  "platform": {"name": "Windows 11", "slug": "windows-11"}},
    }
    report = ad_report(ctx, index)
    no_ad = {r[0] for r in report["no_ad"]}
    assert "pc-ghost" in no_ad and "nas01" not in no_ad  # nur Windows ohne AD-Konto
    ad_only = {r[0] for r in report["ad_only"]}
    assert "pc-old" in ad_only or "srv01" not in ad_only  # srv01 matcht, pc-old nur im AD


# --- DNS-Netbox-Abgleich --------------------------------------------------------------------------

class DnsNetbox:
    def __init__(self, by_addr):
        self.by_addr = by_addr
        self.calls = []

    def list(self, endpoint, **kw):
        self.calls.append(kw)
        wanted = kw.get("address")
        return [m for a in (wanted if isinstance(wanted, list) else [wanted]) for m in self.by_addr.get(a, [])]


def test_dns_netbox_mismatch(ctx):
    from doku_agent.generators import dns_docs
    from doku_agent.generators.ad_common import AdData
    ctx.cfg.ad.enabled = True
    ctx.cfg.netbox.enabled = True
    ctx.__dict__["netbox"] = DnsNetbox({
        "10.0.0.5": [{"id": 7, "address": "10.0.0.5/24", "dns_name": "alt.corp.example.test"}],
        "10.0.0.6": [{"id": 8, "address": "10.0.0.6/24", "dns_name": "srv.corp.example.test"}]})
    data = AdData()
    data.root = {"defaultnamingcontext": BASE}
    data.crossref = Entry.make("x", {"dnsRoot": "corp.example.test"})
    zone = Entry.make(f"DC=corp.example.test,CN=MicrosoftDNS,DC=DomainDnsZones,{BASE}", {"name": "corp.example.test"})
    data.dns_zones = [zone]
    srv = Entry.make(f"DC=srv,{zone.dn}", {"name": "srv", "dnsRecord": [_blob(1, bytes([10, 0, 0, 6]))]})
    web = Entry.make(f"DC=web,{zone.dn}", {"name": "web", "dnsRecord": [_blob(1, bytes([10, 0, 0, 5]))]})
    data.dns_records = {"corp.example.test": [srv, web]}
    mism = dns_docs.netbox_mismatches(ctx, data)
    by_ip = {m["ip"]: m for m in mism}
    assert by_ip["10.0.0.5"]["state"] == "abweichend" and by_ip["10.0.0.5"]["fqdn"] == "web.corp.example.test"
    assert "10.0.0.6" not in by_ip  # srv stimmt bereits überein


def _dns_data(zones, props=None):
    """AdData mit {zone: {knoten: [dnsRecord-Werte]}}; props: dnsProperty-Werte je Zone."""
    from doku_agent.generators.ad_common import AdData
    data = AdData()
    data.root = {"defaultnamingcontext": BASE}
    data.crossref = Entry.make("x", {"dnsRoot": "corp.example.test"})
    for zname, nodes in zones.items():
        zone = Entry.make(f"DC={zname},CN=MicrosoftDNS,DC=DomainDnsZones,{BASE}",
                          {"name": zname, "dnsProperty": (props or {}).get(zname, [])})
        data.dns_zones.append(zone)
        data.dns_records[zname] = [Entry.make(f"DC={n},{zone.dn}", {"name": n, "dnsRecord": recs})
                                   for n, recs in nodes.items()]
    return data


def _a(*octets, stamp_hours=0):
    return _blob(1, bytes(octets), stamp_hours=stamp_hours)


def test_dns_netbox_groups_names_per_ip(ctx):
    """Eine IP hat in Netbox nur einen DNS-Namen: mehrere AD-Namen je IP nicht als widersprüchliche Änderungen
    vorschlagen; DC-Aliasse, _msdcs, Stammhinweise und Dienstnamen gar nicht erst vergleichen."""
    from doku_agent.generators import dns_docs
    ctx.cfg.ad.enabled = ctx.cfg.netbox.enabled = True
    nb = DnsNetbox({
        "10.0.0.1": [{"id": 1, "address": "10.0.0.1/24", "dns_name": ""}],  # DC
        "10.0.0.5": [{"id": 5, "address": "10.0.0.5/24", "dns_name": "WWW.corp.example.test."}],
        "10.0.0.7": [{"id": 70, "address": "10.0.0.7/24", "dns_name": ""},  # zwei VRFs
                     {"id": 71, "address": "10.0.0.7/24", "dns_name": ""}],
        "10.0.0.8": [{"id": 8, "address": "10.0.0.8/24", "dns_name": ""}]})
    ctx.__dict__["netbox"] = nb
    data = _dns_data({
        "corp.example.test": {"@": [_a(10, 0, 0, 1)], "DomainDnsZones": [_a(10, 0, 0, 1)],
                              "ForestDnsZones": [_a(10, 0, 0, 1)], "dc1": [_a(10, 0, 0, 1)],
                              "web": [_a(10, 0, 0, 5)], "www": [_a(10, 0, 0, 5)],  # zweiter Name, eingetragen
                              "app": [_a(10, 0, 0, 7)],
                              "a1": [_a(10, 0, 0, 8)], "a2": [_a(10, 0, 0, 8)],  # zwei Namen, keiner eingetragen
                              "*": [_a(10, 0, 0, 9)], "_ldap._tcp": [_a(10, 0, 0, 1)],
                              "kaputt": [_blob(1, bytes([10, 0]))]},  # zu kurz: keine IP, kein Absturz
        "_msdcs.corp.example.test": {"gc": [_a(10, 0, 0, 1)]},
        "RootDNSServers": {"a.root-servers.net": [_a(198, 41, 0, 4)]}})
    mism = dns_docs.netbox_mismatches(ctx, data)
    rows = {(m["ip"], m["netbox_id"]): m for m in mism}
    assert rows[("10.0.0.1", 1)]["fqdn"] == "dc1.corp.example.test" and rows[("10.0.0.1", 1)]["state"] == "leer"
    assert ("10.0.0.5", 5) not in rows  # www ist (groß/klein, Punkt am Ende egal) schon eingetragen
    assert rows[("10.0.0.8", 8)]["state"] == "mehrdeutig" and rows[("10.0.0.8", 8)]["fqdn"] == ""
    assert {k for k in rows if k[0] == "10.0.0.7"} == {("10.0.0.7", 70), ("10.0.0.7", 71)}
    assert not any(m["ip"] in ("10.0.0.9", "198.41.0.4") for m in mism)  # Platzhalter, Root-Server
    assert len(nb.calls) == 1 and sorted(nb.calls[0]["address"]) == ["10.0.0.1", "10.0.0.5", "10.0.0.7", "10.0.0.8"]

    dns_docs._sync_proposal(ctx, [m for m in mism if m["netbox_id"]])
    prop = ctx.store.list_proposals(status="pending")[0]
    changes = prop.payload["changes"]
    keys = [c["key"] for c in changes]
    assert len(keys) == len(set(keys)) == 3  # dc1 + app in zwei VRFs, nichts für die mehrdeutige IP
    assert {c["after"] for c in changes} == {"dc1.corp.example.test", "app.corp.example.test"}
    assert "a1.corp" not in prop.summary


def test_dns_zone_page_stand_is_stable(ctx):
    """Aktuelle dynamische Einträge ohne Datum (sonst bei jeder Auffrischung ein neuer Vorschlag); veraltet nur mit
    Alterung – ohne Alterung frischt der DNS-Server die Zeitstempel nicht auf."""
    from datetime import timedelta
    from doku_agent.generators import dns_docs
    def hours(days_ago):
        when = datetime.now(timezone.utc) - timedelta(days=days_ago)
        return int((when - ad_dns.EPOCH).total_seconds() // 3600)
    aging_on = [_prop(0x40, struct.pack("<I", 1))]
    nodes = {"fresh": [_a(10, 0, 0, 2, stamp_hours=hours(1))], "old": [_a(10, 0, 0, 3, stamp_hours=hours(400))],
             "static": [_a(10, 0, 0, 4)]}
    for zname, props, expect_old in (("on.example.test", aging_on, "veraltet (letzte Aktualisierung "),
                                     ("off.example.test", [], "dynamisch")):
        data = _dns_data({zname: nodes}, {zname: props})
        dns_docs.zone_page(ctx, data, data.dns_zones[0])
        prop = [p for p in ctx.store.list_proposals(status="pending") if zname in p.title][0]
        content = prop.payload["content"]
        assert f"| fresh.{zname} | A | 10.0.0.2 | dynamisch |" in content
        assert f"| old.{zname} | A | 10.0.0.3 | {expect_old}" in content
        assert f"| static.{zname} | A | 10.0.0.4 | statisch |" in content
        assert ("nicht bewertbar" in content) == (not props)
        assert str(datetime.now(timezone.utc).year) not in content.split("fresh.")[1].split("\n")[0]
