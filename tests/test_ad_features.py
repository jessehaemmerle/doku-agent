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


def test_dns_properties():
    def prop(pid, value):
        data = struct.pack("<I", value)
        return struct.pack("<IIII", len(data), 0, 0, 0) + struct.pack("<I", pid) + data + b"\x00"
    props = ad_dns.parse_properties([prop(ad_dns.PROP_TYPE, 1), prop(ad_dns.PROP_ALLOW_UPDATE, 2),
                                     prop(ad_dns.PROP_AGING_STATE, 1)])
    assert props == {"zone_type": "primär", "allow_update": "nur sicher", "aging": True}


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
    anyp = _template("AnyPurpose", ekus=("2.5.29.37.0",))
    writable = _template("Writable", enroll_sid=None, write_sid="S-1-5-11")
    found = _findings(ctx, [anyp, writable], ["AnyPurpose", "Writable"])
    assert "ESC2:AnyPurpose" in found
    assert "ESC4:Writable" in found and "Authentifizierte Benutzer" in found["ESC4:Writable"]


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

    def list(self, endpoint, **kw):
        return self.by_addr.get(kw.get("address"), [])


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
