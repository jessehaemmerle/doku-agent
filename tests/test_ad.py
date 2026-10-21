"""Active Directory: Parser (SYSVOL, Sicherheitsbeschreibungen, LDAP-Werte), Seiten und Prüfung mit Fakes."""

from __future__ import annotations

import re
import struct
from datetime import datetime, timedelta, timezone

import pytest

from doku_agent import gpo_files
from doku_agent.ad_acl import (ALLOWED, ALLOWED_OBJECT, APPLY_GROUP_POLICY, CONTAINER_INHERIT, CONTROL_ACCESS,
                               DELETE, DELETE_TREE, DENIED, FULL_CONTROL, GET_CHANGES, GET_CHANGES_ALL, INHERIT_ONLY,
                               READ_PROP, RESET_PASSWORD, SELF, WRITE_DAC, WRITE_PROP, Ace, GuidNames, parse_sd,
                               protected_from_deletion, rights_text, scope_text, sd_bytes, sid_to_bytes, sid_to_str)
from doku_agent.connectors.ad import (AdClient, AdError, Entry, bind_message, escape_value, filetime, interval_seconds,
                                      rdn)
from doku_agent.connectors.sysvol import SysvolError, _clean
from doku_agent.egress import EgressGuard, allowed_hosts
from doku_agent.gpo_files import RegEntry, registry_pol_bytes
from tests.conftest import make_config

DOM = "S-1-5-21-1-2-3"
BASE = "DC=corp,DC=example,DC=test"
CFG_NC = f"CN=Configuration,{BASE}"
USER_CLASS = "bf967aba-0de6-11d0-a285-00aa003049e2"
GROUP_CLASS = "bf967a9c-0de6-11d0-a285-00aa003049e2"
MEMBER = "bf9679c0-0de6-11d0-a285-00aa003049e2"
GPO_A = "{AAAAAAAA-0000-0000-0000-000000000001}"
GPO_B = "{BBBBBBBB-0000-0000-0000-000000000002}"
GPO_C = "{CCCCCCCC-0000-0000-0000-000000000003}"
GPO_GONE = "{DDDDDDDD-0000-0000-0000-000000000004}"
NS = 'xmlns="http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions"'


def ft(dt: datetime) -> int:
    return int((dt - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds() * 10_000_000)


NOW = datetime.now(timezone.utc)
RECENT, OLD = ft(NOW - timedelta(days=3)), ft(NOW - timedelta(days=400))


def u16(text: str) -> bytes:
    return b"\xff\xfe" + text.replace("\n", "\r\n").encode("utf-16-le")


# --- Parser ---------------------------------------------------------------------------------------

def test_registry_pol_roundtrip_and_special_values():
    entries = [RegEntry(r"Software\A", "Dword", 4, 7), RegEntry(r"Software\A", "Text", 1, "äbc"),
               RegEntry(r"Software\A", "Multi", 7, ["x", "y"]), RegEntry(r"Software\B", "**del.Old", 1, " "),
               RegEntry(r"Software\B", "**DelVals.", 1, " "), RegEntry(r"Software\B", "Q", 11, 2 ** 40)]
    parsed = gpo_files.parse_registry_pol(registry_pol_bytes(entries))
    assert [(e.key, e.value, e.data) for e in parsed] == [(e.key, e.value, e.data) for e in entries]
    assert gpo_files.special_value("**Del.Old") == ("del", "Old")
    assert gpo_files.special_value("**DelVals") == ("delvals", "")  # Learn schreibt es ohne Punkt
    with pytest.raises(gpo_files.GpoFileError):
        gpo_files.parse_registry_pol(b"XXXX" + struct.pack("<I", 1))
    with pytest.raises(gpo_files.GpoFileError):  # abgeschnitten
        gpo_files.parse_registry_pol(registry_pol_bytes(entries)[:-3])


def test_gpttmpl_sections():
    t = gpo_files.parse_gpttmpl(u16("""[Unicode]
Unicode=yes
[System Access]
MinimumPasswordLength = 14
MaximumPasswordAge = -1
NewGuestName = "Besucher"
[Kerberos Policy]
MaxTicketAge = 10
[Privilege Rights]
SeDebugPrivilege = *S-1-5-32-544
SeDenyNetworkLogonRight = *S-1-5-32-546, Gast
[Registry Values]
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel=4,5
[Group Membership]
*S-1-5-32-544__Memberof =
*S-1-5-32-544__Members = *S-1-5-21-1-2-3-1108
[Service General Setting]
"Spooler",4,""
[Registry Keys]
"MACHINE\\SOFTWARE\\Firma",0,"D:PAR(A;CI;KA;;;BA)"
"""))
    assert t.system_access["MinimumPasswordLength"] == "14"
    assert t.privileges["SeDenyNetworkLogonRight"] == ["S-1-5-32-546", "Gast"]
    assert t.registry_values == [(r"MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel", "4", "5")]
    assert ("S-1-5-32-544", "members", ["S-1-5-21-1-2-3-1108"]) in t.group_membership
    assert ("S-1-5-32-544", "memberof", []) in t.group_membership
    assert t.services == [("Spooler", "4")]
    assert t.registry_keys == [r"MACHINE\SOFTWARE\Firma"]


def test_audit_csv_scripts_and_gpt_ini():
    audit = gpo_files.parse_audit_csv(
        "\ufeffMachine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,"
        "Setting Value\r\n,System,Anmelden,{0cce9215-69ae-11d9-bed3-505054503030},Success and Failure,,3\r\n".encode())
    assert audit[0].subcategory == "Anmelden" and audit[0].value == 3
    scripts = gpo_files.parse_scripts_ini(u16("[Logon]\n0CmdLine=a.cmd\n0Parameters=/x\n1CmdLine=b.ps1\n"
                                              "[ScriptConfig]\nStartExecutePSFirst=true\n"), powershell=True)
    assert [(s.kind, s.command, s.parameters) for s in scripts] == [("Logon", "a.cmd", "/x"), ("Logon", "b.ps1", "")]
    assert gpo_files.parse_gpt_ini(b"[General]\r\nVersion=196611\r\ndisplayName=Neues GPO\r\n") == 196611


def test_preferences_never_expose_cpassword():
    xml = b"""<?xml version="1.0" encoding="utf-8"?><Groups clsid="{x}">
<User clsid="{u}" name="LokalAdmin" uid="{1}"><Properties action="U" userName="LokalAdmin" cpassword="GEHEIM123"
 neverExpires="1"/></User>
<Group clsid="{g}" name="Administratoren" uid="{2}"><Properties action="R" groupName="Administratoren">
<Members><Member name="CORP\\Helpdesk" action="ADD" sid="S-1-5-21-1-2-3-1108"/></Members></Properties>
<Filters><FilterGroup bool="AND" not="1" name="CORP\\Server"/></Filters></Group></Groups>"""
    items = gpo_files.parse_preferences(xml)
    assert items[0].has_cpassword and "GEHEIM123" not in repr(items)
    assert items[1].action == "Ersetzen" and items[1].members == [("Hinzufügen", "CORP\\Helpdesk", "S-1-5-21-1-2-3-1108")]
    assert items[1].filters == ["nicht Group: CORP\\Server"]
    task = gpo_files.parse_preferences(b"""<ScheduledTasks><TaskV2 name="Inventar"><Properties action="C"
 runAs="NT AUTHORITY\\System"><Task><Actions><Exec><Command>c:\\inv.exe</Command><Arguments>/q</Arguments></Exec>
</Actions></Task></Properties></TaskV2></ScheduledTasks>""")
    assert ("Befehl", "c:\\inv.exe /q") in task[0].details and task[0].action == "Erstellen"


def test_firewall_rule():
    rule = gpo_files.parse_firewall_rule("v2.30|Action=Allow|Dir=In|Protocol=6|LPort=443|Profile=Domain|"
                                         "Profile=Private|Name=Web|")
    assert rule["Action"] == ["Allow"] and rule["Profile"] == ["Domain", "Private"]


ADMX_BASE = f"""<policyDefinitions {NS}><policyNamespaces><target prefix="base" namespace="Doku.Base"/>
</policyNamespaces><categories><category name="WC" displayName="$(string.WC)"/></categories></policyDefinitions>"""
ADMX_TEST = f"""<policyDefinitions {NS}><policyNamespaces><target prefix="t" namespace="Doku.Test"/>
<using prefix="base" namespace="Doku.Base"/></policyNamespaces>
<categories><category name="WU" displayName="$(string.WU)"><parentCategory ref="base:WC"/></category></categories>
<policies>
<policy name="AU" class="Machine" displayName="$(string.AU)" presentation="$(presentation.AU)"
 key="Software\\Policies\\WU\\AU" valueName="NoAutoUpdate"><parentCategory ref="WU"/>
<enabledValue><decimal value="0"/></enabledValue><disabledValue><decimal value="1"/></disabledValue>
<elements><enum id="Mode" valueName="AUOptions"><item displayName="$(string.M4)"><value><decimal value="4"/></value>
</item></enum></elements></policy>
<policy name="Cam" class="Machine" displayName="$(string.Cam)" key="Software\\Policies\\P" valueName="NoCam">
<parentCategory ref="WU"/></policy>
<policy name="VBS" class="Machine" displayName="$(string.VBS)" presentation="$(presentation.VBS)"
 key="Software\\Policies\\DG"><parentCategory ref="base:WC"/><elements><boolean id="On" valueName="Enable"/>
</elements></policy>
<policy name="Apps" class="Both" displayName="$(string.Apps)" presentation="$(presentation.Apps)"
 key="Software\\Policies\\Apps"><parentCategory ref="WU"/><elements><list id="L" key="Software\\Policies\\Apps\\List"/>
</elements></policy>
</policies></policyDefinitions>"""
ADML_TEST = f"""<policyDefinitionResources {NS}><resources><stringTable><string id="WU">Windows Update</string>
<string id="AU">Automatische Updates</string><string id="M4">4 - automatisch</string><string id="Cam">Kamera aus</string>
<string id="VBS">VBS</string><string id="Apps">Erlaubte Apps</string></stringTable>
<presentationTable><presentation id="AU"><dropdownList refId="Mode">Modus:</dropdownList></presentation>
<presentation id="Apps"><listBox refId="L">Apps</listBox></presentation></presentationTable></resources>
</policyDefinitionResources>"""
ADML_BASE = f"""<policyDefinitionResources {NS}><resources><stringTable><string id="WC">Windows-Komponenten</string>
</stringTable></resources></policyDefinitionResources>"""


def catalog():
    return gpo_files.AdmxCatalog().load({"t.admx": ADMX_TEST.encode(), "base.admx": ADMX_BASE.encode()},
                                        {"t.adml": ADML_TEST.encode(), "base.adml": ADML_BASE.encode()})


def test_admx_catalog_maps_registry_to_policies():
    cat = catalog()
    entries = [RegEntry(r"Software\Policies\WU\AU", "NoAutoUpdate", 4, 0),
               RegEntry(r"software\policies\wu\au", "AUOptions", 4, 4),  # Groß-/Kleinschreibung egal
               RegEntry(r"Software\Policies\P", "NoCam", 4, 1),
               RegEntry(r"Software\Policies\DG", "**del.Enable", 1, " "),
               RegEntry(r"Software\Policies\Apps\List", "**delvals.", 1, " "),
               RegEntry(r"Software\Policies\Apps\List", "notepad.exe", 1, "notepad.exe"),
               RegEntry(r"Software\Firma", "X", 1, "y")]
    settings, unknown = cat.evaluate("Machine", entries)
    by_name = {s.policy.display: s for s in settings}
    assert by_name["Automatische Updates"].state == "Aktiviert"
    assert by_name["Automatische Updates"].options == [("Modus:", "4 - automatisch")]
    assert by_name["Automatische Updates"].policy.category == "Windows-Komponenten / Windows Update"
    assert by_name["Kamera aus"].state == "Aktiviert"  # ohne enabledValue: 1 = aktiviert
    assert by_name["VBS"].state == "Deaktiviert"
    assert by_name["Erlaubte Apps"].options == [("Apps", "notepad.exe")]
    assert [(e.key, e.value) for e in unknown] == [(r"Software\Firma", "X")]
    user_settings, _ = cat.evaluate("User", entries[:2])  # Machine-Richtlinie greift nicht für User
    assert user_settings == []


# --- Sicherheitsbeschreibungen ---------------------------------------------------------------------

def test_sid_and_sd_roundtrip():
    sid = f"{DOM}-1108"
    assert sid_to_str(sid_to_bytes(sid)) == sid
    aces = [Ace(ALLOWED, CONTAINER_INHERIT, FULL_CONTROL, "S-1-5-18"),
            Ace(ALLOWED_OBJECT, CONTAINER_INHERIT | INHERIT_ONLY, CONTROL_ACCESS, sid, RESET_PASSWORD, USER_CLASS),
            Ace(DENIED, 0, DELETE | DELETE_TREE, "S-1-1-0")]
    sd = parse_sd(sd_bytes(aces, owner=f"{DOM}-512"))
    assert sd.owner == f"{DOM}-512"
    assert [(a.type, a.mask, a.sid, a.object_type, a.inherited_object_type) for a in sd.dacl] == \
        [(a.type, a.mask, a.sid, a.object_type, a.inherited_object_type) for a in aces]
    assert protected_from_deletion(sd)
    assert parse_sd(b"") is None


def test_rights_text_depends_on_access_kind():
    names = GuidNames({MEMBER: ("member", "attribute"), USER_CLASS: ("user", "class")},
                      {MEMBER: ("Self Membership", 8), RESET_PASSWORD: ("User Force Change Password", 256)})
    assert rights_text(Ace(ALLOWED_OBJECT, 0, WRITE_PROP, "S-1-1-0", MEMBER), names) == "Schreiben: member"
    assert rights_text(Ace(ALLOWED_OBJECT, 0, SELF, "S-1-1-0", MEMBER), names) == \
        "Bestätigter Schreibvorgang: sich selbst als Mitglied hinzufügen/entfernen"
    assert rights_text(Ace(ALLOWED_OBJECT, 0, CONTROL_ACCESS, "S-1-1-0", RESET_PASSWORD), names) == \
        "Kennwort zurücksetzen"
    assert rights_text(Ace(ALLOWED, 0, FULL_CONTROL, "S-1-1-0"), names) == "Vollzugriff"
    assert rights_text(Ace(ALLOWED_OBJECT, 0, 0x3, "S-1-1-0", USER_CLASS), names) == "user-Objekte erstellen und löschen"
    ace = Ace(ALLOWED_OBJECT, CONTAINER_INHERIT | INHERIT_ONLY, CONTROL_ACCESS, "S-1-1-0", RESET_PASSWORD, USER_CLASS)
    assert scope_text(ace, names) == "untergeordnete user-Objekte"


# --- LDAP-Werte und Client ---------------------------------------------------------------------------

def test_entry_values_and_helpers():
    e = Entry("CN=Max\\, Muster,OU=X," + BASE, {"pwdLastSet": [str(RECENT).encode()], "whenCreated": [b"20240102030405.0Z"],
                                                "member;range=0-1499": [b"a", b"b"], "Flag": [b"TRUE"]})
    assert e.time("pwdLastSet").date() == (NOW - timedelta(days=3)).date()
    assert e.time("whenCreated") == datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    assert e.values("member") == [b"a", b"b"] and e.bool("flag") is True
    assert rdn(e.dn) == "Max, Muster"
    assert filetime(0) is None and filetime(0x7FFFFFFFFFFFFFFF) is None
    assert interval_seconds(-36288000000000) == 42 * 86400 and interval_seconds(-0x8000000000000000) is None
    assert escape_value("a*(b)\\") == "a\\2a\\28b\\29\\5c"


def test_bind_errors_are_explained():
    msg = bind_message({"description": "invalidCredentials", "message": "80090308: LdapErr: DSID-0C09041C, comment: "
                        "AcceptSecurityContext error, data 775, v4563"})
    assert "Konto gesperrt" in msg


class FakeConn:
    """ldap3-Verbindung mit zwei Seiten (Paged Results) und einem fehlenden Container."""

    def __init__(self):
        self.calls = []

    def search(self, base, flt, search_scope, attributes, controls, paged_size, paged_cookie):
        self.calls.append((base, paged_cookie))
        if base.startswith("CN=Missing"):
            self.result, self.response = {"result": 32}, []
            return
        page = 1 if paged_cookie is None else 2
        self.response = [{"type": "searchResEntry", "dn": f"CN=e{page}", "raw_attributes": {"name": [b"x"]}},
                         {"type": "searchResRef", "uri": ["ldap://other/"]}]
        cookie = b"next" if page == 1 else b""
        self.result = {"result": 0, "controls": {"1.2.840.113556.1.4.319": {"value": {"cookie": cookie}}}}


def test_paged_search_ignores_referrals_and_missing_base(tmp_path):
    cfg = make_config(tmp_path, ad={"enabled": True, "domain": "corp.example.test", "username": "u@x"})
    client = AdClient(cfg.ad, EgressGuard.from_config(cfg))
    conn = FakeConn()
    client._conn = conn
    found = client.search("DC=x", "(objectClass=*)", ["name"])
    assert [e.dn for e in found] == ["CN=e1", "CN=e2"] and conn.calls[1] == ("DC=x", b"next")
    assert client.search("CN=Missing,DC=x", "(objectClass=*)", ["name"]) == []


def test_egress_allows_only_configured_dcs(tmp_path):
    cfg = make_config(tmp_path, ad={"enabled": True, "domain": "corp.example.test", "servers": ["DC1.corp.example.test"]})
    assert "dc1.corp.example.test" in allowed_hosts(cfg) and "corp.example.test" not in allowed_hosts(cfg)
    client = AdClient(cfg.ad, EgressGuard(set()))
    with pytest.raises(AdError, match="blockiert"):
        client._connection()
    with pytest.raises(SysvolError):
        _clean("corp\\..\\..\\secret")
    assert cfg.wiki.paths["ad_gpo"].startswith("identitaet/active-directory/")


# --- Fakes für die Generatoren --------------------------------------------------------------------------

def sd(*aces, owner=f"{DOM}-512") -> bytes:
    return sd_bytes(list(aces), owner=owner)


def gpo_sd(apply_to="S-1-5-11", read=True, editors=()):
    aces = [Ace(ALLOWED, CONTAINER_INHERIT, FULL_CONTROL, f"{DOM}-512"), Ace(ALLOWED, CONTAINER_INHERIT, FULL_CONTROL,
                                                                             "S-1-5-18"),
            Ace(ALLOWED, CONTAINER_INHERIT, READ_PROP | 0x20094, "S-1-5-9")]  # Organisations-DCs lesen jede GPO
    if read:
        aces.append(Ace(ALLOWED, CONTAINER_INHERIT, READ_PROP | 0x20094, apply_to))
    aces.append(Ace(ALLOWED_OBJECT, CONTAINER_INHERIT, CONTROL_ACCESS, apply_to, APPLY_GROUP_POLICY))
    aces += [Ace(ALLOWED, CONTAINER_INHERIT, WRITE_PROP | WRITE_DAC, s) for s in editors]
    return sd(*aces)


def link(*guids_options):
    return "".join(f"[LDAP://cn={g},cn=policies,cn=system,{BASE};{o}]" for g, o in guids_options)


class FakeAd:
    server = "dc1.corp.example.test"

    def __init__(self):
        self.base, self.config, self.schema = BASE, CFG_NC, f"CN=Schema,{CFG_NC}"
        self.closed = 0
        users = f"CN=Users,{BASE}"
        admins = f"OU=Admins,OU=Firma,{BASE}"
        self._domain = Entry.make(BASE, {
            "objectSid": sid_to_bytes(DOM), "minPwdLength": 7, "pwdHistoryLength": 24, "maxPwdAge": -36288000000000,
            "minPwdAge": -864000000000, "lockoutThreshold": 0, "pwdProperties": 1, "ms-DS-MachineAccountQuota": 10,
            "gPLink": link((GPO_A, 0)), "msDS-Behavior-Version": 7, "whenCreated": "20200101000000.0Z",
            "wellKnownObjects": [f"B:32:AA312825768811D1ADED00C04FD8D5CD:CN=Computers,{BASE}"],
            "nTSecurityDescriptor": sd(
                Ace(ALLOWED, CONTAINER_INHERIT, FULL_CONTROL, f"{DOM}-512"),
                Ace(ALLOWED_OBJECT, 0, CONTROL_ACCESS, f"{DOM}-1106", GET_CHANGES),
                Ace(ALLOWED_OBJECT, 0, CONTROL_ACCESS, f"{DOM}-1106", GET_CHANGES_ALL),
                Ace(ALLOWED_OBJECT, 0, CONTROL_ACCESS, "S-1-5-9", GET_CHANGES_ALL)),
        })
        self._ous = [
            Entry.make(f"OU=Firma,{BASE}", {"name": "Firma", "gPLink": link((GPO_B, 1)),
                                            "nTSecurityDescriptor": sd(Ace(DENIED, 0, DELETE | DELETE_TREE, "S-1-1-0"))}),
            Entry.make(f"OU=Clients,OU=Firma,{BASE}", {"name": "Clients", "gPLink": link((GPO_GONE, 0), (GPO_B, 2)),
                                                       "nTSecurityDescriptor": sd(Ace(
                                                           ALLOWED_OBJECT, CONTAINER_INHERIT | INHERIT_ONLY,
                                                           CONTROL_ACCESS, f"{DOM}-1108", RESET_PASSWORD, USER_CLASS))}),
            Entry.make(f"OU=Server,OU=Firma,{BASE}", {"name": "Server", "gPOptions": 1,
                                                      "nTSecurityDescriptor": sd(Ace(ALLOWED, CONTAINER_INHERIT,
                                                                                     WRITE_PROP, "S-1-5-11"))}),
            Entry.make(admins, {"name": "Admins"}),
        ]
        self._gpos = [
            self._gpo(GPO_A, "Default Domain Policy", 0, 0x00010001, gpo_sd()),
            self._gpo(GPO_B, "Clients - Sicherheit", 0, 0x00020003, gpo_sd(apply_to=f"{DOM}-1200", read=False,
                                                                           editors=["S-1-5-11"]),
                      wql="[corp.example.test;{11111111-1111-1111-1111-111111111111};0]",
                      user="[{5794DAFD-BE60-433F-88A2-1A31939AC01F}{2EA1A81B-48E5-45E9-8BB7-A6E3AC170006}]"),
            self._gpo(GPO_C, "Ungenutzt", 0, 0, gpo_sd(), machine=""),
        ]
        self.krbtgt = Entry.make(f"CN=krbtgt,{users}", {"objectClass": ["top", "user"], "sAMAccountName": "krbtgt",
                                                        "objectSid": sid_to_bytes(f"{DOM}-502"), "userAccountControl": 514,
                                                        "pwdLastSet": OLD, "servicePrincipalName": "kadmin/changepw"})
        self.anna = Entry.make(f"CN=Anna,{admins}", {
            "objectClass": ["top", "person", "user"], "sAMAccountName": "anna", "displayName": "Anna Admin",
            "objectSid": sid_to_bytes(f"{DOM}-1105"), "userAccountControl": 0x200 | 0x10000, "pwdLastSet": OLD,
            "lastLogonTimestamp": RECENT, "adminCount": 1, "whenCreated": "20200101000000.0Z"})
        self.svc = Entry.make(f"CN=svc-sql,{admins}", {
            "objectClass": ["top", "person", "user"], "sAMAccountName": "svc-sql", "objectSid": sid_to_bytes(f"{DOM}-1107"),
            "userAccountControl": 0x200 | 0x400000, "servicePrincipalName": "MSSQLSvc/sql01:1433", "pwdLastSet": RECENT,
            "lastLogonTimestamp": RECENT, "whenCreated": "20200101000000.0Z"})
        self.old = Entry.make(f"CN=Ex,{users}", {
            "objectClass": ["top", "person", "user"], "sAMAccountName": "ex", "objectSid": sid_to_bytes(f"{DOM}-1106"),
            "userAccountControl": 0x200 | 0x20, "adminCount": 1, "lastLogonTimestamp": OLD,
            "whenCreated": "20200101000000.0Z"})
        self._users = [self.krbtgt, self.anna, self.svc, self.old]
        self._computers = [
            Entry.make(f"CN=DC1,OU=Domain Controllers,{BASE}", {
                "objectClass": ["top", "computer"], "sAMAccountName": "DC1$", "userAccountControl": 0x2000 | 0x80000,
                "operatingSystem": "Windows Server 2022", "operatingSystemVersion": "10.0 (20348)",
                "dNSHostName": "dc1.corp.example.test", "pwdLastSet": RECENT}),
            Entry.make(f"CN=srv01,OU=Server,OU=Firma,{BASE}", {
                "objectClass": ["top", "computer"], "sAMAccountName": "srv01$", "userAccountControl": 0x1000 | 0x80000,
                "operatingSystem": "Windows Server 2019", "pwdLastSet": RECENT}),
            Entry.make(f"CN=pc-old,CN=Computers,{BASE}", {
                "objectClass": ["top", "computer"], "sAMAccountName": "pc-old$", "userAccountControl": 0x1000,
                "operatingSystem": "Windows 10 Pro", "pwdLastSet": OLD, "lastLogonTimestamp": OLD,
                "whenCreated": "20200101000000.0Z"}),
        ]
        self._groups = {
            f"{DOM}-512": Entry.make(f"CN=Domain Admins,{users}", {"objectClass": ["group"],
                                                                   "sAMAccountName": "Domänen-Admins",
                                                                   "objectSid": sid_to_bytes(f"{DOM}-512")}),
            "S-1-5-32-544": Entry.make(f"CN=Administrators,CN=Builtin,{BASE}", {
                "objectClass": ["group"], "sAMAccountName": "Administratoren", "objectSid": sid_to_bytes("S-1-5-32-544")}),
        }
        self.members_of = {f"CN=Domain Admins,{users}": [self.anna],
                           f"CN=Administrators,CN=Builtin,{BASE}": [self.anna, self.svc, self._groups[f"{DOM}-512"]]}
        self.helpdesk = Entry.make(f"CN=Helpdesk,{users}", {"objectClass": ["group"], "sAMAccountName": "Helpdesk",
                                                            "objectSid": sid_to_bytes(f"{DOM}-1108")})
        self.gg = Entry.make(f"CN=GG-Clients,{users}", {"objectClass": ["group"], "sAMAccountName": "GG-Clients",
                                                        "objectSid": sid_to_bytes(f"{DOM}-1200")})

    @staticmethod
    def _gpo(guid, name, flags, version, raw_sd, machine="[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-"
                                                           "BA88-E8213C6761F1}]", wql="", user=""):
        values = {"cn": guid, "displayName": name, "flags": flags, "versionNumber": version,
                  "gPCFileSysPath": f"\\\\corp.example.test\\SysVol\\corp.example.test\\Policies\\{guid}",
                  "whenCreated": "20240101000000.0Z", "whenChanged": "20240201000000.0Z", "nTSecurityDescriptor": raw_sd}
        if machine:
            values["gPCMachineExtensionNames"] = machine
        if wql:
            values["gPCWQLFilter"] = wql
        if user:
            values["gPCUserExtensionNames"] = user
        return Entry.make(f"CN={guid},CN=Policies,CN=System,{BASE}", values)

    def root(self):
        return {"defaultnamingcontext": BASE, "configurationnamingcontext": CFG_NC,
                "schemanamingcontext": self.schema, "rootdomainnamingcontext": BASE}

    def domain(self):
        return self._domain

    def ous(self):
        return self._ous

    def sites(self):
        return [Entry.make(f"CN=Wien,CN=Sites,{CFG_NC}", {"name": "Wien"})]

    def gpos(self):
        return self._gpos

    def gpo(self, guid):
        return next((g for g in self._gpos if g.str("cn").upper() == guid.upper()), None)

    def wmi_filters(self):
        return [Entry.make(f"CN={{11111111-1111-1111-1111-111111111111}},CN=SOM,CN=WMIPolicy,CN=System,{BASE}", {
            "msWMI-Name": "Nur Windows 11", "msWMI-ID": "{11111111-1111-1111-1111-111111111111}",
            "msWMI-Parm2": '1;3;10;48;WQL;root\\CIMv2;SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "10%";'})]

    def psos(self):
        return self._psos

    _psos: list = []

    def users(self):
        return self._users

    def computers(self):
        return self._computers

    def managed_service_accounts(self):
        return []

    def schema_has(self, attr):
        return False

    def groups_by_sid(self, sids):
        return [self._groups[s] for s in sids if s in self._groups]

    def group_by_name(self, name):
        return None

    def members(self, dn):
        return self.members_of.get(dn, [])

    def direct_members(self, dn):
        return [e.dn for e in self.members_of.get(dn, [])]

    def primary_group_members(self, rid):
        return []

    def adminsdholder(self):
        return Entry.make(f"CN=AdminSDHolder,CN=System,{BASE}", {"nTSecurityDescriptor": sd(
            Ace(ALLOWED, 0, WRITE_DAC, f"{DOM}-1108"))})

    def domain_controllers(self):
        return self._computers[:1]

    def ntds_settings(self):
        return [Entry.make(f"CN=NTDS Settings,CN=DC1,CN=Servers,CN=Wien,CN=Sites,{CFG_NC}", {"options": 1})]

    def fsmo(self):
        return {"PDC-Emulator": f"CN=NTDS Settings,CN=DC1,CN=Servers,CN=Wien,CN=Sites,{CFG_NC}"}

    def subnets(self):
        return [Entry.make(f"CN=10.1.0.0/16,CN=Subnets,CN=Sites,{CFG_NC}", {"name": "10.1.0.0/16",
                                                                            "siteObject": f"CN=Wien,CN=Sites,{CFG_NC}"})]

    def site_links(self):
        return []

    def trusts(self):
        return [Entry.make(f"CN=partner.test,CN=System,{BASE}", {"trustPartner": "partner.test", "flatName": "PARTNER",
                                                                 "trustDirection": 3, "trustType": 2,
                                                                 "trustAttributes": 0}),
                Entry.make(f"CN=forest.test,CN=System,{BASE}", {"trustPartner": "forest.test", "trustDirection": 3,
                                                                "trustType": 2, "trustAttributes": 0x8})]

    def optional_features(self):
        return [Entry.make(f"CN=Recycle Bin Feature,{CFG_NC}", {"cn": "Recycle Bin Feature"})]

    def directory_service(self):
        return Entry.make(f"CN=Directory Service,{CFG_NC}", {"tombstoneLifetime": 180})

    def crossref(self):
        return Entry.make(f"CN=CORP,CN=Partitions,{CFG_NC}", {"nETBIOSName": "CORP", "dnsRoot": "corp.example.test"})

    def forest_level(self):
        return 7

    def schema_names(self):
        return {USER_CLASS: ("user", "class"), GROUP_CLASS: ("group", "class"), MEMBER: ("member", "attribute")}

    def extended_rights(self):
        return {RESET_PASSWORD: ("Reset Password", 256), GET_CHANGES_ALL: ("Replicating Directory Changes All", 256)}

    def resolve_dns(self, dns):
        known = {e.dn.lower(): e for e in [*self._users, *self._computers, *self._groups.values(), self.helpdesk]}
        return {d: known[d] for d in dns if d in known}

    def accounts_by_name(self, names):
        known = {e.str("sAMAccountName").lower(): e for e in [*self._users, *self._groups.values(), self.helpdesk]}
        return {n: known[n] for n in names if n in known}

    def resolve_sids(self, sids):
        known = {e.sid(): e for e in [self.helpdesk, self.gg, *self._groups.values()]}
        return {s: known[s] for s in sids if s in known}

    def close(self):
        self.closed += 1


class FakeSysvol:
    def __init__(self, files: dict[str, bytes]):
        self.files = {k.replace("/", "\\"): v for k, v in files.items()}

    def read(self, path):
        return self.files.get(path)

    def listdir(self, path):
        from doku_agent.connectors.sysvol import DirEntry
        prefix = path + "\\"
        if not any(k.startswith(prefix) for k in self.files):
            return None
        names = {}
        for k, v in self.files.items():
            if k.startswith(prefix):
                rest = k[len(prefix):].split("\\")
                names[rest[0]] = DirEntry(rest[0], len(rest) > 1, 0 if len(rest) > 1 else len(v), None)
        return list(names.values())

    def close(self):
        pass


def sysvol_files():
    root = "corp.example.test/Policies"
    return {
        f"{root}/{GPO_A}/GPT.INI": b"[General]\r\nVersion=65537\r\n",
        f"{root}/{GPO_A}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf": u16(
            "[Kerberos Policy]\nMaxTicketAge = 10\nMaxClockSkew = 5\n"),
        f"{root}/{GPO_B}/GPT.INI": b"[General]\r\nVersion=131075\r\n",
        f"{root}/{GPO_B}/Machine/Registry.pol": registry_pol_bytes([
            RegEntry(r"Software\Policies\WU\AU", "NoAutoUpdate", 4, 0),
            RegEntry(r"Software\Policies\WU\AU", "AUOptions", 4, 4),
            RegEntry(r"Software\Firma", "Server", 1, "agent.corp.example.test")]),
        f"{root}/{GPO_B}/Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf": u16(
            "[Privilege Rights]\nSeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-21-1-2-3-1108\n"),
        f"{root}/{GPO_B}/Machine/Preferences/Groups/Groups.xml": b'<Groups><User name="LokalAdmin"><Properties '
                                                                b'action="U" userName="LokalAdmin" cpassword="X1"/>'
                                                                b'</User></Groups>',
        f"{root}/{GPO_B}/User/Preferences/Drives/Drives.xml": b'<Drives><Drive name="H:"><Properties action="U" '
                                                              b'letter="H" path="\\\\fs01\\home" persistent="1"/>'
                                                              b'</Drive></Drives>',
        f"{root}/PolicyDefinitions/t.admx": ADMX_TEST.encode(),
        f"{root}/PolicyDefinitions/base.admx": ADMX_BASE.encode(),
        f"{root}/PolicyDefinitions/en-US/t.adml": ADML_TEST.encode(),
        f"{root}/PolicyDefinitions/de-DE/base.adml": ADML_BASE.encode(),
        # Ungenutzt (GPO_C) hat keinen Ordner -> Befund
    }


@pytest.fixture
def adctx(ctx):
    ctx.cfg.ad.enabled = True
    ctx.cfg.ad.domain = "corp.example.test"
    ctx.__dict__["ad"] = FakeAd()
    ctx.__dict__["sysvol"] = FakeSysvol(sysvol_files())
    return ctx


def contents(ctx) -> dict[str, str]:
    return {p.title: p.payload.get("content", "") for p in ctx.store.list_proposals()}


def block(content: str, block_id: str) -> str:
    m = re.search(rf"begin {block_id} -->(.*?)<!-- doku-agent:end", content, re.S)
    return m.group(1) if m else ""


def test_document_ad_creates_all_pages(adctx):
    from doku_agent.generators.ad_docs import document_ad
    results = document_ad(adctx)
    pages = contents(adctx)
    assert len([r for r in results if r]) == 9  # 3 GPOs + 6 Bereichsseiten
    gpo = pages["GPO: Clients - Sicherheit"]
    machine = block(gpo, "ad-gpo-machine")
    assert "Automatische Updates" in machine and "4 - automatisch" in machine  # Name aus en-US-ADML als Ersatz
    assert "HKLM\\Software\\Firma" in machine and "Remotedesktopdienste" in machine and "Helpdesk" in machine
    assert "X1" not in gpo and "gespeichertes Kennwort" in machine
    assert "\\\\fs01\\home" in block(gpo, "ad-gpo-user")
    links_md = block(gpo, "ad-gpo-links")
    assert "Firma / Clients" in links_md and "| Firma | OU | 1 | nein |" in links_md  # Verknüpfung an Firma deaktiviert
    assert "Nur Windows 11" in block(gpo, "ad-gpo-basics")
    security = block(gpo, "ad-gpo-security")
    assert "GG-Clients" in security and "kein Leserecht" in security and "Authentifizierte Benutzer" in security
    ou = pages["Active Directory: OU-Struktur und Delegationen"]
    assert "Kennwort zurücksetzen" in block(ou, "ad-ou-delegations") and "Helpdesk" in block(ou, "ad-ou-delegations")
    tree = block(ou, "ad-ou-tree")
    assert "1. Clients - Sicherheit (erzwungen)" in tree and "gelöschte GPO" in tree and "blockiert" in tree
    assert "| Firma | 1. Clients - Sicherheit (deaktiviert) | – | ja |" in tree
    password = pages["Active Directory: Kennwort- und Sperrrichtlinien"]
    assert "Maximale Gültigkeitsdauer des Benutzertickets" in block(password, "ad-password-kerberos")
    assert "Password Settings Container" in block(password, "ad-password-psos")
    domain = pages["Active Directory: Domäne und Gesamtstruktur"]
    assert "Windows Server 2016 (7)" in domain and "PDC-Emulator" in block(domain, "ad-domain-dcs")
    assert "10.1.0.0/16" in block(domain, "ad-domain-sites")
    priv = pages["Active Directory: Privilegierte Gruppen und Konten"]
    assert "Anna Admin (anna)" in priv and "Kennwort läuft nie ab" in priv
    assert "srv01$" in block(priv, "ad-priv-delegation")


def test_audit_findings(adctx):
    from doku_agent.generators.ad_common import AdNames, fetch
    from doku_agent.generators.ad_docs import audit
    data, errors = fetch(adctx, {"base", "structure", "gpo", "files", "password", "accounts", "privileged",
                                 "topology", "acl"})
    assert errors == {}
    f = audit(adctx, data, AdNames(adctx, data))
    text = {k: "\n".join(" | ".join(map(str, r)) for r in rows) for k, rows in f.items()}
    assert "gespeichertes Kennwort" in text["gpo"] and "Ungenutzt | nicht verknüpft" in text["gpo"]
    assert "GPO-Ordner fehlt" in text["gpo"] and "kein Leserecht (MS16-072)" in text["gpo"]
    assert "bearbeitbar durch Authentifizierte Benutzer" in text["gpo"]
    assert f"Verknüpfung auf nicht vorhandene GPO {GPO_GONE}" in text["gpo"]
    assert "Mindestlänge 7" in text["password"] and "keine Kontensperrung" in text["password"]
    assert "Kennwort läuft nie ab | Anna Admin (anna)" in text["privileged"]
    assert "krbtgt" in text["privileged"] and "adminCount=1" in text["privileged"]
    assert "Kerberoasting" in text["kerberos"] and "svc-sql" in text["kerberos"]
    assert "AS-REP" in text["kerberos"] and "srv01$" in text["kerberos"]
    assert "pc-old$" in text["accounts"] and "PASSWD_NOTREQD" in text["accounts"]
    assert "ex darf alle Kennwort-Hashes replizieren" in text["acl"]  # DCSync, nicht aber die DCs (S-1-5-9)
    assert "Domänencontroller der Organisation" not in text["acl"]
    assert "AdminSDHolder | Helpdesk: Berechtigungen ändern" in text["acl"]
    assert "Firma / Server | Authentifizierte Benutzer" in text["acl"]
    assert "MachineAccountQuota" in text["domain"] and "partner.test | externe Vertrauensstellung ohne SID" in text["domain"]
    assert "forest.test" not in text["domain"]  # Gesamtstruktur-Vertrauensstellung filtert SIDs immer
    assert "AD-Papierkorb" in text["domain"]  # Feature ohne msDS-EnabledFeatureBL


def test_count_mode_hides_person_names(adctx):
    from doku_agent.generators.ad_docs import document_ad
    adctx.cfg.ad.user_names = "count"
    document_ad(adctx, ["privileged", "audit"])
    pages = contents(adctx)
    for title in ("Active Directory: Privilegierte Gruppen und Konten", "Active Directory: Prüfung"):
        assert "Anna" not in pages[title] and "anna" not in pages[title]
    assert "Benutzerkonten: 1" in pages["Active Directory: Prüfung"]


def test_second_run_is_stable(adctx, fake_wiki):
    """Unveränderte Daten erzeugen nach dem Übernehmen keine neuen Vorschläge (keine tagesabhängigen Angaben)."""
    from doku_agent.generators.ad_docs import document_ad
    document_ad(adctx)
    for p in adctx.store.list_proposals():
        fake_wiki.add(p.payload["path"], p.payload["title"], p.payload["content"], tags=p.payload["tags"],
                      description=p.payload["description"])
    adctx.__dict__.pop("conventions", None)
    assert all(r is None for r in document_ad(adctx))


def test_unreadable_area_fails_job_but_documents_rest(adctx):
    from doku_agent.connectors.sysvol import SysvolError
    from doku_agent.generators.ad_docs import document_ad

    class Broken(FakeSysvol):
        def listdir(self, path):
            raise SysvolError("SMB-Anmeldung an dc1 abgelehnt")
    adctx.__dict__["sysvol"] = Broken({})
    with pytest.raises(RuntimeError, match="Gruppenrichtlinien"):
        document_ad(adctx, ["gpo", "domain"])
    titles = set(contents(adctx))
    assert "Active Directory: Domäne und Gesamtstruktur" in titles
    assert not any(t.startswith("GPO:") for t in titles)


def test_sysvol_off_documents_gpos_without_settings(adctx):
    from doku_agent.generators.ad_docs import document_ad
    adctx.cfg.ad.sysvol = False
    document_ad(adctx, ["gpo"])
    gpo = contents(adctx)["GPO: Clients - Sicherheit"]
    assert "ad.sysvol: false" in block(gpo, "ad-gpo-machine")


def test_lint_refresh_and_gone_gpo(adctx):
    from doku_agent.lint import SourceGone, Unsupported, refresh
    assert refresh(adctx, f"ad:gpo:{GPO_B}")
    assert refresh(adctx, "ad:kennwortrichtlinien")
    with pytest.raises(SourceGone):
        refresh(adctx, f"ad:gpo:{GPO_GONE}")
    adctx.cfg.ad.include = ["domain"]
    with pytest.raises(Unsupported):
        refresh(adctx, f"ad:gpo:{GPO_B}")


def test_job_and_checks(adctx):
    from doku_agent.jobs import JOBS, STARTABLE, run_now
    from doku_agent.web.app import run_checks
    assert "ad" in JOBS and "ad" in STARTABLE
    adctx.__dict__["llm"].models = lambda: ["qwen3:8b"]
    _, ok = run_now(adctx, "ad", {"areas": "domain"})
    assert ok and adctx.ad.closed == 1
    checks = {name: (ok, text) for name, ok, text in run_checks(adctx)}
    assert checks["Active Directory (LDAP)"][0] and "Windows Server 2016" in checks["Active Directory (LDAP)"][1]
    assert checks["AD-Leserechte"][0] and "Password Settings Container" in checks["AD-Leserechte"][1]
    assert checks["Active Directory (SYSVOL)"] == (True, "3 GPO-Ordner lesbar; Central Store vorhanden") or \
        checks["Active Directory (SYSVOL)"][1].startswith("2 GPO-Ordner")


def test_one_unreadable_gpo_folder_does_not_stop_the_run(adctx):
    from doku_agent.connectors.sysvol import SysvolFileError
    from doku_agent.generators.ad_common import AdNames, fetch
    from doku_agent.generators.ad_docs import audit

    class Denied(FakeSysvol):
        def listdir(self, path):
            if GPO_B in path:
                raise SysvolFileError("Zugriff verweigert")
            return super().listdir(path)
    adctx.__dict__["sysvol"] = Denied(sysvol_files())
    data, errors = fetch(adctx, {"base", "structure", "gpo", "files", "acl"})
    assert errors == {} and data.files[GPO_B.lower()].errors
    f = audit(adctx, data, AdNames(adctx, data))
    assert any("nicht lesbar" in r[1] for r in f["gpo"] if r[0] == "Clients - Sicherheit")
    assert data.files[GPO_A.lower()].template is not None  # die anderen GPOs sind gelesen


# --- Befunde aus dem Code-Review ----------------------------------------------------------------------

def test_secrets_in_preferences_registry_and_templates_are_masked(adctx):
    from doku_agent.generators.ad_docs import document_ad
    files = sysvol_files()
    root = f"corp.example.test/Policies/{GPO_B}"
    files[f"{root}/Machine/Preferences/Registry/Registry.xml"] = (
        b'<RegistrySettings><Registry name="DefaultPassword"><Properties action="U" hive="HKEY_LOCAL_MACHINE" '
        b'key="SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" name="DefaultPassword" type="REG_SZ" '
        b'value="Geheim-Pref-1!"/></Registry></RegistrySettings>')
    files[f"{root}/Machine/Preferences/EnvironmentVariables/EnvironmentVariables.xml"] = (
        b'<EnvironmentVariables><EnvironmentVariable name="API_TOKEN"><Properties action="U" name="API_TOKEN" '
        b'value="Geheim-Env-2!"/></EnvironmentVariable></EnvironmentVariables>')
    files[f"{root}/Machine/Registry.pol"] = registry_pol_bytes([
        RegEntry(r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "DefaultPassword", 1, "Geheim-Pol-3!")])
    adctx.__dict__["sysvol"] = FakeSysvol(files)
    document_ad(adctx, ["gpo"])
    gpo = contents(adctx)["GPO: Clients - Sicherheit"]
    for secret in ("Geheim-Pref-1!", "Geheim-Env-2!", "Geheim-Pol-3!"):
        assert secret not in gpo
    prompts = " ".join(user for _, user in adctx.__dict__["llm"].calls)
    assert "Geheim" not in prompts and "DefaultPassword" in gpo


def test_broken_files_only_affect_their_gpo(adctx):
    from doku_agent.generators.ad_docs import document_ad
    files = sysvol_files()
    files[f"corp.example.test/Policies/{GPO_B}/Machine/Registry.pol"] = b"PReg"  # abgeschnitten
    files[f"corp.example.test/Policies/{GPO_A}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf"] = \
        b"\xff\xfe[\x00K\x00"  # ungerade Länge
    adctx.__dict__["sysvol"] = FakeSysvol(files)
    document_ad(adctx)
    pages = contents(adctx)
    assert "Registry.pol" in block(pages["GPO: Clients - Sicherheit"], "ad-gpo-machine")
    assert "Active Directory: OU-Struktur und Delegationen" in pages and "Active Directory: Prüfung" in pages


def test_large_or_vanishing_file_is_a_per_file_error(adctx):
    from doku_agent.connectors.sysvol import SysvolFileError
    from doku_agent.generators.ad_common import fetch

    class Odd(FakeSysvol):
        def read(self, path):
            if path.endswith("Groups.xml"):
                raise SysvolFileError("STATUS_DELETE_PENDING")
            return super().read(path)
    adctx.__dict__["sysvol"] = Odd(sysvol_files())
    data, errors = fetch(adctx, {"base", "structure", "gpo", "files", "acl"})
    assert errors == {} and any("Groups.xml" in e for e in data.files[GPO_B.lower()].errors)


def test_pso_scope_in_count_mode_and_stable_between_job_and_lint(adctx, fake_wiki):
    from doku_agent.generators.ad_docs import document_ad
    from doku_agent.lint import refresh
    ad = adctx.ad
    ad._psos = [Entry.make(f"CN=PSO-Test,CN=Password Settings Container,CN=System,{BASE}", {
        "name": "PSO-Test", "msDS-PasswordSettingsPrecedence": 5, "msDS-MinimumPasswordLength": 14,
        "msDS-PasswordComplexityEnabled": True, "msDS-LockoutThreshold": 5, "msDS-LockoutDuration": -0x8000000000000000,
        "msDS-PSOAppliesTo": [ad.anna.dn, f"CN=Domain Admins,CN=Users,{BASE}"]})]
    document_ad(adctx, ["password_policy"])
    page = contents(adctx)["Active Directory: Kennwort- und Sperrrichtlinien"]
    psos = block(page, "ad-password-psos")
    assert "Anna Admin (anna)" in psos and "Domänen-Admins" in psos and "bis ein Administrator entsperrt" in psos
    for p in adctx.store.list_proposals():  # übernehmen, dann muss der Wiki-Lint dieselbe Seite erzeugen
        fake_wiki.add(p.payload["path"], p.payload["title"], p.payload["content"], tags=p.payload["tags"],
                      description=p.payload["description"])
    adctx.__dict__.pop("conventions", None)
    assert refresh(adctx, "ad:kennwortrichtlinien") is None
    adctx.cfg.ad.user_names = "count"
    document_ad(adctx, ["password_policy"])
    page = [p for p in adctx.store.list_proposals() if p.title.endswith("Sperrrichtlinien")][-1].payload["content"]
    assert "Anna" not in page and "Benutzer" in block(page, "ad-password-psos")


def test_ms16_072_with_enterprise_dc_read(adctx):
    """Organisations-DCs lesen jede GPO – das zählt nicht als Leserecht der Computer."""
    from doku_agent.generators import gpo_docs
    g = adctx.ad.gpo(GPO_B)
    acl = gpo_docs.gpo_acl(g)
    assert "S-1-5-9" in acl.read and gpo_docs.ms16_072(g, acl, DOM)
    assert not gpo_docs.ms16_072(adctx.ad.gpo(GPO_A), gpo_docs.gpo_acl(adctx.ad.gpo(GPO_A)), DOM)


def test_trust_sid_filtering_direction(adctx):
    from doku_agent.generators.ad_common import AdNames, fetch
    from doku_agent.generators.ad_docs import audit

    def trust(name, direction, kind=2):
        return Entry.make(f"CN={name},CN=System,{BASE}", {"trustPartner": name, "trustDirection": direction,
                                                          "trustType": kind, "trustAttributes": 0})
    adctx.ad.trusts = lambda: [trust("out.test", 2), trust("in.test", 1), trust("mit.test", 2, kind=3)]
    data, _ = fetch(adctx, {"base", "topology"})
    text = str(audit(adctx, data, AdNames(adctx, data))["domain"])
    assert "out.test" in text and "in.test" not in text and "mit.test" not in text


def test_admx_list_delete_and_boolean_false_delete():
    admx = f"""<policyDefinitions {NS}><policyNamespaces><target prefix="x" namespace="X"/></policyNamespaces>
<policies>
<policy name="L" class="Machine" displayName="Liste" key="Software\\L">
<enabledList><item valueName="On"><value><decimal value="1"/></value></item></enabledList>
<disabledList><item valueName="On"><value><decimal value="0"/></value></item></disabledList></policy>
<policy name="E" class="Machine" displayName="Nur enabledValue" key="Software\\E" valueName="V">
<enabledValue><decimal value="1"/></enabledValue></policy>
<policy name="B" class="Machine" displayName="Schalter" presentation="$(presentation.B)" key="Software\\B">
<elements><boolean id="S" valueName="Flag"><trueValue><decimal value="1"/></trueValue><falseValue><delete/></falseValue>
</boolean></elements></policy>
</policies></policyDefinitions>"""
    cat = gpo_files.AdmxCatalog().load({"x.admx": admx.encode()}, {})
    on, _ = cat.evaluate("Machine", [RegEntry(r"Software\L", "On", 4, 1)])
    off, _ = cat.evaluate("Machine", [RegEntry(r"Software\L", "On", 4, 0), RegEntry(r"Software\E", "**del.V", 1, " "),
                                      RegEntry(r"Software\B", "**del.Flag", 1, " ")])
    assert [(s.policy.display, s.state) for s in on] == [("Liste", "Aktiviert")]
    states = {s.policy.display: (s.state, s.options) for s in off}
    assert states["Liste"][0] == "Deaktiviert" and states["Nur enabledValue"][0] == "Deaktiviert"
    assert states["Schalter"] == ("Aktiviert", [("S", "nein")])


def test_kerberos_settings_follow_link_order_per_setting(adctx):
    from doku_agent.generators import ad_docs
    from doku_agent.generators.ad_common import fetch
    ad = adctx.ad
    ad._domain.attrs["gplink"] = [link((GPO_A, 0), (GPO_C, 0)).encode()]  # GPO_C hat Reihenfolge 1
    files = sysvol_files()
    files[f"corp.example.test/Policies/{GPO_C}/Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf"] = u16(
        "[Kerberos Policy]\nMaxTicketAge = 8\n")
    adctx.__dict__["sysvol"] = FakeSysvol(files)
    data, _ = fetch(adctx, {"base", "structure", "gpo", "files"})
    result = {k: (v, src) for k, v, src in ad_docs.kerberos_settings(data)}
    assert result["MaxTicketAge"] == ("8", "Ungenutzt") and result["MaxClockSkew"] == ("5", "Default Domain Policy")


def test_ranged_attribute_uses_reported_range(tmp_path):
    cfg = make_config(tmp_path, ad={"enabled": True, "domain": "corp.example.test", "username": "u@x"})
    client = AdClient(cfg.ad, EgressGuard(set()))
    pages = [{"member;range=0-999": [b"a"] * 1000}, {"member;range=1000-*": [b"b"] * 5}]
    asked = []

    def search(base, flt, attrs, scope="sub", sd=False):
        asked.append(attrs[0])
        return [Entry(base, pages[len(asked) - 1])]
    client.search = search
    assert len(client.ranged("CN=G", "member")) == 1005 and asked == ["member;range=0-*", "member;range=1000-*"]
