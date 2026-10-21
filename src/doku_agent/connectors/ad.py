"""Lokales Active Directory über LDAP – nur lesend.

Anmeldung ausschließlich über TLS (LDAPS oder StartTLS) mit einfacher Anmeldung (UPN + Kennwort): Ein
normaler Domänenbenutzer genügt für fast alles. Verweise (Referrals) auf andere Server werden nicht verfolgt,
es wird nur mit den eingetragenen Domänencontrollern gesprochen. Sicherheitsbeschreibungen werden nur mit
Besitzer und DACL angefordert (ohne SACL – die dürfen nur Administratoren lesen).

Werte werden roh gelesen und hier dekodiert, unabhängig vom Schema-Cache von ldap3.
"""

from __future__ import annotations

import re
import ssl
import threading
from datetime import datetime, timedelta, timezone

from doku_agent.ad_acl import sid_to_bytes, sid_to_str
from doku_agent.config import AdConfig
from doku_agent.egress import EgressBlocked, EgressGuard

PAGE_SIZE = 500
SD_OWNER_DACL = 0x05  # LDAP_SERVER_SD_FLAGS_OID: OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
IN_CHAIN = "1.2.840.113556.1.4.1941"  # LDAP_MATCHING_RULE_IN_CHAIN
BIT_AND = "1.2.840.113556.1.4.803"  # LDAP_MATCHING_RULE_BIT_AND
EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
NEVER = -0x8000000000000000  # Intervall "nie" (z.B. maxPwdAge)

# Fehlercodes in der Antwort auf eine abgelehnte Anmeldung ("… data 52e, …")
BIND_ERRORS = {
    "525": "Benutzer nicht gefunden", "52e": "Benutzername oder Kennwort falsch",
    "530": "Anmeldung zu dieser Zeit nicht erlaubt", "531": "Anmeldung an diesem Computer nicht erlaubt",
    "532": "Kennwort abgelaufen", "533": "Konto deaktiviert", "568": "zu viele Gruppen (Token zu groß)",
    "701": "Konto abgelaufen", "773": "Kennwort muss geändert werden", "775": "Konto gesperrt",
}

DOMAIN_ATTRS = ["distinguishedName", "name", "objectSid", "minPwdLength", "pwdHistoryLength", "maxPwdAge", "minPwdAge",
                "lockoutThreshold", "lockoutDuration", "lockOutObservationWindow", "pwdProperties",
                "ms-DS-MachineAccountQuota", "gPLink", "gPOptions", "whenCreated", "fSMORoleOwner",
                "msDS-Behavior-Version", "wellKnownObjects", "nTSecurityDescriptor"]
GPO_ATTRS = ["cn", "displayName", "gPCFileSysPath", "flags", "versionNumber", "gPCMachineExtensionNames",
             "gPCUserExtensionNames", "gPCWQLFilter", "whenCreated", "whenChanged", "nTSecurityDescriptor"]
OU_ATTRS = ["name", "description", "gPLink", "gPOptions", "managedBy", "whenCreated", "nTSecurityDescriptor"]
PSO_ATTRS = ["name", "description", "msDS-PasswordSettingsPrecedence", "msDS-PasswordReversibleEncryptionEnabled",
             "msDS-PasswordHistoryLength", "msDS-PasswordComplexityEnabled", "msDS-MinimumPasswordLength",
             "msDS-MinimumPasswordAge", "msDS-MaximumPasswordAge", "msDS-LockoutThreshold",
             "msDS-LockoutObservationWindow", "msDS-LockoutDuration", "msDS-PSOAppliesTo", "whenChanged"]
USER_ATTRS = ["objectClass", "sAMAccountName", "displayName", "userPrincipalName", "userAccountControl",
              "lastLogonTimestamp", "pwdLastSet", "adminCount", "servicePrincipalName", "msDS-AllowedToDelegateTo",
              "msDS-AllowedToActOnBehalfOfOtherIdentity", "msDS-SupportedEncryptionTypes", "whenCreated", "objectSid",
              "primaryGroupID", "accountExpires", "description"]
COMPUTER_ATTRS = ["objectClass", "name", "sAMAccountName", "dNSHostName", "operatingSystem", "operatingSystemVersion",
                  "userAccountControl", "lastLogonTimestamp", "pwdLastSet", "whenCreated", "objectSid", "primaryGroupID",
                  "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity", "description"]
LAPS_ATTRS = ("msLAPS-PasswordExpirationTime", "ms-Mcs-AdmPwdExpirationTime")  # Windows LAPS, Legacy-LAPS
MSA_ATTRS = ["sAMAccountName", "objectClass", "servicePrincipalName", "msDS-ManagedPasswordInterval",
             "msDS-HostServiceAccountBL", "userAccountControl", "msDS-AllowedToDelegateTo", "pwdLastSet", "whenCreated",
             "msDS-GroupMSAMembership", "objectSid"]
MEMBER_ATTRS = ["objectClass", "sAMAccountName", "displayName", "userPrincipalName", "userAccountControl",
                "lastLogonTimestamp", "pwdLastSet", "objectSid", "servicePrincipalName", "adminCount"]
GROUP_ATTRS = ["objectClass", "sAMAccountName", "name", "objectSid", "description", "groupType", "adminCount"]
TRUST_ATTRS = ["trustPartner", "flatName", "trustDirection", "trustType", "trustAttributes",
               "msDS-SupportedEncryptionTypes", "whenCreated", "whenChanged", "securityIdentifier"]
DC_ATTRS = ["name", "dNSHostName", "operatingSystem", "operatingSystemVersion", "userAccountControl",
            "lastLogonTimestamp", "whenCreated", "serverReferenceBL"]


class AdError(RuntimeError):
    pass


def _ldap3():
    import ldap3  # erst bei Bedarf: AD ist optional
    return ldap3


def escape_value(value: str) -> str:
    """Wert in einem LDAP-Filter (RFC 4515)."""
    return "".join(f"\\{ord(c):02x}" if c in "*()\\\x00" else c for c in value)


def escape_bytes(raw: bytes) -> str:
    return "".join(f"\\{b:02x}" for b in raw)


def sid_filter(sids: list[str]) -> str:
    parts = []
    for sid in sids:
        try:
            parts.append(f"(objectSid={escape_bytes(sid_to_bytes(sid))})")
        except ValueError:
            continue
    return f"(|{''.join(parts)})" if parts else ""


def filetime(value: int | None) -> datetime | None:
    """FILETIME (100 ns seit 1601); 0 und 'nie' (0x7FFF…) -> None."""
    if not value or value >= 0x7FFFFFFFFFFFFFFF or value < 0:
        return None
    try:
        return EPOCH + timedelta(microseconds=value // 10)
    except OverflowError:
        return None


def interval_seconds(value: int | None) -> int | None:
    """Zeitspanne aus maxPwdAge, lockoutDuration … (negativ in 100 ns); None = nie bzw. nicht gesetzt."""
    if value is None or value == NEVER:
        return None
    return abs(value) // 10_000_000


def generalized_time(value: str) -> datetime | None:
    m = re.match(r"^(\d{14})(?:\.\d+)?Z$", value or "")
    if not m:
        return None
    return datetime.strptime(m.group(1), "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)


def rdn(dn: str) -> str:
    """Wert des ersten RDN: 'CN=Max\\, Muster,OU=…' -> 'Max, Muster'."""
    first = re.split(r"(?<!\\),", dn or "", maxsplit=1)[0]
    return re.sub(r"\\(.)", r"\1", first.split("=", 1)[-1])


def parent_dn(dn: str) -> str:
    parts = re.split(r"(?<!\\),", dn or "", maxsplit=1)
    return parts[1] if len(parts) > 1 else ""


class Entry:
    """Ein Verzeichnisobjekt mit rohen Werten (Attributnamen ohne Groß-/Kleinschreibung)."""

    def __init__(self, dn: str, attrs: dict[str, list[bytes]]):
        self.dn = dn
        self.attrs: dict[str, list[bytes]] = {}
        for key, values in attrs.items():
            name = key.lower()
            if ";range=" in name:  # Teilmenge eines großen Attributs (member;range=0-1499)
                name = name.split(";", 1)[0]
            self.attrs.setdefault(name, []).extend(values if isinstance(values, list) else [values])

    @classmethod
    def make(cls, dn: str, values: dict) -> "Entry":
        """Für Tests: Python-Werte -> rohe Werte wie vom Server."""
        def raw(v) -> bytes:
            if isinstance(v, bytes):
                return v
            if isinstance(v, bool):
                return b"TRUE" if v else b"FALSE"
            return str(v).encode()
        return cls(dn, {k: [raw(x) for x in (v if isinstance(v, list) else [v])] for k, v in values.items()})

    def __repr__(self) -> str:
        return f"Entry({self.dn!r})"

    def has(self, name: str) -> bool:
        return bool(self.attrs.get(name.lower()))

    def raw(self, name: str) -> bytes | None:
        values = self.attrs.get(name.lower())
        return values[0] if values else None

    def values(self, name: str) -> list[bytes]:
        return list(self.attrs.get(name.lower(), []))

    def str(self, name: str, default: str = "") -> str:
        value = self.raw(name)
        return value.decode("utf-8", "replace") if value is not None else default

    def strs(self, name: str) -> list[str]:
        return [v.decode("utf-8", "replace") for v in self.values(name)]

    def int(self, name: str, default: int | None = None) -> int | None:
        value = self.raw(name)
        try:
            return int(value) if value is not None else default
        except ValueError:
            return default

    def bool(self, name: str) -> bool | None:
        value = self.raw(name)
        return None if value is None else value.upper() == b"TRUE"

    def sid(self, name: str = "objectSid") -> str:
        value = self.raw(name)
        return sid_to_str(value) if value else ""

    def time(self, name: str) -> datetime | None:
        """Zeitstempel als FILETIME (pwdLastSet …) oder GeneralizedTime (whenCreated …)."""
        value = self.str(name)
        if value.lstrip("-").isdigit():
            return filetime(int(value))
        return generalized_time(value)

    @property
    def name(self) -> str:
        return self.str("name") or rdn(self.dn)

    def classes(self) -> list[str]:
        return [c.lower() for c in self.strs("objectClass")]


class _ContextTls:
    """TLS über einen eigenen ssl.SSLContext mit Hostnamenprüfung (statt der älteren Prüfung in ldap3)."""

    def __new__(cls, context: ssl.SSLContext, host: str):
        ldap3 = _ldap3()

        class Tls(ldap3.Tls):
            def wrap_socket(self, connection, do_handshake=False):
                connection.socket = context.wrap_socket(connection.socket, server_side=False,
                                                        do_handshake_on_connect=do_handshake,
                                                        server_hostname=host)

        return Tls()


def tls_context(verify) -> ssl.SSLContext:
    if verify is False:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    try:
        ctx = ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)
    except (OSError, ssl.SSLError) as exc:
        raise AdError(f"CA-Datei aus ad.verify_tls nicht lesbar ({verify}): {exc}") from exc
    # Ab Python 3.13 lehnt der strikte Modus Zertifikate ohne Authority Key Identifier ab – bei internen
    # Zertifizierungsstellen und DC-Zertifikaten häufig. Kette und Hostname werden weiterhin geprüft.
    ctx.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
    return ctx


def _tls_hint(message: str) -> str:
    if "CERTIFICATE_VERIFY_FAILED" in message and "Hostname mismatch" in message or "doesn't match" in message:
        return (" – der Servername passt nicht zum Zertifikat; in ad.servers den DNS-Namen aus dem Zertifikat des "
                "DCs eintragen (keine IP-Adresse)")
    if "CERTIFICATE_VERIFY_FAILED" in message:
        return (" – das Zertifikat des DCs ist nicht vertrauenswürdig; die Stammzertifizierungsstelle der Domäne als "
                "PEM-Datei unter ad.verify_tls angeben")
    if "WRONG_VERSION_NUMBER" in message or "UNEXPECTED_EOF" in message or "unexpected eof" in message:
        return (" – der Server spricht an diesem Port kein TLS; für LDAPS Port 636 verwenden, für Port 389 "
                "ad.starttls: true")
    return ""


def bind_message(result: dict) -> str:
    text = f"{result.get('description', '')} {result.get('message', '')}".strip()
    m = re.search(r"data ([0-9a-f]{3,4})", result.get("message", "") or "")
    if m and m.group(1) in BIND_ERRORS:
        return f"Anmeldung abgelehnt: {BIND_ERRORS[m.group(1)]} ({text})"
    if result.get("description") == "strongerAuthRequired":
        return f"Anmeldung abgelehnt: der DC verlangt eine verschlüsselte Verbindung ({text})"
    return f"Anmeldung abgelehnt: {text}"


class AdClient:
    def __init__(self, cfg: AdConfig, guard: EgressGuard):
        self.cfg = cfg
        self.guard = guard
        self.servers = list(cfg.servers) or ([cfg.domain] if cfg.domain else [])
        self._conn = None
        self.server = ""  # verbundener DC
        self._lock = threading.RLock()
        self._root: dict[str, str] | None = None
        self._schema_attrs: set[str] | None = None
        self._names: dict[str, tuple[str, str]] = {}

    # --- Verbindung -----------------------------------------------------------------------------

    def _open(self, host: str):
        ldap3 = _ldap3()
        self.guard.check_host(host, "LDAP")
        tls = _ContextTls(tls_context(self.cfg.verify_tls), host)
        server = ldap3.Server(host, port=self.cfg.ldap_port, use_ssl=not self.cfg.starttls, tls=tls,
                              get_info=ldap3.NONE, connect_timeout=self.cfg.timeout_s)
        conn = ldap3.Connection(server, user=self.cfg.username, password=self.cfg.password,
                                authentication=ldap3.SIMPLE, auto_referrals=False, raise_exceptions=False,
                                receive_timeout=max(self.cfg.timeout_s, 60), read_only=True)
        try:
            conn.open()
            if self.cfg.starttls and not conn.start_tls():
                raise AdError(f"StartTLS an {host}:{self.cfg.ldap_port} fehlgeschlagen: {conn.result}")
        except ldap3.core.exceptions.LDAPException as exc:
            msg = str(exc)
            raise AdError(f"LDAP {host}:{self.cfg.ldap_port} nicht erreichbar: {msg}{_tls_hint(msg)}") from exc
        if not self.cfg.username:
            raise AdError("ad.username fehlt (Lesekonto als UPN, z.B. svc-doku@corp.example.local)")
        if not conn.bind():
            raise AdError(f"LDAP {host}: {bind_message(conn.result)}")
        return conn

    def _connection(self):
        if self._conn is not None:
            return self._conn
        if not self.servers:
            raise AdError("Kein Domänencontroller konfiguriert (ad.domain bzw. ad.servers)")
        errors = []
        for host in self.servers:
            try:
                self._conn = self._open(host)
                self.server = host
                return self._conn
            except (AdError, EgressBlocked) as exc:
                errors.append(str(exc))
                if "Anmeldung abgelehnt" in str(exc):  # gleiche Zugangsdaten scheitern auch am nächsten DC
                    break
        raise AdError("; ".join(errors))

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.unbind()
                except Exception:
                    pass
            self._conn = None

    # --- Suche ------------------------------------------------------------------------------

    def search(self, base: str, flt: str, attrs: list[str], scope: str = "sub", sd: bool = False) -> list[Entry]:
        """Seitenweise Suche. Fehlt die Basis (noSuchObject), ist das Ergebnis leer."""
        ldap3 = _ldap3()
        scopes = {"sub": ldap3.SUBTREE, "one": ldap3.LEVEL, "base": ldap3.BASE}
        controls = None
        if sd:
            from ldap3.protocol.microsoft import security_descriptor_control
            controls = security_descriptor_control(sdflags=SD_OWNER_DACL)
        with self._lock:
            for attempt in (1, 2):
                conn = self._connection()
                try:
                    return self._paged(conn, base, flt, attrs, scopes[scope], controls, scope != "base")
                except ldap3.core.exceptions.LDAPException as exc:  # Verbindung abgebrochen: einmal neu
                    self.close()
                    if attempt == 2:
                        raise AdError(f"LDAP-Suche in {base} fehlgeschlagen: {exc}") from exc
        return []

    @staticmethod
    def _paged(conn, base, flt, attrs, scope, controls, paged) -> list[Entry]:
        out, cookie = [], None
        while True:
            conn.search(base, flt, search_scope=scope, attributes=attrs, controls=controls,
                        paged_size=PAGE_SIZE if paged else None, paged_cookie=cookie)
            result = conn.result or {}
            code = result.get("result")
            if code == 32:  # noSuchObject
                return out
            if code not in (0, None):
                raise AdError(f"LDAP-Suche in {base} mit {flt}: {result.get('description')} "
                              f"{result.get('message', '')}".strip())
            for item in conn.response or []:
                if item.get("type") == "searchResEntry":
                    out.append(Entry(item.get("dn", ""), item.get("raw_attributes") or {}))
            cookie = (((result.get("controls") or {}).get("1.2.840.113556.1.4.319") or {}).get("value") or {}).get(
                "cookie")
            if not paged or not cookie:
                return out

    def ranged(self, dn: str, attr: str) -> list[bytes]:
        """Alle Werte eines großen Attributs (z.B. member mit mehr als 1500 Mitgliedern)."""
        values, start = [], 0
        while True:
            found = self.search(dn, "(objectClass=*)", [f"{attr};range={start}-*"], scope="base")
            if not found:
                return values
            raw = found[0]
            keys = [k for k in raw.attrs if k == attr.lower()]
            values += raw.values(attr)
            # Das letzte Teilstück endet auf '-*'; Entry hat die Bereichsangabe entfernt, daher über die Anzahl
            if not keys or len(raw.values(attr)) < 1500:
                return values
            start += len(raw.values(attr))

    # --- Grunddaten -------------------------------------------------------------------------

    def root(self) -> dict[str, str]:
        if self._root is None:
            found = self.search("", "(objectClass=*)", [
                "defaultNamingContext", "configurationNamingContext", "schemaNamingContext",
                "rootDomainNamingContext", "dnsHostName", "serverName", "dsServiceName", "domainFunctionality",
                "forestFunctionality", "domainControllerFunctionality"], scope="base")
            if not found:
                raise AdError("RootDSE nicht lesbar")
            e = found[0]
            self._root = {k: e.str(k) for k in e.attrs}
            self._root = {k.lower(): v for k, v in self._root.items()}
        return self._root

    @property
    def base(self) -> str:
        return self.root()["defaultnamingcontext"]

    @property
    def config(self) -> str:
        return self.root()["configurationnamingcontext"]

    @property
    def schema(self) -> str:
        return self.root()["schemanamingcontext"]

    def whoami(self) -> str:
        with self._lock:
            return str(self._connection().extend.standard.who_am_i() or "")

    def one(self, dn: str, attrs: list[str], sd: bool = False) -> Entry | None:
        found = self.search(dn, "(objectClass=*)", attrs, scope="base", sd=sd)
        return found[0] if found else None

    def domain(self) -> Entry:
        entry = self.one(self.base, DOMAIN_ATTRS, sd=True)
        if entry is None:
            raise AdError(f"Domänenobjekt {self.base} nicht lesbar")
        return entry

    def schema_has(self, attr: str) -> bool:
        if self._schema_attrs is None:
            self._schema_attrs = {n.lower() for n, kind in self.schema_names().values() if kind == "attribute"}
        return attr.lower() in self._schema_attrs

    def schema_names(self) -> dict[str, tuple[str, str]]:
        """schemaIDGUID -> (lDAPDisplayName, 'attribute'|'class') für die Beschreibung von Berechtigungen."""
        if not self._names:
            from doku_agent.ad_acl import guid_to_str
            for e in self.search(self.schema, "(|(objectClass=attributeSchema)(objectClass=classSchema))",
                                 ["lDAPDisplayName", "schemaIDGUID", "objectClass"]):
                raw = e.raw("schemaIDGUID")
                if raw and len(raw) == 16:
                    kind = "class" if "classschema" in e.classes() else "attribute"
                    self._names[guid_to_str(raw)] = (e.str("lDAPDisplayName"), kind)
        return self._names

    def extended_rights(self) -> dict[str, tuple[str, int]]:
        """rightsGuid -> (Anzeigename, validAccesses) aus CN=Extended-Rights."""
        out = {}
        for e in self.search(f"CN=Extended-Rights,{self.config}", "(objectClass=controlAccessRight)",
                             ["displayName", "rightsGuid", "validAccesses"], scope="one"):
            guid = e.str("rightsGuid").strip("{}").lower()
            if guid:
                out[guid] = (e.str("displayName") or e.name, e.int("validAccesses", 0))
        return out

    # --- Gruppenrichtlinien und Struktur ---------------------------------------------------------

    def gpos(self) -> list[Entry]:
        return self.search(f"CN=Policies,CN=System,{self.base}", "(objectClass=groupPolicyContainer)", GPO_ATTRS,
                           scope="one", sd=True)

    def gpo(self, guid: str) -> Entry | None:
        found = self.search(f"CN=Policies,CN=System,{self.base}",
                            f"(&(objectClass=groupPolicyContainer)(cn={escape_value(guid)}))", GPO_ATTRS,
                            scope="one", sd=True)
        return found[0] if found else None

    def wmi_filters(self) -> list[Entry]:
        return self.search(f"CN=SOM,CN=WMIPolicy,CN=System,{self.base}", "(objectClass=msWMI-Som)",
                           ["msWMI-Name", "msWMI-Parm1", "msWMI-Parm2", "msWMI-ID", "whenChanged"], scope="one")

    def ous(self) -> list[Entry]:
        return self.search(self.base, "(objectClass=organizationalUnit)", OU_ATTRS, sd=True)

    def sites(self) -> list[Entry]:
        return self.search(f"CN=Sites,{self.config}", "(objectClass=site)", ["name", "description", "gPLink",
                                                                             "location"], scope="one")

    def subnets(self) -> list[Entry]:
        return self.search(f"CN=Subnets,CN=Sites,{self.config}", "(objectClass=subnet)",
                           ["name", "siteObject", "location", "description"], scope="one")

    def site_links(self) -> list[Entry]:
        return self.search(f"CN=Inter-Site Transports,CN=Sites,{self.config}", "(objectClass=siteLink)",
                           ["name", "cost", "replInterval", "siteList", "options", "description"])

    def ntds_settings(self) -> list[Entry]:
        """NTDS-Einstellungen je DC (Optionen: Bit 1 = globaler Katalog)."""
        return self.search(f"CN=Sites,{self.config}", "(objectClass=nTDSDSA)", ["options", "msDS-isRODC"])

    def domain_controllers(self) -> list[Entry]:
        return self.search(self.base, f"(&(objectCategory=computer)(|(userAccountControl:{BIT_AND}:=8192)"
                                      f"(userAccountControl:{BIT_AND}:=67108864)))", DC_ATTRS)

    def fsmo(self) -> dict[str, str]:
        """Rolle -> DN der NTDS-Einstellungen des Rolleninhabers."""
        holders = {"PDC-Emulator": self.base, "RID-Master": f"CN=RID Manager$,CN=System,{self.base}",
                   "Infrastrukturmaster": f"CN=Infrastructure,{self.base}",
                   "Domänennamenmaster": f"CN=Partitions,{self.config}", "Schemamaster": self.schema}
        out = {}
        for role, dn in holders.items():
            e = self.one(dn, ["fSMORoleOwner"])
            if e and e.str("fSMORoleOwner"):
                out[role] = e.str("fSMORoleOwner")
        return out

    def crossref(self) -> Entry | None:
        """Partitionseintrag der Domäne (NetBIOS-Name, DNS-Name)."""
        found = self.search(f"CN=Partitions,{self.config}",
                            f"(&(objectClass=crossRef)(nCName={escape_value(self.base)}))",
                            ["nETBIOSName", "dnsRoot", "msDS-Behavior-Version"], scope="one")
        return found[0] if found else None

    def forest_level(self) -> int | None:
        e = self.one(f"CN=Partitions,{self.config}", ["msDS-Behavior-Version"])
        return e.int("msDS-Behavior-Version") if e else None

    def trusts(self) -> list[Entry]:
        return self.search(f"CN=System,{self.base}", "(objectClass=trustedDomain)", TRUST_ATTRS, scope="one")

    def psos(self) -> list[Entry]:
        return self.search(f"CN=Password Settings Container,CN=System,{self.base}",
                           "(objectClass=msDS-PasswordSettings)", PSO_ATTRS, scope="one")

    def optional_features(self) -> list[Entry]:
        return self.search(f"CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,{self.config}",
                           "(objectClass=msDS-OptionalFeature)", ["cn", "msDS-EnabledFeatureBL"], scope="one")

    def directory_service(self) -> Entry | None:
        return self.one(f"CN=Directory Service,CN=Windows NT,CN=Services,{self.config}",
                        ["tombstoneLifetime", "msDS-DeletedObjectLifetime", "dSHeuristics"])

    def adminsdholder(self) -> Entry | None:
        return self.one(f"CN=AdminSDHolder,CN=System,{self.base}", ["whenChanged", "nTSecurityDescriptor"], sd=True)

    # --- Konten -----------------------------------------------------------------------------------

    def users(self) -> list[Entry]:
        return self.search(self.base, "(&(objectCategory=person)(objectClass=user))", USER_ATTRS)

    def computers(self) -> list[Entry]:
        laps = [a for a in LAPS_ATTRS if self.schema_has(a)]
        return self.search(self.base, "(objectCategory=computer)", COMPUTER_ATTRS + laps)

    def managed_service_accounts(self) -> list[Entry]:
        return self.search(self.base, "(|(objectClass=msDS-GroupManagedServiceAccount)"
                                      "(objectClass=msDS-ManagedServiceAccount))", MSA_ATTRS)

    def groups_by_sid(self, sids: list[str]) -> list[Entry]:
        flt = sid_filter(sids)
        return self.search(self.base, f"(&(objectClass=group){flt})", GROUP_ATTRS) if flt else []

    def group_by_name(self, name: str) -> Entry | None:
        found = self.search(self.base, f"(&(objectClass=group)(sAMAccountName={escape_value(name)}))", GROUP_ATTRS)
        return found[0] if found else None

    def members(self, group_dn: str) -> list[Entry]:
        """Alle Mitglieder einschließlich verschachtelter Gruppen (ohne Mitgliedschaft über die primäre Gruppe)."""
        return self.search(self.base, f"(memberOf:{IN_CHAIN}:={escape_value(group_dn)})", MEMBER_ATTRS)

    def direct_members(self, group_dn: str) -> list[str]:
        return [v.decode("utf-8", "replace") for v in self.ranged(group_dn, "member")]

    def primary_group_members(self, rid: int) -> list[Entry]:
        return self.search(self.base, f"(primaryGroupID={int(rid)})", MEMBER_ATTRS)

    def resolve_sids(self, sids: list[str]) -> dict[str, Entry]:
        """SID -> Objekt (Benutzer, Gruppe, Computer) in Paketen zu 50."""
        out: dict[str, Entry] = {}
        wanted = sorted({s for s in sids if s.startswith(("S-1-5-21-", "S-1-5-32-"))})
        for i in range(0, len(wanted), 50):
            flt = sid_filter(wanted[i:i + 50])
            if flt:
                for e in self.search(self.base, flt, ["sAMAccountName", "name", "displayName", "objectClass",
                                                      "objectSid"]):
                    out[e.sid()] = e
        return out
