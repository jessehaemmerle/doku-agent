"""Konfiguration: YAML-Datei mit ${ENV}-Platzhaltern für Geheimnisse."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, field_validator

_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


class ConfigError(RuntimeError):
    pass


def _expand_env(value):
    """Ersetzt ${VAR} bzw. ${VAR:-default} rekursiv durch Umgebungsvariablen."""
    if isinstance(value, str):
        def repl(match: re.Match) -> str:
            name, default = match.group(1), match.group(2)
            if name in os.environ:
                return os.environ[name]
            if default is not None:
                return default
            raise ConfigError(f"Umgebungsvariable {name} ist nicht gesetzt")

        return _ENV_PATTERN.sub(repl, value)
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    return value


# TLS-Prüfung: true/false oder Pfad zu einem CA-Bundle (interne CA).
TlsVerify = bool | str


class GeneralConfig(BaseModel):
    language: str = "Deutsch"
    data_dir: Path = Path("/data")
    timezone: str = "Europe/Vienna"


class LLMConfig(BaseModel):
    base_url: str = "http://ollama:11434"
    model: str = "qwen3:8b"
    num_ctx: int = 8192
    temperature: float = 0.2
    timeout_s: float = 1800
    keep_alive: str = "10m"
    # Rohtext-Budget pro Prompt in Zeichen (~3 Zeichen pro Token bei Deutsch).
    max_input_chars: int = 12000
    # Obergrenze für die Antwortlänge. Ohne Limit können kleine Modelle (v.a. im JSON-Modus)
    # endlos weitergenerieren.
    max_output_tokens: int = 2048


# Ziel-Pfade je Dokutyp. Platzhalter in {} werden befüllt und "geslugt".
DEFAULT_PATHS = {
    "netbox_device": "infrastruktur/geraete/{name}",
    "wazuh_rules": "security/wazuh/regeln/{name}",
    "wazuh_decoders": "security/wazuh/decoder/{name}",
    "wazuh_config": "security/wazuh/konfiguration/{name}",
    "wazuh_sca": "security/wazuh/sca/{name}",
    "intune_policy": "clients/intune/{category}/{name}",
    "intune_apps": "clients/intune/apps",
    "intune_groups": "clients/intune/gruppen",
    "fortigate": "netzwerk/firewall/{device}/{section}",
    "wiki_lint": "wartung/wiki-lint",
    "coverage": "infrastruktur/abdeckung",
    "entra": "identitaet/entra/{section}",
    "entra_ca": "identitaet/entra/conditional-access/{name}",
}
# Zusätzliche Tags je Dokutyp (gelernte Tags aus dem Wiki kommen dazu).
DEFAULT_TAGS = {
    "netbox_device": ["netbox"],
    "wazuh_rules": ["wazuh"],
    "wazuh_decoders": ["wazuh"],
    "wazuh_config": ["wazuh"],
    "wazuh_sca": ["wazuh", "sca"],
    "intune_policy": ["intune"],
    "intune_apps": ["intune"],
    "intune_groups": ["intune"],
    "fortigate": ["firewall", "fortigate"],
    "wiki_lint": [],
    "coverage": ["netbox"],
    "entra": ["entra"],
    "entra_ca": ["entra", "conditional-access"],
}


class WikiConfig(BaseModel):
    url: str
    api_key: str
    locale: str = "de"
    verify_tls: TlsVerify = True
    paths: dict[str, str] = Field(default_factory=lambda: dict(DEFAULT_PATHS))
    tags: dict[str, list[str]] = Field(default_factory=lambda: {k: list(v) for k, v in DEFAULT_TAGS.items()})
    # Wie viele Seiten pro Bereich zum Lernen der Konventionen gelesen werden.
    convention_sample_pages: int = 5

    @field_validator("paths", "tags", mode="before")
    @classmethod
    def _with_defaults(cls, value, info):
        """Eigene Einträge überschreiben die Standardwerte; Dokutypen neuer Versionen kommen dazu,
        auch wenn die config.yaml nur die älteren auflistet."""
        defaults = DEFAULT_PATHS if info.field_name == "paths" else DEFAULT_TAGS
        return {**defaults, **(value or {})}


class NetboxRoleRule(BaseModel):
    os: str = ".*"  # Regex auf Betriebssystem-Name
    role: str  # Slug der Geräterolle


class NetboxCustomFields(BaseModel):
    """Custom Fields für die feste Zuordnung zu Wazuh/Intune. Fehlen sie in Netbox, schlägt die
    Discovery einmalig vor, sie anzulegen."""
    enabled: bool = True
    wazuh_agent_id: str = "wazuh_agent_id"
    intune_device_id: str = "intune_device_id"
    last_seen: str = "last_seen"  # wird ohne Freigabe gepflegt (einzige Ausnahme)


class NetboxConfig(BaseModel):
    enabled: bool = True
    url: str = ""
    token: str = ""
    verify_tls: TlsVerify = True
    site: str = ""  # Slug des Standorts für neu erkannte Geräte
    status: str = "active"
    roles: list[NetboxRoleRule] = Field(default_factory=lambda: [
        NetboxRoleRule(os=r"(?i)server|linux|ubuntu|debian|red ?hat|rhel|centos|rocky|alma|suse", role="server"),
        NetboxRoleRule(os=".*", role="client"),
    ])
    unknown_manufacturer: str = "Unbekannt"
    unknown_model: str = "Unbekannt"
    vm_serial_patterns: list[str] = Field(default_factory=lambda: [
        r"^VMware-", r"(?i)^parallels", r"(?i)^vbox", r"(?i)^ec2", r"(?i)^google",
    ])
    vm_model_patterns: list[str] = Field(default_factory=lambda: [
        r"(?i)virtual machine", r"(?i)vmware", r"(?i)kvm", r"(?i)qemu", r"(?i)virtualbox", r"(?i)hvm domu",
    ])
    vm_cluster: int | None = None  # Optional: Cluster-ID für neu erkannte VMs
    assign_ips: bool = True
    set_primary_ip: bool = True
    # Abgleich bereits eingetragener Maschinen (leer = aus):
    #   missing  – leere Felder füllen, fehlende Interfaces/MACs/IPs ergänzen
    #   os       – Plattform nach OS-Wechsel, vCPU/RAM von VMs
    #   network  – geänderte IPs, MAC-Wechsel, primäre IP
    #   rename   – neuer Hostname bei gleicher Seriennummer/MAC
    sync: list[Literal["missing", "os", "network", "rename"]] = Field(
        default_factory=lambda: ["missing", "os", "network", "rename"])
    # RAM-Abweichung (in %), ab der eine Anpassung vorgeschlagen wird – das OS meldet etwas weniger als zugewiesen.
    memory_tolerance_percent: int = 10
    custom_fields: NetboxCustomFields = Field(default_factory=NetboxCustomFields)


class WazuhConfig(BaseModel):
    enabled: bool = True
    url: str = ""
    username: str = ""
    password: str = ""
    verify_tls: TlsVerify = True
    rules_dir: str = "etc/rules"
    decoders_dir: str = "etc/decoders"
    # Leere Liste = alle aktiven Agents
    sca_agents: list[str] = Field(default_factory=list)
    document_groups: bool = True


class IntuneConfig(BaseModel):
    enabled: bool = False
    tenant_id: str = ""
    client_id: str = ""
    client_secret: str = ""
    resolve_group_names: bool = True
    # groups = Übersichtsseite der Entra-Gruppen mit Mitgliederzahlen und allen Zuweisungen
    include: list[Literal["compliance", "configurations", "settings_catalog", "apps", "groups"]] = Field(
        default_factory=lambda: ["compliance", "configurations", "settings_catalog", "apps", "groups"]
    )
    # Ethernet-MAC gibt Graph nur per Einzelabfrage heraus.
    fetch_ethernet_mac: bool = True
    # Welche Betriebssysteme die Netbox-Discovery übernimmt (leer = alle, z.B. auch Handys).
    discovery_os: list[str] = Field(default_factory=lambda: ["Windows", "macOS", "Linux"])


class EntraConfig(BaseModel):
    """Entra ID über Microsoft Graph (nur lesend). Zugang leer = derselbe wie bei Intune."""
    enabled: bool = False
    tenant_id: str = ""
    client_id: str = ""
    client_secret: str = ""
    include: list[Literal["conditional_access", "auth_methods", "tenant_settings", "roles", "audit"]] = Field(
        default_factory=lambda: ["conditional_access", "auth_methods", "tenant_settings", "roles", "audit"])
    # Benutzer in Richtlinien und Rollen: Anzeigename + UPN, nur Anzeigename oder nur die Anzahl
    user_names: Literal["name_upn", "name", "count"] = "name_upn"
    # Notfallkonten (UPN oder Objekt-ID): Die Prüfung meldet aktive Richtlinien, die sie nicht ausnehmen
    breakglass: list[str] = Field(default_factory=list)
    max_global_admins: int = 4  # mehr Globale Administratoren meldet die Prüfung


class FortiGateDevice(BaseModel):
    name: str  # Kurzname für Wiki-Pfad und Titel, z.B. fw-zentrale
    url: str  # https://fw.example.local (ggf. mit Admin-Port)
    token: str  # REST-API-Admin mit Profil nur lesend
    verify_tls: TlsVerify = True
    vdoms: list[str] = Field(default_factory=lambda: ["root"])
    netbox_site: str = ""  # Standort in Netbox (Slug); leer = netbox.site


class FortiGateConfig(BaseModel):
    enabled: bool = False
    devices: list[FortiGateDevice] = Field(default_factory=list)
    include: list[Literal["policies", "nat", "objects", "network", "vpn", "audit"]] = Field(
        default_factory=lambda: ["policies", "nat", "objects", "network", "vpn", "audit"])
    # FortiGate -> Netbox: Gerät, Interfaces, IPs, VLANs, Präfixe (alles mit Freigabe)
    netbox_sync: list[Literal["device", "interfaces", "ips", "vlans", "prefixes"]] = Field(
        default_factory=lambda: ["device", "interfaces", "ips", "vlans", "prefixes"])
    netbox_role: str = "firewall"  # Slug der Geräterolle
    netbox_skip_roles: list[str] = Field(default_factory=lambda: ["wan"])  # keine Präfixe für diese Interface-Rollen
    # Steckbrief: Regeln, die eine Maschine über Host-, Bereichs-, VIP- oder Netzobjekte ab dieser Größe betreffen
    steckbrief_rules: bool = True
    steckbrief_min_prefix: int = 24


class VCenterConfig(BaseModel):
    enabled: bool = False
    url: str = ""  # https://vcenter.example.local
    username: str = ""  # Benutzer mit Rolle "Nur lesen"
    password: str = ""
    verify_tls: TlsVerify = True
    # Hardware der ESXi-Hosts (Hersteller, Modell, Seriennummer) gibt es nur über die VI/JSON-API
    # (ab vCenter 8.0 U1). Release-Kennung des vCenters, leer = ohne Hardwaredaten.
    vijson_release: str = "8.0.1.0"
    hosts: bool = True  # ESXi-Hosts als Netbox-Geräte
    host_role: str = "hypervisor"
    powered_off: bool = True  # ausgeschaltete VMs auch anlegen
    virtual_disks: bool = True  # Disks einzeln als virtual-disks
    cluster_type: str = "VMware vSphere"


class SnmpCredentials(BaseModel):
    version: Literal["2c", "3"] = "2c"
    community: str = ""  # v2c
    user: str = ""  # v3
    auth_protocol: Literal["sha", "sha224", "sha256", "sha384", "sha512", "md5"] = "sha256"
    auth_key: str = ""
    priv_protocol: Literal["aes", "aes192", "aes256", "des", "3des", "none"] = "aes"
    priv_key: str = ""
    port: int = 161
    timeout_s: float = 5
    retries: int = 1


class SwitchDevice(BaseModel):
    host: str  # IP oder DNS-Name; nur diese Ziele dürfen per SNMP abgefragt werden
    name: str = ""  # leer = sysName des Switches
    netbox_site: str = ""  # leer = netbox.site
    snmp: SnmpCredentials | None = None  # abweichende Zugangsdaten für diesen Switch


class SwitchesConfig(BaseModel):
    enabled: bool = False
    snmp: SnmpCredentials = Field(default_factory=SnmpCredentials)
    devices: list[SwitchDevice] = Field(default_factory=list)
    netbox_role: str = "switch"
    # Endgeräte über die MAC-Tabelle verkabeln (nur Ports mit genau so vielen bekannten MACs, keine Uplinks)
    mac_table: bool = True
    mac_table_max_macs: int = 1


class EmbeddingsConfig(BaseModel):
    """Lokale Embeddings (über dasselbe Ollama) für semantische Suche und Fragen ans Wiki."""
    enabled: bool = True
    model: str = "qwen3-embedding:0.6b"
    chunk_chars: int = 1500  # Abschnitte werden auf diese Länge (Zeichen) zerlegt
    batch_size: int = 16
    top_k: int = 6  # Auszüge pro Frage
    # Qwen3-Embedding erwartet bei Suchanfragen eine Anweisung; für andere Modelle (z.B. bge-m3) leer lassen.
    query_prefix: str = "Instruct: Given a question, retrieve wiki passages that answer the question\nQuery: "
    keep_alive: str = "30m"


class CoverageConfig(BaseModel):
    """Abdeckungsbericht (nach jeder Discovery): wer hat Wazuh, Intune, einen Netbox-Eintrag, wer meldet sich nicht."""
    enabled: bool = True
    wazuh_roles: list[str] = Field(default_factory=lambda: ["server", "client"])  # Netbox-Rollen (Slug) mit Wazuh-Pflicht
    intune_roles: list[str] = Field(default_factory=lambda: ["client"])
    stale_days: int = 30  # "Funkstille": letzter Kontakt älter als so viele Tage


class LintConfig(BaseModel):
    report_page: bool = True  # Bericht zusätzlich als Wiki-Seite (Vorschlag)
    refresh_stale: bool = True  # veraltete Seiten über den passenden Generator neu vorschlagen
    duplicate_threshold: float = 0.93  # Ähnlichkeit (Embeddings), ab der Seiten als mögliche Dubletten gelten
    exclude_paths: list[str] = Field(default_factory=list)  # Pfad-Präfixe, die nicht geprüft werden
    fix_links: bool = True  # tote Links: eindeutigen Ersatz als Vorschlag (sonst Kandidaten im Bericht)
    suggest_tags: bool = True  # Seiten ohne Tags: Tags aus Bereich bzw. ähnlichen Seiten vorschlagen


class ScheduleEntry(BaseModel):
    job: str
    at: str  # HH:MM in general.timezone
    days: list[int] = Field(default_factory=lambda: [0, 1, 2, 3, 4, 5, 6])  # 0 = Montag

    @field_validator("at")
    @classmethod
    def _check_time(cls, v: str) -> str:
        if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", v):
            raise ValueError("Zeit muss im Format HH:MM sein")
        return v


class WebConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8080
    username: str = "admin"
    password: str = ""


class EgressConfig(BaseModel):
    # Zusätzlich erlaubte Hosts (z.B. wenn ein Dienst Weiterleitungen nutzt).
    extra_allowed_hosts: list[str] = Field(default_factory=list)
    # HTTP(S)_PROXY aus der Umgebung nutzen (z.B. Firmenproxy für Graph).
    trust_env: bool = False


class NarrativeConfig(BaseModel):
    """Fließtext über den Tabellen. Fakten stammen immer aus den Quelldaten; das LLM formuliert nur."""
    enabled: bool = True
    # Zusätzliche Textabschnitte: Überblick im Steckbrief, Bewertung auf Prüfseiten, Überblick auf Übersichtsseiten
    areas: list[Literal["steckbrief", "audit", "overview"]] = Field(
        default_factory=lambda: ["steckbrief", "audit", "overview"])
    length: Literal["detailed", "compact"] = "detailed"
    fact_check: bool = True  # Angaben im Text gegen die Daten prüfen; sonst zweiter Versuch bzw. feste Vorlage


class Config(BaseModel):
    general: GeneralConfig = Field(default_factory=GeneralConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    wiki: WikiConfig
    netbox: NetboxConfig = Field(default_factory=NetboxConfig)
    wazuh: WazuhConfig = Field(default_factory=WazuhConfig)
    intune: IntuneConfig = Field(default_factory=IntuneConfig)
    entra: EntraConfig = Field(default_factory=EntraConfig)
    fortigate: FortiGateConfig = Field(default_factory=FortiGateConfig)
    switches: SwitchesConfig = Field(default_factory=SwitchesConfig)
    vcenter: VCenterConfig = Field(default_factory=VCenterConfig)
    embeddings: EmbeddingsConfig = Field(default_factory=EmbeddingsConfig)
    narrative: NarrativeConfig = Field(default_factory=NarrativeConfig)
    lint: LintConfig = Field(default_factory=LintConfig)
    coverage: CoverageConfig = Field(default_factory=CoverageConfig)
    schedule: list[ScheduleEntry] = Field(default_factory=list)
    web: WebConfig = Field(default_factory=WebConfig)
    egress: EgressConfig = Field(default_factory=EgressConfig)

    @property
    def db_path(self) -> Path:
        return self.general.data_dir / "doku-agent.sqlite3"

    @property
    def upload_dir(self) -> Path:
        return self.general.data_dir / "uploads"


def load_config(path: str | os.PathLike | None = None) -> Config:
    path = Path(path or os.environ.get("DOKU_AGENT_CONFIG", "config.yaml"))
    if not path.exists():
        raise ConfigError(f"Konfigurationsdatei {path} nicht gefunden (siehe config.example.yaml)")
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    try:
        return Config.model_validate(_expand_env(raw))
    except ConfigError:
        raise
    except Exception as exc:  # pydantic.ValidationError mit allen Details
        raise ConfigError(f"Ungültige Konfiguration in {path}:\n{exc}") from exc
