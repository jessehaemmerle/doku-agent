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


class WikiConfig(BaseModel):
    url: str
    api_key: str
    locale: str = "de"
    verify_tls: TlsVerify = True
    # Ziel-Pfade je Dokutyp. Platzhalter in {} werden befüllt und "geslugt".
    paths: dict[str, str] = Field(default_factory=lambda: {
        "netbox_device": "infrastruktur/geraete/{name}",
        "wazuh_rules": "security/wazuh/regeln/{name}",
        "wazuh_decoders": "security/wazuh/decoder/{name}",
        "wazuh_config": "security/wazuh/konfiguration/{name}",
        "wazuh_sca": "security/wazuh/sca/{name}",
        "intune_policy": "clients/intune/{category}/{name}",
        "intune_apps": "clients/intune/apps",
    })
    # Zusätzliche Tags je Dokutyp (gelernte Tags aus dem Wiki kommen dazu).
    tags: dict[str, list[str]] = Field(default_factory=lambda: {
        "netbox_device": ["netbox"],
        "wazuh_rules": ["wazuh"],
        "wazuh_decoders": ["wazuh"],
        "wazuh_config": ["wazuh"],
        "wazuh_sca": ["wazuh", "sca"],
        "intune_policy": ["intune"],
        "intune_apps": ["intune"],
    })
    # Wie viele Seiten pro Bereich zum Lernen der Konventionen gelesen werden.
    convention_sample_pages: int = 5


class NetboxRoleRule(BaseModel):
    os: str = ".*"  # Regex auf Betriebssystem-Name
    role: str  # Slug der Geräterolle


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
    include: list[Literal["compliance", "configurations", "settings_catalog", "apps"]] = Field(
        default_factory=lambda: ["compliance", "configurations", "settings_catalog", "apps"]
    )
    # Ethernet-MAC gibt Graph nur per Einzelabfrage heraus.
    fetch_ethernet_mac: bool = True
    # Welche Betriebssysteme die Netbox-Discovery übernimmt (leer = alle, z.B. auch Handys).
    discovery_os: list[str] = Field(default_factory=lambda: ["Windows", "macOS", "Linux"])


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


class Config(BaseModel):
    general: GeneralConfig = Field(default_factory=GeneralConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    wiki: WikiConfig
    netbox: NetboxConfig = Field(default_factory=NetboxConfig)
    wazuh: WazuhConfig = Field(default_factory=WazuhConfig)
    intune: IntuneConfig = Field(default_factory=IntuneConfig)
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
