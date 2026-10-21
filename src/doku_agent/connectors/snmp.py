"""SNMP (v2c/v3, nur lesend) für Switches: System, Interfaces, LLDP-Nachbarn und MAC-Tabelle.

Abgefragt werden nur Hosts aus switches.devices und – bei der LLDP-Suche – Adressen in lldp_discovery.networks
(Allowlist wie bei HTTP). Verwendete MIBs:
SNMPv2-MIB (System), IF-MIB, ENTITY-MIB (Seriennummer/Modell), LLDP-MIB (IEEE 802.1AB),
BRIDGE-MIB und Q-BRIDGE-MIB (MAC-Tabelle).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from doku_agent.config import SnmpCredentials
from doku_agent.egress import EgressBlocked, EgressGuard

OIDS = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
}
TABLES = {
    "ifDescr": "1.3.6.1.2.1.2.2.1.2",
    "ifType": "1.3.6.1.2.1.2.2.1.3",
    "ifPhysAddress": "1.3.6.1.2.1.2.2.1.6",
    "ifOperStatus": "1.3.6.1.2.1.2.2.1.8",
    "ifName": "1.3.6.1.2.1.31.1.1.1.1",
    "ifHighSpeed": "1.3.6.1.2.1.31.1.1.1.15",
    "ifAlias": "1.3.6.1.2.1.31.1.1.1.18",
    "entPhysicalClass": "1.3.6.1.2.1.47.1.1.1.1.5",
    "entPhysicalSerialNum": "1.3.6.1.2.1.47.1.1.1.1.11",
    "entPhysicalMfgName": "1.3.6.1.2.1.47.1.1.1.1.12",
    "entPhysicalModelName": "1.3.6.1.2.1.47.1.1.1.1.13",
    "lldpLocPortIdSubtype": "1.0.8802.1.1.2.1.3.7.1.2",
    "lldpLocPortId": "1.0.8802.1.1.2.1.3.7.1.3",
    "lldpLocPortDesc": "1.0.8802.1.1.2.1.3.7.1.4",
    "lldpRemChassisIdSubtype": "1.0.8802.1.1.2.1.4.1.1.4",
    "lldpRemChassisId": "1.0.8802.1.1.2.1.4.1.1.5",
    "lldpRemPortIdSubtype": "1.0.8802.1.1.2.1.4.1.1.6",
    "lldpRemPortId": "1.0.8802.1.1.2.1.4.1.1.7",
    "lldpRemPortDesc": "1.0.8802.1.1.2.1.4.1.1.8",
    "lldpRemSysName": "1.0.8802.1.1.2.1.4.1.1.9",
    "lldpRemSysCapEnabled": "1.0.8802.1.1.2.1.4.1.1.12",
    # Management-Adressen der Nachbarn: die Adresse steckt im Index (Familie, Länge, Oktette)
    "lldpRemManAddrIfSubtype": "1.0.8802.1.1.2.1.4.2.1.3",
    "dot1dBasePortIfIndex": "1.3.6.1.2.1.17.1.4.1.2",
    "dot1dTpFdbPort": "1.3.6.1.2.1.17.4.3.1.2",
    "dot1qTpFdbPort": "1.3.6.1.2.1.17.7.1.2.2.1.2",
}

Index = tuple[int, ...]


class SnmpError(RuntimeError):
    pass


@dataclass
class SnmpData:
    """Rohdaten: Skalare und Tabellen als {Index-Tupel: Wert}; OCTET STRING als bytes."""
    scalars: dict[str, object] = field(default_factory=dict)
    tables: dict[str, dict[Index, object]] = field(default_factory=dict)


def _value(v):
    """pysnmp-Werte in Python-Typen: OCTET STRING -> bytes, Zahlen -> int, OID -> str."""
    cls = type(v).__name__
    if hasattr(v, "asOctets"):
        return v.asOctets()
    if cls in ("ObjectIdentifier", "ObjectName"):
        return str(v)
    try:
        return int(v)
    except (TypeError, ValueError):
        return str(v)


class SnmpClient:
    def __init__(self, host: str, creds: SnmpCredentials, guard: EgressGuard):
        if not guard.allows_snmp(host):
            raise EgressBlocked(f"SNMP zu {host!r} blockiert (nicht in der Allowlist bzw. lldp_discovery.networks)")
        self.host, self.creds = host, creds

    def _check_credentials(self) -> None:
        c = self.creds
        if c.version == "2c" and not c.community:
            raise SnmpError(f"{self.host}: keine SNMP-Community gesetzt (SNMP_COMMUNITY in .env bzw. "
                            f"switches.snmp.community) – ohne Community antwortet kein Switch.")
        if c.version == "3" and not c.user:
            raise SnmpError(f"{self.host}: SNMPv3 ohne Benutzer (switches.snmp.user).")
        for label, key in (("auth_key", c.auth_key), ("priv_key", c.priv_key)):
            if c.version == "3" and key and len(key) < 8:
                raise SnmpError(f"{self.host}: SNMPv3-{label} ist kürzer als 8 Zeichen – das lässt SNMPv3 nicht zu.")

    def _timeout_message(self) -> str:
        c = self.creds
        return (f"{self.host}: keine Antwort per SNMP {'v2c' if c.version == '2c' else 'v3'} auf UDP {c.port} "
                f"({c.retries + 1} Versuche à {c.timeout_s:g} s). Häufigste Ursachen: falsche Community bzw. "
                f"falsche v3-Zugangsdaten (Switches verwerfen solche Anfragen ohne Antwort); SNMP auf dem Switch "
                f"nicht aktiv oder andere Version (v2c/v3); eine ACL auf dem Switch lässt den Agent nicht zu – "
                f"Absender ist die IP des Docker-Hosts; eine Firewall blockiert UDP {c.port}; falsche Adresse.")

    def _auth(self):
        from pysnmp.hlapi.v3arch import asyncio as snmp

        c = self.creds
        if c.version == "2c":
            return snmp.CommunityData(c.community, mpModel=1)
        auth = {"md5": snmp.usmHMACMD5AuthProtocol, "sha": snmp.usmHMACSHAAuthProtocol,
                "sha224": snmp.usmHMAC128SHA224AuthProtocol, "sha256": snmp.usmHMAC192SHA256AuthProtocol,
                "sha384": snmp.usmHMAC256SHA384AuthProtocol, "sha512": snmp.usmHMAC384SHA512AuthProtocol}
        priv = {"aes": snmp.usmAesCfb128Protocol, "aes192": snmp.usmAesCfb192Protocol,
                "aes256": snmp.usmAesCfb256Protocol, "des": snmp.usmDESPrivProtocol,
                "3des": snmp.usm3DESEDEPrivProtocol, "none": snmp.usmNoPrivProtocol}
        has_priv = c.priv_protocol != "none" and c.priv_key
        return snmp.UsmUserData(c.user, authKey=c.auth_key or None, privKey=c.priv_key if has_priv else None,
                                authProtocol=auth[c.auth_protocol] if c.auth_key else snmp.usmNoAuthProtocol,
                                privProtocol=priv[c.priv_protocol] if has_priv else snmp.usmNoPrivProtocol)

    async def _collect(self, tables: dict[str, str]) -> SnmpData:
        from pysnmp.hlapi.v3arch import asyncio as snmp

        engine = snmp.SnmpEngine()
        auth = self._auth()
        target = await snmp.UdpTransportTarget.create((self.host, self.creds.port), timeout=self.creds.timeout_s,
                                                      retries=self.creds.retries)
        data = SnmpData()
        try:
            err, status, _, binds = await snmp.get_cmd(
                engine, auth, target, snmp.ContextData(), *(snmp.ObjectType(snmp.ObjectIdentity(o)) for o in OIDS.values()))
            if err:
                if "timeout" in str(err).lower():
                    raise SnmpError(self._timeout_message())
                raise SnmpError(f"{self.host}: {err}")
            if status:
                raise SnmpError(f"{self.host}: {status.prettyPrint()}")
            for name, (_, value) in zip(OIDS, binds):
                data.scalars[name] = _value(value)
            for name, base in tables.items():
                prefix = tuple(int(x) for x in base.split("."))
                rows: dict[Index, object] = {}
                async for err, status, _, binds in snmp.bulk_walk_cmd(
                        engine, auth, target, snmp.ContextData(), 0, 50,
                        snmp.ObjectType(snmp.ObjectIdentity(base)), lexicographicMode=False):
                    if err or status:
                        break  # Tabelle fehlt auf diesem Gerät (z.B. kein LLDP) – nicht fatal
                    for oid, value in binds:
                        parts = tuple(oid)
                        if parts[:len(prefix)] != prefix:
                            continue
                        rows[parts[len(prefix):]] = _value(value)
                data.tables[name] = rows
        finally:
            engine.close_dispatcher()
        return data

    def collect(self, tables: dict[str, str] | None = None) -> SnmpData:
        """Systemdaten und Tabellen (Standard: alle für den Abgleich; {} = nur Systemdaten)."""
        self._check_credentials()
        try:
            return asyncio.run(self._collect(TABLES if tables is None else tables))
        except SnmpError:
            raise
        except Exception as exc:
            raise SnmpError(f"SNMP-Abfrage von {self.host} fehlgeschlagen: {exc}") from exc
