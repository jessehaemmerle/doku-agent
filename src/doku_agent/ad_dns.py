"""AD-integrierte DNS-Zonen: das binäre dnsRecord-Attribut lesen (MS-DNSP 2.3.2.2) – reiner Parser.

Jeder Wert des mehrwertigen Attributs dnsRecord ist ein DNS_RPC_RECORD: fester Kopf, dann je nach Typ die
Daten. Namen stehen als DNS_COUNT_NAME (längenpräfigierte Labels). Der Zeitstempel sind Stunden seit dem
1.1.1601; 0 bedeutet ein statischer (nicht gealterter) Eintrag.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 0: "ZERO"}


@dataclass
class DnsRecord:
    type: str
    value: str
    ttl: int
    static: bool  # Zeitstempel 0 = statisch (wird nicht gealtert)
    stamp: datetime | None  # letzte Aktualisierung (nur dynamische Einträge)


def _name(data: bytes, pos: int) -> tuple[str, int]:
    """DNS_COUNT_NAME: Länge (1), LabelCount (1), dann längenpräfigierte Labels in 'Länge' Bytes."""
    if pos >= len(data):
        return "", pos
    total = data[pos]
    pos += 2  # Länge + LabelCount überspringen
    end = pos + total
    labels = []
    while pos < end and data[pos] != 0:
        n = data[pos]
        pos += 1
        labels.append(data[pos:pos + n].decode("utf-8", "replace"))
        pos += n
    return ".".join(labels), end


def parse_dns_record(blob: bytes) -> DnsRecord | None:
    """Ein Wert des dnsRecord-Attributs. None bei unbekanntem oder zu kurzem Inhalt."""
    if len(blob) < 24:
        return None
    data_len, rtype = struct.unpack_from("<HH", blob, 0)
    ttl = struct.unpack_from(">I", blob, 12)[0]  # TtlSeconds steht als Big-Endian
    stamp_hours = struct.unpack_from("<I", blob, 20)[0]
    data = blob[24:24 + data_len]
    name = TYPES.get(rtype, f"TYPE{rtype}")
    static = stamp_hours == 0
    stamp = None if static else EPOCH + timedelta(hours=stamp_hours)
    value = _record_value(name, data)
    return DnsRecord(name, value, ttl, static, stamp)


def _record_value(name: str, data: bytes) -> str:
    try:
        if name == "A" and len(data) >= 4:
            return str(ipaddress.IPv4Address(data[:4]))
        if name == "AAAA" and len(data) >= 16:
            return str(ipaddress.IPv6Address(data[:16]))
        if name in ("CNAME", "NS", "PTR"):
            return _name(data, 0)[0]
        if name == "MX" and len(data) >= 2:
            pref = struct.unpack_from(">H", data, 0)[0]
            return f"{pref} {_name(data, 2)[0]}"
        if name == "SRV" and len(data) >= 6:
            prio, weight, port = struct.unpack_from(">HHH", data, 0)
            return f"{_name(data, 6)[0]}:{port} (Priorität {prio}, Gewicht {weight})"
        if name == "TXT":
            out, pos = [], 0
            while pos < len(data):
                n = data[pos]
                pos += 1
                out.append(data[pos:pos + n].decode("utf-8", "replace"))
                pos += n
            return "; ".join(out)
        if name == "SOA" and len(data) >= 20:
            serial, refresh, retry, expire, minimum = struct.unpack_from(">IIIII", data, 0)
            primary, pos = _name(data, 20)
            admin = _name(data, pos)[0]
            return f"primär {primary}, Serien-Nr. {serial}, Refresh {refresh}s, Verantwortlich {admin}"
    except (struct.error, IndexError, ValueError):
        return "(unlesbar)"
    return data.hex(" ")[:40]


# --- dnsProperty (Zoneneigenschaften, MS-DNSP 2.3.2.1) --------------------------------------------

PROP_TYPE = 0x00000001
PROP_ALLOW_UPDATE = 0x00000002
PROP_AGING_STATE = 0x00000040
# Vorgabewerte bei DataLength 0 (MS-DNSP 2.3.2.1.1); für ALLOW_UPDATE nennt die Spezifikation keinen
DEFAULTS = {PROP_TYPE: 1, PROP_AGING_STATE: 0}
ZONE_TYPE = {0: "Cache", 1: "primär", 2: "sekundär", 3: "Stub", 4: "Weiterleitung"}
UPDATE = {0: "keine", 1: "nicht sicher und sicher", 2: "nur sicher"}


def parse_properties(blobs: list[bytes]) -> dict[str, object]:
    """dnsProperty-Werte -> {zone_type, allow_update, aging}.

    Layout: DataLength(4), NameLength(4), Flag(4), Version(4), Id(4), Data(DataLength), Name(1). Die Daten sind
    unterschiedlich breit – ALLOW_UPDATE ist z.B. ein einzelnes Byte –, daher genau DataLength Bytes lesen."""
    out: dict[str, object] = {}
    for blob in blobs:
        if len(blob) < 20:
            continue
        data_len, prop_id = struct.unpack_from("<I", blob, 0)[0], struct.unpack_from("<I", blob, 16)[0]
        if data_len == 0:
            if prop_id not in DEFAULTS:
                continue
            value = DEFAULTS[prop_id]
        else:
            data = blob[20:20 + data_len]
            if len(data) < data_len or data_len > 4:
                continue  # abgeschnitten, oder keine Zahl (Serverlisten, Namen …) – hier nicht gebraucht
            value = int.from_bytes(data, "little")
        if prop_id == PROP_TYPE:
            out["zone_type"] = ZONE_TYPE.get(value, str(value))
        elif prop_id == PROP_ALLOW_UPDATE:
            out["allow_update"] = UPDATE.get(value, str(value))
        elif prop_id == PROP_AGING_STATE:
            out["aging"] = bool(value)
    return out
