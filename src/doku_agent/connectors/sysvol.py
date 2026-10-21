"""SYSVOL eines Domänencontrollers per SMB lesen – nur lesend, signiert, ohne DFS-Weiterleitungen.

Es wird ausschließlich die Freigabe SYSVOL des eingetragenen DCs geöffnet (Low-Level-API von smbprotocol;
der High-Level-Client würde DFS-Verweisen zu anderen Servern folgen). Anmeldung per NTLMv2 mit dem
Lesekonto aus ad.username.
"""

from __future__ import annotations

import logging
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime

from doku_agent.config import AdConfig
from doku_agent.egress import EgressGuard

# smbprotocol protokolliert jede Anfrage auf INFO – das würde das Dienstprotokoll fluten
for _name in ("smbprotocol", "spnego"):
    logging.getLogger(_name).setLevel(logging.WARNING)

MAX_FILE = 32 * 1024 * 1024  # größere Dateien gibt es in einer GPO nicht; schützt vor Speicherüberlauf


class SysvolError(RuntimeError):
    pass


class SysvolAccessDenied(SysvolError):
    """Einzelne Datei oder einzelner Ordner nicht lesbar (die Verbindung selbst steht)."""


@dataclass
class DirEntry:
    name: str
    is_dir: bool
    size: int
    modified: datetime | None


def _clean(path: str) -> str:
    """Relativer Pfad innerhalb von SYSVOL, ohne '..' und ohne führenden Trenner."""
    parts = [p for p in path.replace("/", "\\").split("\\") if p and p != "."]
    if any(p == ".." for p in parts):
        raise SysvolError(f"Ungültiger Pfad: {path}")
    return "\\".join(parts)


class SysvolClient:
    def __init__(self, cfg: AdConfig, guard: EgressGuard, server: str):
        self.cfg, self.guard, self.server = cfg, guard, server
        self._conn = self._session = self._tree = None
        self._lock = threading.RLock()

    def _connect(self):
        if self._tree is not None:
            return self._tree
        from smbprotocol.connection import Connection
        from smbprotocol.exceptions import SMBException
        from smbprotocol.session import Session
        from smbprotocol.tree import TreeConnect

        self.guard.check_host(self.server, "SMB")
        try:
            conn = Connection(uuid.uuid4(), self.server, self.cfg.smb_port, require_signing=True)
            conn.connect(timeout=self.cfg.timeout_s)
        except (OSError, SMBException, ValueError) as exc:
            raise SysvolError(f"SMB zu {self.server}:{self.cfg.smb_port} nicht erreichbar: {exc}") from exc
        try:
            session = Session(conn, self.cfg.username, self.cfg.password, require_encryption=False,
                              auth_protocol="ntlm")
            session.connect()
        except Exception as exc:  # LogonFailure, SpnegoError …
            conn.disconnect()
            raise SysvolError(f"SMB-Anmeldung an {self.server} abgelehnt: {exc}. Ist NTLM für das Lesekonto erlaubt?"
                              ) from exc
        try:
            tree = TreeConnect(session, rf"\\{self.server}\SYSVOL")
            tree.connect()
        except SMBException as exc:
            conn.disconnect()
            raise SysvolError(f"Freigabe \\\\{self.server}\\SYSVOL nicht lesbar: {exc}") from exc
        self._conn, self._session, self._tree = conn, session, tree
        return tree

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.disconnect()
                except Exception:
                    pass
            self._conn = self._session = self._tree = None

    def _retry(self, fn):
        from smbprotocol.exceptions import AccessDenied, SMBConnectionClosed, SMBException
        with self._lock:
            for attempt in (1, 2):
                tree = self._connect()
                try:
                    return fn(tree)
                except (SMBConnectionClosed, OSError) as exc:  # Verbindung weg (z.B. Leerlauf): einmal neu
                    self.close()
                    if attempt == 2:
                        raise SysvolError(f"SMB-Verbindung zu {self.server} abgebrochen: {exc}") from exc
                except AccessDenied as exc:
                    raise SysvolAccessDenied(f"Zugriff verweigert: {exc}") from exc
                except SMBException as exc:
                    raise SysvolError(f"SYSVOL: {exc}") from exc

    def read(self, path: str) -> bytes | None:
        """Datei lesen; None, wenn es sie nicht gibt."""
        from smbprotocol.exceptions import ObjectNameNotFound, ObjectPathNotFound
        from smbprotocol.open import (CreateDisposition, CreateOptions, FileAttributes, FilePipePrinterAccessMask,
                                      ImpersonationLevel, Open, ShareAccess)
        name = _clean(path)

        def run(tree):
            f = Open(tree, name)
            try:
                f.create(ImpersonationLevel.Impersonation, FilePipePrinterAccessMask.GENERIC_READ,
                         FileAttributes.FILE_ATTRIBUTE_NORMAL,
                         ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE | ShareAccess.FILE_SHARE_DELETE,
                         CreateDisposition.FILE_OPEN, CreateOptions.FILE_NON_DIRECTORY_FILE)
            except (ObjectNameNotFound, ObjectPathNotFound):
                return None
            try:
                size = f.end_of_file
                if size > MAX_FILE:
                    raise SysvolError(f"{name}: Datei zu groß ({size} Bytes)")
                chunk = max(64 * 1024, min(tree.session.connection.max_read_size, 1024 * 1024))
                data = bytearray()
                while len(data) < size:
                    part = f.read(len(data), min(chunk, size - len(data)))
                    if not part:
                        break
                    data += part
                return bytes(data)
            finally:
                f.close()

        return self._retry(run)

    def listdir(self, path: str) -> list[DirEntry] | None:
        """Verzeichnisinhalt; None, wenn es das Verzeichnis nicht gibt."""
        from smbprotocol.exceptions import NoMoreFiles, NoSuchFile, ObjectNameNotFound, ObjectPathNotFound
        from smbprotocol.file_info import FileInformationClass
        from smbprotocol.open import (CreateDisposition, CreateOptions, DirectoryAccessMask, FileAttributes,
                                      ImpersonationLevel, Open, QueryDirectoryFlags, ShareAccess)
        name = _clean(path)

        def run(tree):
            d = Open(tree, name)
            try:
                d.create(ImpersonationLevel.Impersonation,
                         DirectoryAccessMask.FILE_LIST_DIRECTORY | DirectoryAccessMask.FILE_READ_ATTRIBUTES,
                         FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
                         ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE | ShareAccess.FILE_SHARE_DELETE,
                         CreateDisposition.FILE_OPEN, CreateOptions.FILE_DIRECTORY_FILE)
            except (ObjectNameNotFound, ObjectPathNotFound):
                return None
            out, flags = [], QueryDirectoryFlags.SMB2_RESTART_SCANS
            try:
                while True:
                    try:
                        entries = d.query_directory("*", FileInformationClass.FILE_DIRECTORY_INFORMATION, flags=flags)
                    except (NoMoreFiles, NoSuchFile):
                        break
                    flags = 0
                    for e in entries:
                        filename = e["file_name"].get_value().decode("utf-16-le")
                        if filename in (".", ".."):
                            continue
                        out.append(DirEntry(filename, bool(e["file_attributes"].get_value() & 0x10),
                                            e["end_of_file"].get_value(), e["last_write_time"].get_value()))
            finally:
                d.close()
            return out

        return self._retry(run)

    def find(self, directory: str, name: str) -> str | None:
        """Pfad eines Eintrags ohne Rücksicht auf Groß-/Kleinschreibung (Machine/MACHINE, Registry.pol …)."""
        entries = self.listdir(directory) or []
        hit = next((e.name for e in entries if e.name.lower() == name.lower()), None)
        return f"{_clean(directory)}\\{hit}" if hit else None
