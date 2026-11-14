"""Vault: content-addressed, deduplicated, compressed chunk store plus signed snapshot manifests."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import time
import zlib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .util import RecoveryXError, atomic_write, canonical_json

log = logging.getLogger("recoveryx")

HASH_RE = re.compile(r"^[0-9a-f]{64}$")
SNAP_ID_RE = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{6}$")


class VaultError(RecoveryXError):
    """Problem reading or writing the vault (missing, corrupt or tampered data)."""


@dataclass
class FileEntry:
    source: str
    path: str
    mode: int
    size: int
    mtime_ns: int
    sha256: str
    chunks: List[str] = field(default_factory=list)


@dataclass
class Snapshot:
    id: str
    set_name: str
    created: float
    files: List[FileEntry]
    stats: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    chunk_size: int = 0
    version: int = 1

    @property
    def partial(self) -> bool:
        return bool(self.stats.get("skipped_count"))

    @property
    def total_size(self) -> int:
        return sum(f.size for f in self.files)

    def chunk_hashes(self) -> Set[str]:
        return {h for f in self.files for h in f.chunks}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version, "id": self.id, "set": self.set_name,
            "created": self.created, "tags": self.tags, "chunk_size": self.chunk_size,
            "stats": self.stats, "files": [asdict(f) for f in self.files],
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Snapshot":
        try:
            return cls(
                id=d["id"], set_name=d["set"], created=float(d["created"]),
                files=[FileEntry(**f) for f in d["files"]],
                stats=dict(d.get("stats", {})), tags=list(d.get("tags", [])),
                chunk_size=int(d.get("chunk_size", 0)), version=int(d.get("version", 1)),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise VaultError(f"malformed snapshot manifest: {exc}")


class Vault:
    def __init__(self, root: Path, key: Optional[bytes] = None):
        self.root = Path(root)
        self.key = key
        self._chunks = self.root / "chunks"
        self._snaps = self.root / "snapshots"

    # ----------------------------------------------------------------- chunks
    def _chunk_path(self, h: str) -> Path:
        if not isinstance(h, str) or not HASH_RE.match(h):
            raise VaultError(f"invalid chunk hash '{str(h)[:20]}'")
        return self._chunks / h[:2] / h

    def has_chunk(self, h: str) -> bool:
        return self._chunk_path(h).is_file()

    def put_chunk(self, data: bytes) -> Tuple[str, bool]:
        """Store a chunk; returns (sha256, was_new). Identical data is stored only once."""
        h = hashlib.sha256(data).hexdigest()
        path = self._chunk_path(h)
        if path.is_file():
            return h, False
        atomic_write(path, zlib.compress(data, 6))
        return h, True

    def get_chunk(self, h: str) -> bytes:
        """Read a chunk and verify it against its hash."""
        try:
            raw = self._chunk_path(h).read_bytes()
        except FileNotFoundError:
            raise VaultError(f"missing chunk {h[:12]}")
        except OSError as exc:
            raise VaultError(f"cannot read chunk {h[:12]}: {exc}")
        try:
            data = zlib.decompress(raw)
        except zlib.error:
            raise VaultError(f"corrupt chunk {h[:12]} (cannot decompress)")
        if hashlib.sha256(data).hexdigest() != h:
            raise VaultError(f"corrupt chunk {h[:12]} (hash mismatch)")
        return data

    # -------------------------------------------------------------- snapshots
    def _snap_path(self, sid: str) -> Path:
        if not isinstance(sid, str) or not SNAP_ID_RE.match(sid):
            raise VaultError(f"invalid snapshot id '{str(sid)[:30]}'")
        return self._snaps / f"{sid}.json"

    def _sign(self, manifest: Dict[str, Any]) -> Optional[str]:
        if not self.key:
            return None
        return hmac.new(self.key, canonical_json(manifest), hashlib.sha256).hexdigest()

    def has_snapshot(self, sid: str) -> bool:
        return self._snap_path(sid).is_file()

    def save_snapshot(self, snap: Snapshot) -> None:
        manifest = snap.to_dict()
        doc = {"manifest": manifest, "signature": self._sign(manifest)}
        atomic_write(self._snap_path(snap.id), json.dumps(doc).encode("utf-8"))

    def read_raw_snapshot(self, sid: str) -> bytes:
        try:
            return self._snap_path(sid).read_bytes()
        except OSError as exc:
            raise VaultError(f"cannot read snapshot {sid}: {exc}")

    def write_raw_snapshot(self, sid: str, raw: bytes) -> None:
        atomic_write(self._snap_path(sid), raw)

    def load_snapshot(self, sid: str) -> Snapshot:
        raw = self.read_raw_snapshot(sid)
        try:
            doc = json.loads(raw)
            manifest = doc["manifest"]
        except (ValueError, KeyError, TypeError):
            raise VaultError(f"snapshot {sid}: manifest is not valid JSON")
        if self.key:
            signature = doc.get("signature")
            expected = self._sign(manifest)
            if not isinstance(signature, str) or not hmac.compare_digest(signature, expected or ""):
                raise VaultError(f"snapshot {sid}: signature invalid (tampered, unsigned or wrong key)")
        if not isinstance(manifest, dict) or manifest.get("id") != sid:
            raise VaultError(f"snapshot {sid}: manifest id mismatch")
        return Snapshot.from_dict(manifest)

    def list_snapshots(self, set_name: Optional[str] = None, strict: bool = False) -> List[Snapshot]:
        """Snapshots oldest to newest. Unreadable ones are skipped (or raise when strict)."""
        snaps: List[Snapshot] = []
        if self._snaps.is_dir():
            for path in sorted(self._snaps.glob("*.json")):
                try:
                    snap = self.load_snapshot(path.stem)
                except VaultError as exc:
                    if strict:
                        raise
                    log.warning("skipping unreadable snapshot %s: %s", path.name, exc)
                    continue
                if set_name is None or snap.set_name == set_name:
                    snaps.append(snap)
        snaps.sort(key=lambda s: (s.created, s.id))
        return snaps

    def delete_snapshot(self, sid: str) -> None:
        try:
            self._snap_path(sid).unlink()
        except FileNotFoundError:
            pass

    # --------------------------------------------------------------------- gc
    def gc(self, grace_seconds: float = 3600.0, dry_run: bool = False,
           now: Optional[float] = None) -> Tuple[int, int]:
        """Delete chunks no snapshot references. Returns (chunks, bytes).

        Aborts if any snapshot cannot be read (its chunks would look unreferenced), and spares
        chunks younger than `grace_seconds` so a running backup is never hurt.
        """
        referenced: Set[str] = set()
        for snap in self.list_snapshots(strict=True):
            referenced |= snap.chunk_hashes()
        now = time.time() if now is None else now
        removed = freed = 0
        if self._chunks.is_dir():
            for path in self._chunks.rglob("*"):
                if not path.is_file() or path.name.startswith(".tmp-") or path.name in referenced:
                    continue
                stat = path.stat()
                if now - stat.st_mtime < grace_seconds:
                    continue
                removed += 1
                freed += stat.st_size
                if not dry_run:
                    path.unlink()
        return removed, freed
