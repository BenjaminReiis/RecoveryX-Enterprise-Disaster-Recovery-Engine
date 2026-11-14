"""Tamper-evident audit log: JSON Lines where every entry is chained to the previous one."""
from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from .util import RecoveryXError, canonical_json, iso_time

try:  # POSIX only: serialise writers across processes
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

GENESIS = "0" * 64


class AuditError(RecoveryXError):
    """The audit log could not be written."""


def _actor() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


class AuditLog:
    """Each entry holds the hash of the previous one. With a key the hashes are HMACs, so the
    chain cannot be recomputed by someone who edits the file but does not hold the key."""

    def __init__(self, path: Path, key: Optional[bytes] = None):
        self.path = Path(path)
        self.key = key
        self._lock = threading.Lock()

    def _digest(self, body: bytes) -> str:
        if self.key:
            return hmac.new(self.key, body, hashlib.sha256).hexdigest()
        return hashlib.sha256(body).hexdigest()

    @staticmethod
    def _tail(fh) -> Tuple[int, str]:
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        if size == 0:
            return 0, GENESIS
        fh.seek(max(0, size - 65536))
        lines = [ln for ln in fh.read().decode("utf-8", "replace").splitlines() if ln.strip()]
        try:
            last = json.loads(lines[-1])
            return int(last["seq"]), str(last["hash"])
        except (IndexError, ValueError, KeyError, TypeError):
            raise AuditError("audit log is corrupt: cannot read the last entry")

    def record(self, action: str, **details: Any) -> Dict[str, Any]:
        with self._lock:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.path, "a+b") as fh:
                    if fcntl is not None:
                        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
                    seq, prev = self._tail(fh)
                    entry: Dict[str, Any] = {
                        "seq": seq + 1, "ts": iso_time(time.time()), "actor": _actor(),
                        "action": action, "details": details, "prev": prev,
                    }
                    entry["hash"] = self._digest(canonical_json(entry))
                    fh.seek(0, os.SEEK_END)
                    fh.write((json.dumps(entry, ensure_ascii=False) + "\n").encode("utf-8"))
                    fh.flush()
                    os.fsync(fh.fileno())
                    return entry
            except OSError as exc:
                raise AuditError(f"cannot write the audit log {self.path}: {exc}")

    def entries(self):
        try:
            text = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return []
        out = []
        for line in text.splitlines():
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
        return out

    def verify(self) -> Tuple[bool, int, Optional[str]]:
        """Returns (ok, entries_checked, error_message)."""
        try:
            text = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return True, 0, None
        prev, count = GENESIS, 0
        for number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                return False, count, f"line {number}: not valid JSON"
            claimed = entry.pop("hash", None)
            if entry.get("prev") != prev:
                return False, count, f"line {number}: chain broken (previous hash does not match)"
            if entry.get("seq") != count + 1:
                return False, count, f"line {number}: sequence number out of order"
            if not isinstance(claimed, str) or not hmac.compare_digest(claimed, self._digest(canonical_json(entry))):
                return False, count, f"line {number}: entry hash mismatch (entry was modified)"
            prev, count = claimed, count + 1
        return True, count, None
