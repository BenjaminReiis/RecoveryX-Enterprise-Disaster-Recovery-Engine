"""Restore and verify snapshots."""
from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

from .config import NAME_RE
from .util import RecoveryXError
from .vault import Snapshot, Vault, VaultError


class RestoreError(RecoveryXError):
    """A restore failed (for example because of corrupt vault data)."""


class RestoreUsageError(RestoreError):
    """The restore request itself is wrong (unsafe or non-empty target, unknown source)."""


@dataclass
class RestoreResult:
    files: int
    bytes: int
    seconds: float
    target: str


@dataclass
class VerifyResult:
    snapshot: str
    ok: bool
    files: int
    chunks: int
    problems: List[str] = field(default_factory=list)


def _destination(target: Path, source: str, rel: str) -> Path:
    """Map a manifest entry to a path inside `target`, rejecting anything that could escape it."""
    parts = [source] + rel.split("/")
    if not NAME_RE.match(source) or any(p in ("", ".", "..") or "\\" in p for p in parts[1:]):
        raise RestoreUsageError(f"unsafe path in manifest: {source}/{rel}")
    dest = target.joinpath(*parts)
    root = target.resolve()
    resolved = dest.resolve()
    if root != resolved and root not in resolved.parents:
        raise RestoreUsageError(f"path escapes the restore target: {source}/{rel}")
    return dest


def restore_snapshot(
    vault: Vault,
    snap: Snapshot,
    target: Path,
    only: Optional[List[str]] = None,
    overwrite: bool = False,
    clock: Callable[[], float] = time.monotonic,
) -> RestoreResult:
    """Restore into `target/<source>/<path>`, verifying every chunk and every file checksum."""
    start = clock()
    known = {f.source for f in snap.files}
    if only:
        unknown = sorted(set(only) - known)
        if unknown:
            raise RestoreUsageError(f"unknown source(s) in snapshot: {', '.join(unknown)}")
    entries = [f for f in snap.files if not only or f.source in only]
    if not entries:
        raise RestoreUsageError("nothing to restore")
    target = Path(target)
    if target.exists():
        if not target.is_dir():
            raise RestoreUsageError(f"restore target is not a directory: {target}")
        if any(target.iterdir()) and not overwrite:
            raise RestoreUsageError(f"restore target is not empty: {target} (use overwrite to allow)")
    target.mkdir(parents=True, exist_ok=True)

    total = 0
    for f in entries:
        dest = _destination(target, f.source, f.path)
        tmp = dest.with_name(f".{dest.name}.recoveryx-tmp")
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            hasher = hashlib.sha256()
            with open(tmp, "wb") as fh:
                for h in f.chunks:
                    data = vault.get_chunk(h)
                    hasher.update(data)
                    fh.write(data)
            if hasher.hexdigest() != f.sha256:
                raise RestoreError(f"{f.source}/{f.path}: checksum mismatch after restore")
            os.chmod(tmp, f.mode & 0o777)
            os.utime(tmp, ns=(f.mtime_ns, f.mtime_ns))
            os.replace(tmp, dest)
        except VaultError as exc:
            _discard(tmp)
            raise RestoreError(f"{f.source}/{f.path}: {exc}")
        except OSError as exc:
            _discard(tmp)
            raise RestoreError(f"{f.source}/{f.path}: {exc.strerror or exc}")
        except BaseException:
            _discard(tmp)
            raise
        total += f.size
    return RestoreResult(len(entries), total, clock() - start, str(target))


def _discard(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass


def verify_snapshot(vault: Vault, snap: Snapshot, deep: bool = True) -> VerifyResult:
    """Shallow: every chunk exists. Deep: every chunk decompresses and matches its hash, and
    every file's checksum is recomputed from its chunks."""
    problems: List[str] = []
    seen = set()
    for f in snap.files:
        hasher = hashlib.sha256()
        broken = False
        for h in f.chunks:
            try:
                if deep:
                    hasher.update(vault.get_chunk(h))
                elif not vault.has_chunk(h):
                    raise VaultError(f"missing chunk {h[:12]}")
            except VaultError as exc:
                problems.append(f"{f.source}/{f.path}: {exc}")
                broken = True
                break
            seen.add(h)
        if deep and not broken and hasher.hexdigest() != f.sha256:
            problems.append(f"{f.source}/{f.path}: file checksum does not match the manifest")
    return VerifyResult(snap.id, not problems, len(snap.files), len(seen), problems)
