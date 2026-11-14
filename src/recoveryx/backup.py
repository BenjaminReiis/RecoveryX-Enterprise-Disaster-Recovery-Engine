"""Backup: walk the sources, chunk files into the vault and build a snapshot manifest."""
from __future__ import annotations

import hashlib
import os
import secrets
import stat
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from .config import ProtectionSet
from .util import RecoveryXError, is_excluded, join_rel
from .vault import FileEntry, Snapshot, Vault


class BackupError(RecoveryXError):
    """A backup could not be created."""


def new_snapshot_id(now: float) -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(now)) + "-" + secrets.token_hex(3)


def _store_file(vault: Vault, path: Path, chunk_size: int) -> Tuple[str, int, List[str], int, int]:
    hasher = hashlib.sha256()
    chunks: List[str] = []
    size = new_chunks = new_bytes = 0
    with open(path, "rb") as fh:
        while True:
            block = fh.read(chunk_size)
            if not block:
                break
            hasher.update(block)
            size += len(block)
            digest, was_new = vault.put_chunk(block)
            chunks.append(digest)
            if was_new:
                new_chunks += 1
                new_bytes += len(block)
    return hasher.hexdigest(), size, chunks, new_chunks, new_bytes


def create_snapshot(
    vault: Vault,
    pset: ProtectionSet,
    chunk_size: int,
    clock: Callable[[], float] = time.time,
    tags: Optional[List[str]] = None,
    use_cache: bool = True,
) -> Snapshot:
    """Create (but do not save) a snapshot of `pset`.

    Files whose size and mtime match the previous snapshot are not re-read, provided all of
    their chunks are still in the vault. Unreadable files are skipped and recorded.
    """
    started = time.monotonic()
    created = clock()
    previous = vault.list_snapshots(pset.name)
    cache: Dict[Tuple[str, str], FileEntry] = {}
    if use_cache and previous:
        cache = {(f.source, f.path): f for f in previous[-1].files}

    files: List[FileEntry] = []
    skipped: List[str] = []
    new_chunks = new_bytes = reused = 0
    for source in pset.sources:
        if not source.path.is_dir():
            raise BackupError(f"source '{source.name}' not found or not a directory: {source.path}")
        for dirpath, dirnames, filenames in os.walk(source.path):
            rel_dir = Path(dirpath).relative_to(source.path).as_posix()
            rel_dir = "" if rel_dir == "." else rel_dir
            dirnames[:] = sorted(
                d for d in dirnames if not is_excluded(join_rel(rel_dir, d), pset.exclude)
            )
            for name in sorted(filenames):
                rel = join_rel(rel_dir, name)
                if is_excluded(rel, pset.exclude):
                    continue
                full = Path(dirpath) / name
                try:
                    st = os.lstat(full)
                    if not stat.S_ISREG(st.st_mode):
                        continue  # symlinks, sockets, devices
                    mode = stat.S_IMODE(st.st_mode)
                    cached = cache.get((source.name, rel))
                    if (
                        cached
                        and cached.size == st.st_size
                        and cached.mtime_ns == st.st_mtime_ns
                        and all(vault.has_chunk(c) for c in cached.chunks)
                    ):
                        files.append(FileEntry(source.name, rel, mode, st.st_size, st.st_mtime_ns,
                                               cached.sha256, list(cached.chunks)))
                        reused += 1
                        continue
                    sha, size, chunks, n_new, n_bytes = _store_file(vault, full, chunk_size)
                    files.append(FileEntry(source.name, rel, mode, size, st.st_mtime_ns, sha, chunks))
                    new_chunks += n_new
                    new_bytes += n_bytes
                except OSError as exc:
                    skipped.append(f"{source.name}/{rel}: {exc.strerror or exc}")

    if not files:
        raise BackupError(
            f"'{pset.name}': sources contain no readable files; refusing to create an empty "
            "snapshot (is the volume mounted?)"
        )
    stats = {
        "files": len(files),
        "bytes": sum(f.size for f in files),
        "new_chunks": new_chunks,
        "new_bytes": new_bytes,
        "reused_files": reused,
        "seconds": round(time.monotonic() - started, 3),
        "skipped_count": len(skipped),
        "skipped": skipped[:50],
    }
    return Snapshot(
        id=new_snapshot_id(created), set_name=pset.name, created=created, files=files,
        stats=stats, tags=list(tags or []), chunk_size=chunk_size,
    )
