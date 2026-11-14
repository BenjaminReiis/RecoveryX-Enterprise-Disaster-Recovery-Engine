"""Replication of snapshots and chunks from one vault to another (e.g. the DR site)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from .util import RecoveryXError
from .vault import Vault


@dataclass
class ReplicationResult:
    replica: str
    snapshots: int = 0
    chunks: int = 0
    bytes: int = 0
    errors: List[str] = field(default_factory=list)


def replicate_vault(src: Vault, dst: Vault, set_name: Optional[str] = None) -> ReplicationResult:
    """Copy snapshots missing from `dst`. Chunks are read with verification, so corruption in the
    source is reported instead of being propagated. The manifest is written last, so a replicated
    snapshot is always complete."""
    result = ReplicationResult(str(dst.root))
    for snap in src.list_snapshots(set_name):
        if dst.has_snapshot(snap.id):
            continue
        try:
            for h in sorted(snap.chunk_hashes()):
                if not dst.has_chunk(h):
                    data = src.get_chunk(h)
                    dst.put_chunk(data)
                    result.chunks += 1
                    result.bytes += len(data)
            dst.write_raw_snapshot(snap.id, src.read_raw_snapshot(snap.id))
            result.snapshots += 1
        except RecoveryXError as exc:
            result.errors.append(f"{snap.id}: {exc}")
        except OSError as exc:
            result.errors.append(f"{snap.id}: {exc.strerror or exc}")
    return result
