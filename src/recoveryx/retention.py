"""Retention: decide which snapshots to keep (last / daily / weekly / monthly)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Dict, Hashable, List

from .config import Retention
from .vault import Snapshot


def _utc(snap: Snapshot) -> datetime:
    return datetime.fromtimestamp(snap.created, timezone.utc)


def _day(snap: Snapshot) -> Hashable:
    d = _utc(snap)
    return (d.year, d.month, d.day)


def _week(snap: Snapshot) -> Hashable:
    iso = _utc(snap).isocalendar()
    return (iso[0], iso[1])


def _month(snap: Snapshot) -> Hashable:
    d = _utc(snap)
    return (d.year, d.month)


def _newest_per_bucket(newest_first: List[Snapshot], key: Callable[[Snapshot], Hashable], n: int) -> List[str]:
    """Newest snapshot of each of the `n` most recent buckets."""
    kept: List[str] = []
    buckets: List[Hashable] = []
    for snap in newest_first:
        k = key(snap)
        if k in buckets:
            continue
        buckets.append(k)
        if len(buckets) > n:
            break
        kept.append(snap.id)
    return kept


def select_keep(snapshots: List[Snapshot], policy: Retention) -> Dict[str, str]:
    """Return {snapshot_id: reason} for the snapshots to keep.

    With no retention rule configured everything is kept, and the newest snapshot is always kept.
    """
    if not policy.active:
        return {s.id: "no retention policy" for s in snapshots}
    ordered = sorted(snapshots, key=lambda s: (s.created, s.id), reverse=True)
    keep: Dict[str, str] = {}
    if ordered:
        keep[ordered[0].id] = "newest"
    for sid in (s.id for s in ordered[: policy.keep_last]):
        keep.setdefault(sid, "keep_last")
    for sid in _newest_per_bucket(ordered, _day, policy.keep_daily):
        keep.setdefault(sid, "daily")
    for sid in _newest_per_bucket(ordered, _week, policy.keep_weekly):
        keep.setdefault(sid, "weekly")
    for sid in _newest_per_bucket(ordered, _month, policy.keep_monthly):
        keep.setdefault(sid, "monthly")
    return keep
