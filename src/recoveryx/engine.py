"""Engine: the facade used by the CLI and the scheduler. Every operation is audited."""
from __future__ import annotations

import json
import logging
import os
import shutil
import tempfile
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

from .audit import AuditLog
from .backup import create_snapshot
from .config import Config, PlanConfig, ProtectionSet
from .plan import PlanReport, PlanRunner
from .replicate import ReplicationResult, replicate_vault
from .restore import (
    RestoreError, RestoreResult, RestoreUsageError, VerifyResult, restore_snapshot, verify_snapshot,
)
from .retention import select_keep
from .util import RecoveryXError, fmt_duration, iso_time, run_shell
from .vault import Snapshot, Vault, VaultError

log = logging.getLogger("recoveryx")


@dataclass
class SetStatus:
    name: str
    state: str  # ok | warning | breach
    snapshots: int
    last_backup: Optional[float]
    age_seconds: Optional[float]
    last_drill: Optional[dict]
    problems: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DrillResult:
    set: str
    snapshot: str
    ok: bool
    seconds: float
    files: int
    bytes: int
    error: str = ""


class Engine:
    def __init__(
        self,
        config: Config,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.cfg = config
        self.clock = clock
        self.sleep = sleep
        self.vault = Vault(config.vault, config.key)
        self.replicas = [Vault(p, config.key) for p in config.replicas]
        self.audit = AuditLog(config.audit_log, config.key)
        self.sets: Dict[str, ProtectionSet] = {s.name: s for s in config.sets}
        self.plans: Dict[str, PlanConfig] = {p.name: p for p in config.plans}
        self._lock = threading.Lock()

    # ----------------------------------------------------------------- helpers
    def _set(self, name: str) -> ProtectionSet:
        if name not in self.sets:
            raise RecoveryXError(f"unknown protection set '{name}'")
        return self.sets[name]

    def _vaults(self) -> List[Vault]:
        return [self.vault] + self.replicas

    def _append_jsonl(self, path: Path, obj: dict) -> None:
        with self._lock:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(obj, ensure_ascii=False) + "\n")

    @staticmethod
    def _read_jsonl(path: Path) -> List[dict]:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return []
        out = []
        for line in lines:
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
        return out

    def resolve_snapshot(self, set_name: str, snapshot_id: Optional[str] = None,
                         before: Optional[float] = None, vault: Optional[Vault] = None) -> Snapshot:
        v = vault or self.vault
        if snapshot_id:
            snap = v.load_snapshot(snapshot_id)
            if snap.set_name != set_name:
                raise RecoveryXError(f"snapshot {snapshot_id} belongs to '{snap.set_name}', not '{set_name}'")
            return snap
        snaps = v.list_snapshots(set_name)
        if before is not None:
            snaps = [s for s in snaps if s.created <= before]
        if not snaps:
            suffix = f" at or before {iso_time(before)}" if before is not None else ""
            raise RecoveryXError(f"no snapshot available for '{set_name}'{suffix}")
        return snaps[-1]

    def check_snapshot_available(self, set_name: str, snapshot_id: Optional[str] = None,
                                 before: Optional[float] = None) -> Optional[str]:
        """None if some vault can serve the snapshot, otherwise a problem description."""
        first: Optional[str] = None
        for vault in self._vaults():
            try:
                self.resolve_snapshot(set_name, snapshot_id, before, vault)
                return None
            except RecoveryXError as exc:
                first = first or str(exc)
        return first

    # --------------------------------------------------------------- operations
    def backup(self, set_name: str, tags: Optional[List[str]] = None) -> Snapshot:
        pset = self._set(set_name)
        try:
            snap = create_snapshot(self.vault, pset, self.cfg.chunk_size, self.clock, tags)
            self.vault.save_snapshot(snap)
        except RecoveryXError as exc:
            self.audit.record("backup_failed", set=set_name, error=str(exc))
            raise
        self.audit.record("backup", set=set_name, snapshot=snap.id, files=snap.stats["files"],
                          bytes=snap.stats["bytes"], new_bytes=snap.stats["new_bytes"], partial=snap.partial)
        return snap

    def restore(self, set_name: str, target, snapshot_id: Optional[str] = None,
                before: Optional[float] = None, only: Optional[List[str]] = None,
                overwrite: bool = False) -> RestoreResult:
        """Restore from the primary vault, falling back to each replica if that fails."""
        self._set(set_name)
        errors: List[str] = []
        for index, vault in enumerate(self._vaults()):
            try:
                snap = self.resolve_snapshot(set_name, snapshot_id, before, vault)
                # a fallback attempt may find our own partial output in the target
                result = restore_snapshot(vault, snap, Path(target), only, overwrite or index > 0)
            except RestoreUsageError as exc:
                self.audit.record("restore_failed", set=set_name, error=str(exc))
                raise
            except RecoveryXError as exc:
                errors.append(f"{vault.root}: {exc}")
                self.audit.record("restore_failed", set=set_name, vault=str(vault.root), error=str(exc))
                log.warning("restore from %s failed: %s", vault.root, exc)
                continue
            self.audit.record("restore", set=set_name, snapshot=snap.id, target=str(target),
                              vault=str(vault.root), files=result.files, bytes=result.bytes,
                              seconds=round(result.seconds, 3))
            return result
        raise RestoreError("restore failed on every vault: " + "; ".join(errors))

    def verify(self, set_name: str, snapshot_id: Optional[str] = None, deep: bool = True,
               vault: Optional[Vault] = None, fallback: bool = False) -> VerifyResult:
        self._set(set_name)
        vaults = [vault] if vault else ([self.vault] + (self.replicas if fallback else []))
        first: Optional[VerifyResult] = None
        for v in vaults:
            try:
                snap = self.resolve_snapshot(set_name, snapshot_id, None, v)
                result = verify_snapshot(v, snap, deep)
            except RecoveryXError as exc:
                result = VerifyResult(snapshot_id or "-", False, 0, 0, [str(exc)])
            first = first or result
            self.audit.record("verify", set=set_name, snapshot=result.snapshot, ok=result.ok,
                              deep=deep, vault=str(v.root))
            if result.ok:
                return result
        assert first is not None
        return first

    def drill(self, set_name: str) -> DrillResult:
        """Restore the latest snapshot into a scratch directory, measure it and clean up."""
        pset = self._set(set_name)
        snap = self.resolve_snapshot(set_name)
        scratch_root = str(self.cfg.scratch_dir) if self.cfg.scratch_dir else None
        if scratch_root:
            Path(scratch_root).mkdir(parents=True, exist_ok=True)
        tmp = Path(tempfile.mkdtemp(prefix="recoveryx-drill-", dir=scratch_root))
        try:
            res = restore_snapshot(self.vault, snap, tmp / "restore")
            outcome = DrillResult(set_name, snap.id, True, round(res.seconds, 3), res.files, res.bytes)
        except RecoveryXError as exc:
            outcome = DrillResult(set_name, snap.id, False, 0.0, 0, 0, str(exc))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        record = {"ts": iso_time(self.clock()), "epoch": self.clock(), **asdict(outcome)}
        self._append_jsonl(self.cfg.vault / "drills.jsonl", record)
        self.audit.record("drill", set=set_name, snapshot=snap.id, ok=outcome.ok,
                          seconds=outcome.seconds, rto_minutes=pset.rto_minutes)
        return outcome

    def replicate(self, set_name: Optional[str] = None) -> List[ReplicationResult]:
        if set_name:
            self._set(set_name)
        results = []
        for replica in self.replicas:
            res = replicate_vault(self.vault, replica, set_name)
            results.append(res)
            self.audit.record("replicate", replica=res.replica, snapshots=res.snapshots,
                              chunks=res.chunks, bytes=res.bytes, errors=res.errors[:5])
        return results

    def prune(self, set_name: Optional[str] = None, dry_run: bool = False) -> List[dict]:
        names = [set_name] if set_name else list(self.sets)
        for name in names:
            self._set(name)
        report = []
        for vault in self._vaults():
            deleted: List[str] = []
            kept = 0
            for name in names:
                snaps = vault.list_snapshots(name)
                keep = select_keep(snaps, self.sets[name].retention)
                for snap in snaps:
                    if snap.id in keep:
                        kept += 1
                    else:
                        deleted.append(snap.id)
                        if not dry_run:
                            vault.delete_snapshot(snap.id)
            entry = {"vault": str(vault.root), "deleted": deleted, "kept": kept,
                     "gc_chunks": 0, "gc_bytes": 0, "gc_error": None}
            if not dry_run:
                try:
                    entry["gc_chunks"], entry["gc_bytes"] = vault.gc(self.cfg.gc_grace_seconds)
                except VaultError as exc:
                    entry["gc_error"] = str(exc)
                    log.warning("garbage collection skipped for %s: %s", vault.root, exc)
                self.audit.record("prune", **entry)
            report.append(entry)
        return report

    # ------------------------------------------------------------------ status
    def status(self) -> List[SetStatus]:
        now = self.clock()
        drills: Dict[str, dict] = {}
        for rec in self._read_jsonl(self.cfg.vault / "drills.jsonl"):
            drills[rec.get("set", "")] = rec  # later records win
        out: List[SetStatus] = []
        for pset in self.cfg.sets:
            snaps = self.vault.list_snapshots(pset.name)
            last = snaps[-1] if snaps else None
            age = (now - last.created) if last else None
            problems: List[str] = []
            warnings: List[str] = []
            if last is None:
                problems.append("no backups exist")
            elif age > pset.rpo_minutes * 60:
                problems.append(f"RPO breached: last backup {fmt_duration(age)} ago "
                                f"(limit {pset.rpo_minutes:g} min)")
            if last is not None and last.partial:
                warnings.append(f"last backup is partial ({last.stats.get('skipped_count')} file(s) skipped)")
            drill = drills.get(pset.name)
            if drill is None:
                warnings.append("no restore drill recorded: recovery time is unverified")
            elif not drill.get("ok"):
                problems.append("last restore drill FAILED")
            elif pset.rto_minutes and drill.get("seconds", 0) > pset.rto_minutes * 60:
                problems.append(f"RTO exceeded in last drill: {fmt_duration(drill['seconds'])} "
                                f"(limit {pset.rto_minutes:g} min)")
            for replica in self.replicas:
                if last is not None and not replica.has_snapshot(last.id):
                    warnings.append(f"replica {replica.root} is behind (missing {last.id})")
            state = "breach" if problems else "warning" if warnings else "ok"
            out.append(SetStatus(pset.name, state, len(snaps), last.created if last else None,
                                 age, drill, problems, warnings))
        return out

    # ------------------------------------------------------------------- plans
    def run_plan(self, name: str, dry_run: bool = False) -> PlanReport:
        plan = self.plans.get(name)
        if plan is None:
            raise RecoveryXError(f"unknown plan '{name}'")
        report = PlanRunner(self, sleep=self.sleep).run(plan, dry_run)
        self.audit.record("plan_dry_run" if dry_run else "plan_run", plan=name, ok=report.ok,
                          seconds=report.seconds, rto_met=report.rto_met, preflight=report.preflight)
        if not dry_run:
            self._append_jsonl(self.cfg.vault / "plan_runs.jsonl", report.to_dict())
        return report

    # ---------------------------------------------------------------- scheduler
    def run_cycle(self) -> List[dict]:
        """One scheduler pass: back up what is due, replicate, prune, evaluate and alert."""
        now = self.clock()
        results: List[dict] = []
        backed_up = False
        for pset in self.cfg.sets:
            entry = {"set": pset.name, "actions": [], "error": None}
            try:
                snaps = self.vault.list_snapshots(pset.name)
                if not snaps or now - snaps[-1].created >= pset.interval_minutes * 60:
                    snap = self.backup(pset.name)
                    backed_up = True
                    entry["actions"].append(f"backup {snap.id}")
            except RecoveryXError as exc:
                entry["error"] = str(exc)
                log.error("backup of '%s' failed: %s", pset.name, exc)
            results.append(entry)
        try:
            for rep in self.replicate():
                if rep.snapshots:
                    results.append({"set": "*", "actions": [f"replicated {rep.snapshots} snapshot(s) to {rep.replica}"],
                                    "error": None})
                for err in rep.errors:
                    results.append({"set": "*", "actions": [], "error": f"replication to {rep.replica}: {err}"})
            if backed_up:
                self.prune()
        except RecoveryXError as exc:
            results.append({"set": "*", "actions": [], "error": str(exc)})
            log.error("maintenance failed: %s", exc)
        self._alert(self.status())
        return results

    def _alert(self, statuses: List[SetStatus]) -> None:
        path = self.cfg.vault / "state.json"
        try:
            previous = json.loads(path.read_text(encoding="utf-8")).get("states", {})
        except (OSError, ValueError):
            previous = {}
        current = {}
        for st in statuses:
            current[st.name] = st.state
            before = previous.get(st.name, "ok")
            if st.state != before and "breach" in (st.state, before):
                message = "; ".join(st.problems) or "back to normal"
                self.audit.record("alert", set=st.name, state=st.state, previous=before, message=message)
                log.warning("ALERT [%s] %s -> %s: %s", st.name, before, st.state, message)
                if self.cfg.alert_command:
                    env = {**os.environ, "RECOVERYX_SET": st.name, "RECOVERYX_STATE": st.state,
                           "RECOVERYX_PREVIOUS": before, "RECOVERYX_MESSAGE": message}
                    res = run_shell(self.cfg.alert_command, 30, env)
                    if not res.ok:
                        log.error("alert command failed: %s", res.output)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"states": current}), encoding="utf-8")
        except OSError as exc:
            log.warning("could not save alert state: %s", exc)
