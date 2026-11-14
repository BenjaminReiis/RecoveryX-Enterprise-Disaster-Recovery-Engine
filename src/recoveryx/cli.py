"""Command line interface."""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from . import __version__
from .config import ConfigError, load_config
from .engine import Engine
from .util import RecoveryXError, fmt_bytes, fmt_duration, parse_time

DEFAULT_EXAMPLE = {
    "vault": "./vault",
    "replicas": [],
    "audit_log": "./audit.jsonl",
    "chunk_size": 1048576,
    "protection_sets": [
        {
            "name": "app-data",
            "sources": [{"name": "data", "path": "./data"}],
            "exclude": ["*.tmp", "cache"],
            "interval_minutes": 60,
            "rpo_minutes": 120,
            "rto_minutes": 30,
            "retention": {"keep_last": 5, "keep_daily": 7, "keep_weekly": 4, "keep_monthly": 6},
        }
    ],
    "plans": [
        {
            "name": "recover-app",
            "rto_minutes": 30,
            "steps": [
                {"name": "restore-data", "type": "restore", "set": "app-data", "target": "./restored"},
                {"name": "verify-data", "type": "verify", "set": "app-data", "depends_on": ["restore-data"]},
                {"name": "announce", "type": "command", "command": "echo recovery finished",
                 "depends_on": ["verify-data"]},
            ],
        }
    ],
}


def _engine(args) -> Engine:
    return Engine(load_config(args.config))


def _ts(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


# ------------------------------------------------------------------- commands
def cmd_init(args) -> int:
    path = Path(args.config)
    if path.exists() and not args.force:
        print(f"error: {path} already exists (use --force to overwrite)", file=sys.stderr)
        return 1
    path.write_text(json.dumps(DEFAULT_EXAMPLE, indent=2) + "\n", encoding="utf-8")
    print(f"created {path}. Edit it, then run: recoveryx validate && recoveryx backup")
    return 0


def cmd_validate(args) -> int:
    cfg = load_config(args.config)
    for s in cfg.sets:
        print(f"[{s.name}] sources={','.join(x.name for x in s.sources)} interval={s.interval_minutes:g}m "
              f"rpo={s.rpo_minutes:g}m rto={'-' if s.rto_minutes is None else f'{s.rto_minutes:g}m'}")
    for p in cfg.plans:
        print(f"[plan {p.name}] {len(p.steps)} step(s)")
    print(f"configuration valid: {len(cfg.sets)} set(s), {len(cfg.plans)} plan(s), "
          f"{len(cfg.replicas)} replica(s), signing {'on' if cfg.key else 'off'}")
    return 0


def cmd_backup(args) -> int:
    engine = _engine(args)
    names = args.sets or list(engine.sets)
    failed = 0
    for name in names:
        try:
            snap = engine.backup(name, args.tag)
        except RecoveryXError as exc:
            print(f"[{name}] FAILED: {exc}", file=sys.stderr)
            failed += 1
            continue
        s = snap.stats
        flag = f" PARTIAL ({s['skipped_count']} skipped)" if snap.partial else ""
        print(f"[{name}] snapshot {snap.id}: {s['files']} files, {fmt_bytes(s['bytes'])}, "
              f"{fmt_bytes(s['new_bytes'])} new, {s['reused_files']} unchanged, {s['seconds']}s{flag}")
        for line in s["skipped"][:10]:
            print(f"    skipped {line}")
    return 1 if failed else 0


def cmd_list(args) -> int:
    engine = _engine(args)
    snaps = engine.vault.list_snapshots(args.set)
    if not snaps:
        print("no snapshots")
        return 0
    print(f"{'ID':<24} {'CREATED (UTC)':<20} {'SET':<16} {'FILES':>6} {'SIZE':>10}  FLAGS")
    for s in snaps:
        flags = ",".join(filter(None, ["partial" if s.partial else "", *s.tags]))
        print(f"{s.id:<24} {_ts(s.created):<20} {s.set_name:<16} {len(s.files):>6} "
              f"{fmt_bytes(s.total_size):>10}  {flags}")
    return 0


def cmd_verify(args) -> int:
    engine = _engine(args)
    vaults = [("primary", None)] + ([(str(r.root), r) for r in engine.replicas] if args.replicas else [])
    bad = 0
    for label, vault in vaults:
        res = engine.verify(args.set, args.snapshot, deep=not args.shallow, vault=vault)
        state = "OK" if res.ok else "FAILED"
        print(f"[{label}] {res.snapshot}: {state} ({res.files} files, {res.chunks} chunks, "
              f"{'shallow' if args.shallow else 'deep'})")
        for problem in res.problems[:20]:
            print(f"    {problem}")
        bad += 0 if res.ok else 1
    return 1 if bad else 0


def cmd_restore(args) -> int:
    engine = _engine(args)
    before = parse_time(args.before) if args.before else None
    result = engine.restore(args.set, args.target, args.snapshot, before, args.only, args.overwrite)
    print(f"restored {result.files} file(s), {fmt_bytes(result.bytes)} into {result.target} "
          f"in {fmt_duration(result.seconds)}")
    return 0


def cmd_drill(args) -> int:
    engine = _engine(args)
    res = engine.drill(args.set)
    if res.ok:
        print(f"[{args.set}] drill OK: snapshot {res.snapshot}, {res.files} files, "
              f"{fmt_bytes(res.bytes)} restored in {fmt_duration(res.seconds)}")
        return 0
    print(f"[{args.set}] drill FAILED: {res.error}", file=sys.stderr)
    return 1


def cmd_replicate(args) -> int:
    engine = _engine(args)
    if not engine.replicas:
        print("no replicas configured")
        return 0
    failed = 0
    for res in engine.replicate(args.set):
        print(f"[{res.replica}] {res.snapshots} snapshot(s), {res.chunks} chunk(s), {fmt_bytes(res.bytes)} copied")
        for err in res.errors:
            print(f"    ERROR {err}")
        failed += len(res.errors)
    return 1 if failed else 0


def cmd_prune(args) -> int:
    engine = _engine(args)
    for entry in engine.prune(args.set, args.dry_run):
        verb = "would delete" if args.dry_run else "deleted"
        print(f"[{entry['vault']}] {verb} {len(entry['deleted'])} snapshot(s), kept {entry['kept']}"
              + ("" if args.dry_run else f", freed {entry['gc_chunks']} chunk(s) ({fmt_bytes(entry['gc_bytes'])})"))
        if entry["gc_error"]:
            print(f"    garbage collection skipped: {entry['gc_error']}")
    return 0


def cmd_status(args) -> int:
    engine = _engine(args)
    statuses = engine.status()
    if args.json:
        print(json.dumps([s.to_dict() for s in statuses], indent=2))
    else:
        for st in statuses:
            age = "never" if st.age_seconds is None else f"{fmt_duration(st.age_seconds)} ago"
            drill = "no drill" if not st.last_drill else (
                f"drill {'ok' if st.last_drill.get('ok') else 'FAILED'} in {fmt_duration(st.last_drill.get('seconds', 0))}")
            print(f"[{st.name}] {st.state.upper()}: last backup {age}, {st.snapshots} snapshot(s), {drill}")
            for p in st.problems:
                print(f"    PROBLEM: {p}")
            for w in st.warnings:
                print(f"    warning: {w}")
    return 1 if any(s.state == "breach" for s in statuses) else 0


def cmd_plans(args) -> int:
    cfg = load_config(args.config)
    for p in cfg.plans:
        print(f"{p.name}: {len(p.steps)} step(s)" + (f", RTO {p.rto_minutes:g} min" if p.rto_minutes else ""))
    return 0


def cmd_plan(args) -> int:
    engine = _engine(args)
    report = engine.run_plan(args.name, args.dry_run)
    title = "DRY RUN" if report.dry_run else ("SUCCEEDED" if report.ok else "FAILED")
    print(f"plan '{report.plan}' {title} in {fmt_duration(report.seconds)}")
    for problem in report.preflight:
        print(f"  preflight: {problem}")
    for r in report.steps:
        extra = f" x{r.attempts}" if r.attempts > 1 else ""
        print(f"  {r.status:<10} {r.name}{extra}: {r.detail}")
    for r in report.rollbacks:
        print(f"  {r.status:<15} {r.name}: {r.detail}")
    if report.rto_met is not None:
        print(f"  RTO target {fmt_duration(report.rto_seconds or 0)}: {'met' if report.rto_met else 'EXCEEDED'}")
    return 0 if report.ok else 1


def cmd_run(args) -> int:
    engine = _engine(args)
    interval = args.interval
    while True:
        for entry in engine.run_cycle():
            for action in entry["actions"]:
                print(f"[{entry['set']}] {action}")
            if entry["error"]:
                print(f"[{entry['set']}] ERROR {entry['error']}", file=sys.stderr)
        if args.once:
            return 0
        try:
            time.sleep(interval)
        except KeyboardInterrupt:
            print("\nstopped")
            return 0


def cmd_audit_verify(args) -> int:
    engine = _engine(args)
    ok, count, error = engine.audit.verify()
    if ok:
        print(f"audit log intact: {count} entries")
        return 0
    print(f"AUDIT LOG TAMPERED OR CORRUPT after {count} valid entries: {error}", file=sys.stderr)
    return 1


# --------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="recoveryx", description="Enterprise disaster recovery engine.")
    p.add_argument("-c", "--config", default="recoveryx.json", help="configuration file")
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    p.add_argument("--version", action="version", version=f"recoveryx {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("init", help="write an example configuration")
    s.add_argument("--force", action="store_true")
    sub.add_parser("validate", help="validate the configuration")
    s = sub.add_parser("backup", help="create snapshots (all sets by default)")
    s.add_argument("sets", nargs="*")
    s.add_argument("--tag", action="append", default=[])
    s = sub.add_parser("list", help="list snapshots")
    s.add_argument("set", nargs="?")
    s = sub.add_parser("verify", help="check the integrity of a snapshot")
    s.add_argument("set")
    s.add_argument("--snapshot")
    s.add_argument("--shallow", action="store_true", help="only check that chunks exist")
    s.add_argument("--replicas", action="store_true", help="also verify every replica")
    s = sub.add_parser("restore", help="restore a snapshot into a directory")
    s.add_argument("set")
    s.add_argument("target")
    s.add_argument("--snapshot")
    s.add_argument("--before", help="newest snapshot at or before this ISO 8601 time")
    s.add_argument("--only", action="append", help="restore only this source (repeatable)")
    s.add_argument("--overwrite", action="store_true", help="allow a non-empty target")
    s = sub.add_parser("drill", help="restore the latest snapshot to scratch space and measure it")
    s.add_argument("set")
    s = sub.add_parser("replicate", help="copy snapshots to the replica vaults")
    s.add_argument("set", nargs="?")
    s = sub.add_parser("prune", help="apply retention and free unused chunks")
    s.add_argument("set", nargs="?")
    s.add_argument("--dry-run", action="store_true")
    s = sub.add_parser("status", help="RPO/RTO compliance (exit code 1 on breach)")
    s.add_argument("--json", action="store_true")
    sub.add_parser("plans", help="list recovery plans")
    s = sub.add_parser("plan", help="run a recovery plan")
    s.add_argument("name")
    s.add_argument("--dry-run", action="store_true")
    s = sub.add_parser("run", help="scheduler: back up, replicate, prune and alert continuously")
    s.add_argument("--once", action="store_true")
    s.add_argument("--interval", type=float, default=60.0, help="seconds between cycles")
    sub.add_parser("audit-verify", help="verify the audit log hash chain")
    return p


COMMANDS = {
    "init": cmd_init, "validate": cmd_validate, "backup": cmd_backup, "list": cmd_list,
    "verify": cmd_verify, "restore": cmd_restore, "drill": cmd_drill, "replicate": cmd_replicate,
    "prune": cmd_prune, "status": cmd_status, "plans": cmd_plans, "plan": cmd_plan,
    "run": cmd_run, "audit-verify": cmd_audit_verify,
}


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    try:
        return COMMANDS[args.command](args)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2
    except RecoveryXError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
