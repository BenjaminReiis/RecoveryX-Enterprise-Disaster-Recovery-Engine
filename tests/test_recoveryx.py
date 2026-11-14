import json
import os
import shutil
import tempfile
import threading
import unittest
import zlib
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from recoveryx.audit import AuditLog
from recoveryx.backup import BackupError
from recoveryx.cli import main
from recoveryx.config import ConfigError, Retention, parse_config, step_levels
from recoveryx.engine import Engine
from recoveryx.restore import RestoreError, RestoreUsageError
from recoveryx.retention import select_keep
from recoveryx.util import RecoveryXError
from recoveryx.vault import FileEntry, Snapshot, Vault, VaultError

T0 = 1_700_000_000.0


class FakeClock:
    def __init__(self, t=T0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


def put(path: Path, content="x", mode=None, binary=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    if binary:
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")
    if mode is not None:
        os.chmod(path, mode)


def chunk_files(vault: Vault):
    return sorted(p for p in (vault.root / "chunks").rglob("*") if p.is_file())


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.data = self.tmp / "data"
        self.etc = self.tmp / "etc"
        put(self.data / "a.txt", "alpha content, long enough to span chunks")
        put(self.data / "sub/b.txt", "bravo")
        put(self.data / "run.sh", "#!/bin/sh\necho hi\n", mode=0o755)
        put(self.etc / "app.conf", "setting=1")
        self.clock = FakeClock()

    def raw(self, **overrides):
        raw = {
            "vault": "vault", "replicas": ["replica"], "audit_log": "audit.jsonl",
            "chunk_size": 8, "gc_grace_seconds": 0,
            "protection_sets": [{
                "name": "app",
                "sources": [{"name": "data", "path": "data"}, {"name": "etc", "path": "etc"}],
                "exclude": ["*.tmp"], "interval_minutes": 60, "rpo_minutes": 120, "rto_minutes": 30,
                "retention": {"keep_last": 2},
            }],
        }
        raw.update(overrides)
        return raw

    def engine(self, **overrides):
        return Engine(parse_config(self.raw(**overrides), self.tmp), clock=self.clock, sleep=lambda s: None)


# ------------------------------------------------------------------------ vault
class TestVault(Base):
    def test_chunk_dedup_and_corruption(self):
        v = Vault(self.tmp / "v")
        h, new = v.put_chunk(b"hello")
        self.assertTrue(new)
        self.assertEqual(v.put_chunk(b"hello"), (h, False))
        self.assertEqual(v.get_chunk(h), b"hello")
        path = v.root / "chunks" / h[:2] / h
        path.write_bytes(zlib.compress(b"other"))
        with self.assertRaisesRegex(VaultError, "hash mismatch"):
            v.get_chunk(h)
        path.write_bytes(b"garbage")
        with self.assertRaisesRegex(VaultError, "decompress"):
            v.get_chunk(h)
        path.unlink()
        with self.assertRaisesRegex(VaultError, "missing"):
            v.get_chunk(h)
        with self.assertRaises(VaultError):
            v.get_chunk("../../etc/passwd")

    def test_snapshot_signature(self):
        key = b"k" * 16
        eng = self.engine()
        eng.vault.key = key
        snap = eng.backup("app")
        v = Vault(eng.vault.root, key)
        self.assertEqual(v.load_snapshot(snap.id).id, snap.id)
        with self.assertRaisesRegex(VaultError, "signature"):
            Vault(eng.vault.root, b"wrong-key-0000000").load_snapshot(snap.id)
        path = v.root / "snapshots" / f"{snap.id}.json"
        doc = json.loads(path.read_text())
        doc["manifest"]["created"] += 1
        path.write_text(json.dumps(doc))
        with self.assertRaisesRegex(VaultError, "signature"):
            v.load_snapshot(snap.id)
        self.assertEqual(v.list_snapshots(), [])  # unreadable snapshots are skipped...
        with self.assertRaises(VaultError):
            v.list_snapshots(strict=True)  # ...unless strict

    def test_gc_grace_and_strict(self):
        eng = self.engine()
        snap = eng.backup("app")
        self.assertTrue(chunk_files(eng.vault))
        eng.vault.delete_snapshot(snap.id)
        self.assertEqual(eng.vault.gc(grace_seconds=3600)[0], 0)  # too young
        self.assertEqual(eng.vault.gc(grace_seconds=3600, dry_run=True, now=10**11)[0] > 0, True)
        removed, freed = eng.vault.gc(grace_seconds=0)
        self.assertGreater(removed, 0)
        self.assertGreater(freed, 0)
        self.assertEqual(chunk_files(eng.vault), [])
        eng.backup("app")
        (eng.vault.root / "snapshots" / "20200101T000000Z-aaaaaa.json").write_text("not json")
        with self.assertRaises(VaultError):  # an unreadable snapshot must stop GC
            eng.vault.gc(grace_seconds=0)


# ----------------------------------------------------------------------- backup
class TestBackup(Base):
    def test_incremental_dedup(self):
        eng = self.engine()
        first = eng.backup("app")
        self.assertEqual(first.stats["files"], 4)
        self.clock.advance(60)
        second = eng.backup("app")
        self.assertEqual(second.stats["new_chunks"], 0)
        self.assertEqual(second.stats["reused_files"], 4)
        put(self.data / "sub/b.txt", "bravo changed")
        self.clock.advance(60)
        third = eng.backup("app")
        self.assertEqual(third.stats["reused_files"], 3)
        self.assertGreater(third.stats["new_chunks"], 0)

    def test_exclude_and_symlinks(self):
        put(self.data / "junk.tmp", "zzz")
        put(self.data / "cache.tmp/inner.txt", "zzz")
        if os.name == "posix":
            os.symlink(self.data / "a.txt", self.data / "link")
        snap = self.engine().backup("app")
        paths = {f"{f.source}/{f.path}" for f in snap.files}
        self.assertEqual(paths, {"data/a.txt", "data/sub/b.txt", "data/run.sh", "etc/app.conf"})

    def test_refuses_empty_or_missing_source(self):
        empty = self.tmp / "empty"
        empty.mkdir()
        eng = self.engine(protection_sets=[{"name": "e", "sources": [{"name": "d", "path": "empty"}]}])
        with self.assertRaisesRegex(BackupError, "empty snapshot"):
            eng.backup("e")
        eng = self.engine(protection_sets=[{"name": "m", "sources": [{"name": "d", "path": "nope"}]}])
        with self.assertRaisesRegex(BackupError, "not found"):
            eng.backup("m")
        self.assertIn("backup_failed", [e["action"] for e in eng.audit.entries()])

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() != 0,
                         "needs POSIX permissions and a non-root user")
    def test_unreadable_file_is_skipped_and_flagged(self):
        locked = self.data / "locked.txt"
        put(locked, "secret", mode=0o000)
        self.addCleanup(os.chmod, locked, 0o600)
        snap = self.engine().backup("app")
        self.assertTrue(snap.partial)
        self.assertEqual(snap.stats["skipped_count"], 1)
        self.assertIn("locked.txt", snap.stats["skipped"][0])


# ---------------------------------------------------------------------- restore
class TestRestore(Base):
    def test_roundtrip_preserves_content_mode_and_mtime(self):
        eng = self.engine()
        eng.backup("app")
        out = self.tmp / "out"
        res = eng.restore("app", out)
        self.assertEqual(res.files, 4)
        self.assertEqual((out / "data/a.txt").read_text(), (self.data / "a.txt").read_text())
        self.assertEqual((out / "etc/app.conf").read_text(), "setting=1")
        if os.name == "posix":
            self.assertEqual(os.stat(out / "data/run.sh").st_mode & 0o777, 0o755)
        self.assertEqual(os.stat(out / "data/a.txt").st_mtime_ns, os.stat(self.data / "a.txt").st_mtime_ns)

    def test_large_multichunk_binary_file(self):
        blob = os.urandom(1000)
        put(self.data / "blob.bin", blob, binary=True)
        eng = self.engine()
        snap = eng.backup("app")
        entry = next(f for f in snap.files if f.path == "blob.bin")
        self.assertEqual(len(entry.chunks), 125)
        eng.restore("app", self.tmp / "out")
        self.assertEqual((self.tmp / "out/data/blob.bin").read_bytes(), blob)

    def test_target_must_be_empty_unless_overwrite(self):
        eng = self.engine()
        eng.backup("app")
        out = self.tmp / "out"
        put(out / "existing.txt", "keep me")
        with self.assertRaisesRegex(RestoreUsageError, "not empty"):
            eng.restore("app", out)
        eng.restore("app", out, overwrite=True)
        self.assertTrue((out / "existing.txt").exists())
        self.assertTrue((out / "data/a.txt").exists())

    def test_only_and_unknown_source(self):
        eng = self.engine()
        eng.backup("app")
        eng.restore("app", self.tmp / "out", only=["etc"])
        self.assertTrue((self.tmp / "out/etc/app.conf").exists())
        self.assertFalse((self.tmp / "out/data").exists())
        with self.assertRaisesRegex(RestoreUsageError, "unknown source"):
            eng.restore("app", self.tmp / "out2", only=["nope"])

    def test_point_in_time_and_specific_snapshot(self):
        eng = self.engine()
        old = eng.backup("app")
        self.clock.advance(3600)
        put(self.data / "a.txt", "NEW VERSION of the file")
        eng.backup("app")
        eng.restore("app", self.tmp / "past", before=T0 + 10)
        self.assertIn("alpha", (self.tmp / "past/data/a.txt").read_text())
        eng.restore("app", self.tmp / "latest")
        self.assertIn("NEW VERSION", (self.tmp / "latest/data/a.txt").read_text())
        eng.restore("app", self.tmp / "byid", snapshot_id=old.id)
        self.assertIn("alpha", (self.tmp / "byid/data/a.txt").read_text())
        with self.assertRaisesRegex(RecoveryXError, "no snapshot available"):
            eng.restore("app", self.tmp / "ancient", before=T0 - 1000)

    def test_manifest_path_traversal_is_rejected(self):
        eng = self.engine()
        h, _ = eng.vault.put_chunk(b"evil")
        snap = Snapshot("20260101T000000Z-abcdef", "app", T0,
                        [FileEntry("data", "../evil.txt", 0o644, 4, 0, __import__("hashlib").sha256(b"evil").hexdigest(), [h])])
        eng.vault.save_snapshot(snap)
        with self.assertRaisesRegex(RestoreUsageError, "unsafe path"):
            eng.restore("app", self.tmp / "out")
        self.assertFalse((self.tmp / "evil.txt").exists())

    def test_corrupt_primary_falls_back_to_replica(self):
        eng = self.engine()
        eng.backup("app")
        eng.replicate()
        victim = chunk_files(eng.vault)[0]
        victim.write_bytes(zlib.compress(b"corrupted!"))
        res = eng.restore("app", self.tmp / "out")
        self.assertEqual(res.files, 4)
        self.assertEqual((self.tmp / "out/data/a.txt").read_text(), (self.data / "a.txt").read_text())
        actions = [e["action"] for e in eng.audit.entries()]
        self.assertIn("restore_failed", actions)
        self.assertEqual(actions[-1], "restore")

    def test_corrupt_without_replica_fails(self):
        eng = self.engine(replicas=[])
        eng.backup("app")
        chunk_files(eng.vault)[0].write_bytes(zlib.compress(b"corrupted!"))
        with self.assertRaises(RestoreError):
            eng.restore("app", self.tmp / "out")

    def test_usage_error_never_falls_back_to_overwrite(self):
        eng = self.engine()
        eng.backup("app")
        eng.replicate()
        out = self.tmp / "out"
        put(out / "precious.txt", "do not touch")
        with self.assertRaises(RestoreUsageError):
            eng.restore("app", out)
        self.assertEqual(os.listdir(out), ["precious.txt"])


# ----------------------------------------------------------------------- verify
class TestVerify(Base):
    def test_deep_and_shallow(self):
        eng = self.engine()
        eng.backup("app")
        self.assertTrue(eng.verify("app").ok)
        files = chunk_files(eng.vault)
        files[0].write_bytes(zlib.compress(b"bit rot"))
        self.assertFalse(eng.verify("app", deep=True).ok)
        self.assertTrue(eng.verify("app", deep=False).ok)  # exists, so shallow passes
        files[1].unlink()
        shallow = eng.verify("app", deep=False)
        self.assertFalse(shallow.ok)
        self.assertIn("missing chunk", shallow.problems[0])

    def test_fallback_uses_replica(self):
        eng = self.engine()
        eng.backup("app")
        eng.replicate()
        chunk_files(eng.vault)[0].unlink()
        self.assertFalse(eng.verify("app").ok)
        self.assertTrue(eng.verify("app", fallback=True).ok)


# -------------------------------------------------------------------- retention
def snap_at(year, month, day, hour=10, n=[0]):
    n[0] += 1
    ts = datetime(year, month, day, hour, tzinfo=timezone.utc).timestamp()
    return Snapshot(f"s{n[0]:03d}", "app", ts, [])


class TestRetention(Base):
    def test_no_policy_keeps_everything(self):
        snaps = [snap_at(2026, 11, d) for d in range(1, 5)]
        self.assertEqual(set(select_keep(snaps, Retention())), {s.id for s in snaps})

    def test_last_and_daily(self):
        d1a, d1b = snap_at(2026, 11, 1, 10), snap_at(2026, 11, 1, 18)
        d2, d3 = snap_at(2026, 11, 2), snap_at(2026, 11, 3)
        d4a, d4b = snap_at(2026, 11, 4, 8), snap_at(2026, 11, 4, 20)
        snaps = [d1a, d1b, d2, d3, d4a, d4b]
        keep = select_keep(snaps, Retention(keep_last=1, keep_daily=2))
        self.assertEqual(set(keep), {d4b.id, d3.id})
        self.assertEqual(keep[d4b.id], "newest")

    def test_weekly_and_monthly(self):
        oct5, oct20 = snap_at(2026, 10, 5), snap_at(2026, 10, 20)
        nov3, nov10 = snap_at(2026, 11, 3), snap_at(2026, 11, 10)
        snaps = [oct5, oct20, nov3, nov10]
        self.assertEqual(set(select_keep(snaps, Retention(keep_monthly=2))), {oct20.id, nov10.id})
        self.assertEqual(set(select_keep(snaps, Retention(keep_weekly=3))), {nov10.id, nov3.id, oct20.id})

    def test_prune_applies_policy_and_frees_chunks(self):
        eng = self.engine()
        for i in range(4):
            put(self.data / "a.txt", f"version {i} " * 5)
            eng.backup("app")
            self.clock.advance(3600)
        before = len(chunk_files(eng.vault))
        dry = eng.prune("app", dry_run=True)
        self.assertEqual(len(dry[0]["deleted"]), 2)
        self.assertEqual(len(eng.vault.list_snapshots()), 4)
        report = eng.prune("app")
        self.assertEqual(len(report[0]["deleted"]), 2)
        self.assertEqual(len(eng.vault.list_snapshots()), 2)
        self.assertLess(len(chunk_files(eng.vault)), before)
        self.assertGreater(report[0]["gc_chunks"], 0)
        self.assertTrue(eng.verify("app").ok)  # what remains is intact


# ------------------------------------------------------------------ replication
class TestReplication(Base):
    def test_replicates_idempotently_and_replica_is_usable(self):
        eng = self.engine()
        eng.backup("app")
        first = eng.replicate()[0]
        self.assertEqual(first.snapshots, 1)
        self.assertGreater(first.chunks, 0)
        again = eng.replicate()[0]
        self.assertEqual((again.snapshots, again.chunks), (0, 0))
        self.assertTrue(eng.verify("app", vault=eng.replicas[0]).ok)

    def test_corruption_is_not_propagated(self):
        eng = self.engine()
        eng.backup("app")
        chunk_files(eng.vault)[0].write_bytes(zlib.compress(b"rot"))
        res = eng.replicate()[0]
        self.assertEqual(res.snapshots, 0)
        self.assertTrue(res.errors)
        self.assertEqual(eng.replicas[0].list_snapshots(), [])


# ------------------------------------------------------------------------ audit
class TestAudit(Base):
    def test_chain_detects_edits_and_deletions(self):
        path = self.tmp / "audit.jsonl"
        log = AuditLog(path)
        for i in range(4):
            log.record("event", n=i)
        self.assertEqual(log.verify(), (True, 4, None))
        lines = path.read_text().splitlines()
        edited = json.loads(lines[1])
        edited["details"]["n"] = 99
        path.write_text("\n".join([lines[0], json.dumps(edited), *lines[2:]]) + "\n")
        ok, count, err = log.verify()
        self.assertFalse(ok)
        self.assertEqual(count, 1)
        self.assertIn("modified", err)
        path.write_text("\n".join([lines[0], lines[2], lines[3]]) + "\n")
        self.assertFalse(log.verify()[0])

    def test_new_instance_continues_the_chain(self):
        path = self.tmp / "audit.jsonl"
        AuditLog(path).record("a")
        AuditLog(path).record("b")
        self.assertEqual(AuditLog(path).verify(), (True, 2, None))

    def test_hmac_requires_the_key(self):
        path = self.tmp / "audit.jsonl"
        log = AuditLog(path, key=b"secret")
        log.record("a")
        self.assertTrue(log.verify()[0])
        self.assertFalse(AuditLog(path, key=b"other").verify()[0])
        self.assertFalse(AuditLog(path).verify()[0])

    def test_operations_are_audited(self):
        eng = self.engine()
        eng.backup("app")
        eng.restore("app", self.tmp / "out")
        eng.verify("app")
        actions = [e["action"] for e in eng.audit.entries()]
        self.assertEqual(actions, ["backup", "restore", "verify"])
        self.assertTrue(eng.audit.verify()[0])


# ------------------------------------------------------------------------ plans
class _Health(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200 if self.path == "/ok" else 503)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


class TestPlans(Base):
    def setUp(self):
        super().setUp()
        self.log = self.tmp / "order.log"
        self.httpd = HTTPServer(("127.0.0.1", 0), _Health)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def say(self, word, **extra):
        return {"name": word, "type": "command", "command": f"echo {word} >> {self.log}", **extra}

    def plan_engine(self, steps, **plan):
        plans = [{"name": "p", "rto_minutes": 30, "steps": steps, **plan}]
        return self.engine(plans=plans)

    def order(self):
        return self.log.read_text().split() if self.log.exists() else []

    def test_validation(self):
        with self.assertRaisesRegex(ConfigError, "cycle"):
            self.plan_engine([self.say("a", depends_on=["b"]), self.say("b", depends_on=["a"])])
        with self.assertRaisesRegex(ConfigError, "unknown step"):
            self.plan_engine([self.say("a", depends_on=["ghost"])])
        with self.assertRaisesRegex(ConfigError, "unknown protection set"):
            self.plan_engine([{"name": "r", "type": "restore", "set": "ghost", "target": "x"}])
        with self.assertRaisesRegex(ConfigError, "duplicate step"):
            self.plan_engine([self.say("a"), self.say("a")])
        steps = self.plan_engine([self.say("a"), self.say("b", depends_on=["a"]),
                                  self.say("c", depends_on=["a"]), self.say("d", depends_on=["b", "c"])]).plans["p"].steps
        self.assertEqual([[s.name for s in lvl] for lvl in step_levels(steps)], [["a"], ["b", "c"], ["d"]])

    def test_happy_path_respects_dependencies(self):
        eng = self.plan_engine([self.say("a"), self.say("b", depends_on=["a"]),
                                self.say("c", depends_on=["a"]), self.say("d", depends_on=["b", "c"])])
        report = eng.run_plan("p")
        self.assertTrue(report.ok)
        self.assertTrue(report.rto_met)
        order = self.order()
        self.assertEqual(order[0], "a")
        self.assertEqual(order[-1], "d")
        self.assertEqual(set(order[1:3]), {"b", "c"})
        self.assertTrue((eng.cfg.vault / "plan_runs.jsonl").exists())
        self.assertEqual(eng.audit.entries()[-1]["action"], "plan_run")

    def test_failure_aborts_and_rolls_back_in_reverse(self):
        eng = self.plan_engine([
            self.say("s1", rollback=f"echo undo-s1 >> {self.log}"),
            self.say("s2", depends_on=["s1"], rollback=f"echo undo-s2 >> {self.log}"),
            {"name": "s3", "type": "command", "command": "exit 1", "depends_on": ["s2"]},
            self.say("s4", depends_on=["s3"]),
        ])
        report = eng.run_plan("p")
        status = {r.name: r.status for r in report.steps}
        self.assertFalse(report.ok)
        self.assertEqual(status, {"s1": "ok", "s2": "ok", "s3": "failed", "s4": "skipped"})
        self.assertEqual(self.order(), ["s1", "s2", "undo-s2", "undo-s1"])
        self.assertEqual([r.status for r in report.rollbacks], ["rolled_back", "rolled_back"])

    def test_no_rollback_when_disabled_and_continue_on_failure(self):
        eng = self.plan_engine([
            {"name": "s1", "type": "command", "command": "exit 1", "on_failure": "continue"},
            self.say("s2", depends_on=["s1"]),
            self.say("s3", rollback=f"echo undo-s3 >> {self.log}"),
        ])
        report = eng.run_plan("p")
        status = {r.name: r.status for r in report.steps}
        self.assertEqual(status, {"s1": "failed", "s2": "skipped", "s3": "ok"})
        self.assertFalse(report.ok)
        self.assertEqual(report.rollbacks, [])
        self.assertEqual(self.order(), ["s3"])

    def test_retries(self):
        marker = self.tmp / "marker"
        step = {"name": "flaky", "type": "command", "retries": 2,
                "command": f"[ -f {marker} ] || {{ touch {marker}; exit 1; }}"}
        report = self.plan_engine([step]).run_plan("p")
        self.assertTrue(report.ok)
        self.assertEqual(report.steps[0].attempts, 2)
        always = {"name": "bad", "type": "command", "retries": 2, "command": "exit 1"}
        report = self.plan_engine([always]).run_plan("p")
        self.assertEqual((report.steps[0].status, report.steps[0].attempts), ("failed", 3))

    def test_step_timeout(self):
        step = {"name": "slow", "type": "command", "command": "sleep 5", "timeout": 0.3}
        report = self.plan_engine([step]).run_plan("p")
        self.assertFalse(report.ok)
        self.assertIn("timed out", report.steps[0].detail)

    def test_dry_run_executes_nothing(self):
        eng = self.plan_engine([self.say("a"), self.say("b", depends_on=["a"])])
        report = eng.run_plan("p", dry_run=True)
        self.assertTrue(report.ok)
        self.assertEqual([r.status for r in report.steps], ["dry_run", "dry_run"])
        self.assertEqual(self.order(), [])
        self.assertFalse((eng.cfg.vault / "plan_runs.jsonl").exists())

    def test_preflight_blocks_plan_without_snapshots(self):
        eng = self.plan_engine([self.say("a"),
                                {"name": "r", "type": "restore", "set": "app", "target": str(self.tmp / "out"),
                                 "depends_on": ["a"]}])
        report = eng.run_plan("p")
        self.assertFalse(report.ok)
        self.assertIn("no snapshot available", report.preflight[0])
        self.assertEqual(self.order(), [])  # nothing ran

    def test_restore_verify_and_http_steps(self):
        out = self.tmp / "dr-site"
        eng = self.plan_engine([
            {"name": "restore", "type": "restore", "set": "app", "target": str(out)},
            {"name": "verify", "type": "verify", "set": "app", "depends_on": ["restore"]},
            {"name": "health", "type": "http", "url": self.base + "/ok", "depends_on": ["verify"]},
            {"name": "pause", "type": "wait", "seconds": 0, "depends_on": ["health"]},
        ])
        eng.backup("app")
        report = eng.run_plan("p")
        self.assertTrue(report.ok, [r.detail for r in report.steps])
        self.assertTrue((out / "data/a.txt").exists())
        bad = self.plan_engine([{"name": "health", "type": "http", "url": self.base + "/bad"}])
        report = bad.run_plan("p")
        self.assertFalse(report.ok)
        self.assertIn("503", report.steps[0].detail)


# ----------------------------------------------------------------------- status
class TestStatusAndScheduler(Base):
    def test_rpo_and_rto_compliance(self):
        eng = self.engine()
        st = eng.status()[0]
        self.assertEqual(st.state, "breach")
        self.assertIn("no backups", st.problems[0])
        eng.backup("app")
        st = eng.status()[0]
        self.assertEqual(st.state, "warning")  # no drill, replica behind
        self.assertEqual(len(st.warnings), 2)
        eng.replicate()
        self.assertTrue(eng.drill("app").ok)
        self.assertEqual(eng.status()[0].state, "ok")
        self.clock.advance(3 * 3600)
        st = eng.status()[0]
        self.assertEqual(st.state, "breach")
        self.assertIn("RPO breached", st.problems[0])
        self.clock.advance(-3 * 3600)
        eng._append_jsonl(eng.cfg.vault / "drills.jsonl",
                          {"set": "app", "ok": True, "seconds": 4000, "snapshot": "x"})
        self.assertIn("RTO exceeded", eng.status()[0].problems[0])

    def test_failed_drill_is_a_breach(self):
        eng = self.engine()
        eng.backup("app")
        chunk_files(eng.vault)[0].write_bytes(zlib.compress(b"rot"))
        drill = eng.drill("app")
        self.assertFalse(drill.ok)
        self.assertIn("drill FAILED", eng.status()[0].problems[0])
        self.assertEqual(list(Path(tempfile.gettempdir()).glob("recoveryx-drill-*")), [])  # cleaned up

    def test_scheduler_backs_up_when_due_replicates_and_alerts(self):
        alerts = self.tmp / "alerts.log"
        eng = self.engine(alert_command=f'echo "$RECOVERYX_SET $RECOVERYX_PREVIOUS>$RECOVERYX_STATE" >> {alerts}')
        first = eng.run_cycle()
        self.assertTrue(any("backup" in a for e in first for a in e["actions"]))
        self.assertTrue(any("replicated" in a for e in first for a in e["actions"]))
        self.assertEqual(len(eng.replicas[0].list_snapshots()), 1)
        self.assertFalse(alerts.exists())  # ok -> warning is not alert-worthy
        self.clock.advance(600)
        second = eng.run_cycle()
        self.assertFalse(any("backup" in a for e in second for a in e["actions"]))  # not due yet

        shutil.move(str(self.data), str(self.tmp / "data-gone"))  # simulate a lost volume
        self.clock.advance(3 * 3600)
        broken = eng.run_cycle()
        self.assertTrue(any(e["error"] for e in broken))
        self.assertEqual(alerts.read_text().split("\n")[0], "app warning>breach")
        eng.run_cycle()
        self.assertEqual(len(alerts.read_text().splitlines()), 1)  # no repeated alerts

        shutil.move(str(self.tmp / "data-gone"), str(self.data))
        fixed = eng.run_cycle()
        self.assertTrue(any("backup" in a for e in fixed for a in e["actions"]))
        self.assertEqual(alerts.read_text().splitlines()[1], "app breach>warning")
        self.assertIn("alert", [e["action"] for e in eng.audit.entries()])


# ------------------------------------------------------------------- config/cli
class TestConfig(Base):
    def bad(self, **overrides):
        with self.assertRaises(ConfigError):
            parse_config(self.raw(**overrides), self.tmp)

    def test_validation(self):
        self.bad(vault=None)
        self.bad(protection_sets=[])
        self.bad(replicas=["vault"])
        self.bad(signing_key_env="RECOVERYX_TEST_MISSING_KEY")
        self.bad(chunk_size=0)
        base = self.raw()["protection_sets"][0]
        self.bad(protection_sets=[{**base, "retention": {"keep_last": -1}}])
        self.bad(protection_sets=[{**base, "interval_minutes": 0}])
        self.bad(protection_sets=[{**base, "sources": [{"name": "a", "path": "x"}, {"name": "a", "path": "y"}]}])
        self.bad(protection_sets=[base, base])
        self.bad(plans=[{"name": "p", "steps": [{"name": "s", "type": "command"}]}])
        self.bad(plans=[{"name": "p", "steps": [{"name": "s", "type": "http", "url": "ftp://x"}]}])
        self.bad(plans=[{"name": "p", "steps": [{"name": "s", "type": "teleport"}]}])

    def test_signed_vault_end_to_end(self):
        os.environ["RECOVERYX_TEST_KEY"] = "super-secret-key"
        self.addCleanup(os.environ.pop, "RECOVERYX_TEST_KEY", None)
        eng = self.engine(signing_key_env="RECOVERYX_TEST_KEY")
        snap = eng.backup("app")
        eng.restore("app", self.tmp / "out")
        self.assertTrue(eng.audit.verify()[0])
        path = eng.vault.root / "snapshots" / f"{snap.id}.json"
        doc = json.loads(path.read_text())
        doc["manifest"]["files"][0]["path"] = "tampered.txt"
        path.write_text(json.dumps(doc))
        with self.assertRaisesRegex(RecoveryXError, "signature"):
            eng.restore("app", self.tmp / "out2", snapshot_id=snap.id)


class TestCli(Base):
    def test_full_workflow(self):
        cfg = str(self.tmp / "recoveryx.json")
        run = lambda *a: main(["-c", cfg, *a])
        self.assertEqual(run("init"), 0)
        self.assertEqual(run("init"), 1)
        (self.tmp / "data").mkdir(exist_ok=True)
        self.assertEqual(run("validate"), 0)
        self.assertEqual(run("status"), 1)  # nothing backed up yet: breach
        self.assertEqual(run("backup", "--tag", "nightly"), 0)
        self.assertEqual(run("list"), 0)
        self.assertEqual(run("verify", "app-data"), 0)
        self.assertEqual(run("restore", "app-data", str(self.tmp / "out")), 0)
        self.assertEqual(run("restore", "app-data", str(self.tmp / "out")), 1)  # not empty
        self.assertEqual((self.tmp / "out/data/a.txt").read_text(), (self.data / "a.txt").read_text())
        self.assertEqual(run("drill", "app-data"), 0)
        self.assertEqual(run("status"), 0)
        self.assertEqual(run("status", "--json"), 0)
        self.assertEqual(run("prune", "--dry-run"), 0)
        self.assertEqual(run("plans"), 0)
        self.assertEqual(run("plan", "recover-app", "--dry-run"), 0)
        self.assertEqual(run("plan", "recover-app"), 0)
        self.assertEqual(run("run", "--once"), 0)
        self.assertEqual(run("audit-verify"), 0)
        self.assertEqual(main(["-c", str(self.tmp / "missing.json"), "validate"]), 2)
        self.assertEqual(run("restore", "ghost", str(self.tmp / "o")), 1)


if __name__ == "__main__":
    unittest.main()
