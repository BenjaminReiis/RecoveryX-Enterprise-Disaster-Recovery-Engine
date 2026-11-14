# RecoveryX: Enterprise Disaster Recovery Engine

> Disaster recovery and operational continuity.

> 🔒 **Proprietary and confidential software.** All rights reserved.
> Access to this repository does not grant any right to copy, distribute, modify or use the code without prior written permission from the author.

---

## What it does

- **Vault:** deduplicated, compressed, content-addressed backup storage. Every snapshot manifest is signed (HMAC-SHA256) so tampering is detected.
- **Incremental backups:** unchanged files are not re-read; unchanged data is never stored twice.
- **Retention:** keep-last / daily / weekly / monthly rules, with safe garbage collection.
- **Replication:** copy snapshots to one or more DR vaults. Corruption in the source is reported, never propagated.
- **Restore:** full or partial, latest, by snapshot id, or point-in-time. If the primary vault is damaged, restore falls back to the replicas automatically.
- **Verification and drills:** deep integrity checks, plus restore drills that measure how long recovery really takes.
- **RPO / RTO compliance:** `status` compares reality with your targets and exits non-zero on breach.
- **Recovery plans:** dependency-ordered runbooks (restore, verify, commands, HTTP checks) with retries, timeouts, parallel steps, rollback and RTO tracking.
- **Tamper-evident audit log:** every operation is recorded in a hash-chained log.
- **Scheduler:** `run` backs up what is due, replicates, prunes and alerts on breaches.

## How it works

```
 sources ──► backup ──► VAULT (primary)
                          │  chunks/ab/abcdef…   zlib-compressed, named by SHA-256
                          │  snapshots/<id>.json manifest + HMAC signature
                          │  audit.jsonl · drills.jsonl · plan_runs.jsonl · state.json
                          │
                  replicate│            restore ◄── falls back to replicas if the primary is damaged
                          ▼
                    REPLICA vault(s)  (DR site)
```

Files are split into fixed-size chunks (default 1 MiB), each stored once under its SHA-256. A snapshot is a manifest that lists files and their chunks, so a new snapshot only costs the data that changed.

## Install

```bash
pip install -e .
```

Or without installing: `PYTHONPATH=src python -m recoveryx --help`

## Quick start

```bash
recoveryx init                      # writes recoveryx.json
recoveryx validate
recoveryx backup                    # all protection sets (or: backup app-data)
recoveryx list
recoveryx verify app-data           # deep check (--shallow, --replicas)
recoveryx restore app-data ./out    # --snapshot ID, --before 2026-11-13T10:00:00Z, --only data, --overwrite
recoveryx drill app-data            # restore to scratch space, measure, clean up
recoveryx replicate
recoveryx prune --dry-run
recoveryx status                    # RPO/RTO compliance, exit code 1 on breach
recoveryx plans
recoveryx plan recover-app --dry-run
recoveryx plan recover-app
recoveryx run                       # scheduler (--once for a single cycle)
recoveryx audit-verify
```

Restoring creates `<target>/<source name>/<path>`. A restore refuses a non-empty target unless `--overwrite` is given.

## Configuration

Relative paths are resolved relative to the configuration file.

```json
{
  "vault": "./vault",
  "replicas": ["/mnt/dr-site/vault"],
  "signing_key_env": "RECOVERYX_KEY",
  "audit_log": "/var/log/recoveryx/audit.jsonl",
  "chunk_size": 1048576,
  "gc_grace_seconds": 3600,
  "alert_command": "/usr/local/bin/notify-oncall.sh",
  "scratch_dir": "/var/tmp/recoveryx",
  "protection_sets": [
    {
      "name": "app-data",
      "sources": [
        { "name": "data", "path": "/srv/app/data" },
        { "name": "etc", "path": "/etc/app" }
      ],
      "exclude": ["*.tmp", "cache"],
      "interval_minutes": 60,
      "rpo_minutes": 120,
      "rto_minutes": 30,
      "retention": { "keep_last": 5, "keep_daily": 7, "keep_weekly": 4, "keep_monthly": 6 }
    }
  ],
  "plans": [
    {
      "name": "recover-app",
      "rto_minutes": 30,
      "rollback_on_failure": true,
      "max_parallel": 4,
      "steps": [
        { "name": "restore-data", "type": "restore", "set": "app-data", "target": "/srv/restore" },
        { "name": "verify-data", "type": "verify", "set": "app-data", "depends_on": ["restore-data"] },
        { "name": "start-db", "type": "command", "command": "systemctl start db",
          "depends_on": ["verify-data"], "rollback": "systemctl stop db", "timeout": 60, "retries": 2 },
        { "name": "db-health", "type": "http", "url": "http://localhost:8080/health",
          "depends_on": ["start-db"], "retries": 5, "retry_delay": 5 },
        { "name": "start-app", "type": "command", "command": "systemctl start app",
          "depends_on": ["db-health"], "rollback": "systemctl stop app" }
      ]
    }
  ]
}
```

### Top level

| Field | Default | Description |
|-------|---------|-------------|
| `vault` | required | Primary vault directory. |
| `replicas` | `[]` | Additional vault directories (DR sites). |
| `signing_key_env` | none | Name of the environment variable holding the signing key. Enables signed manifests and an HMAC audit chain. The key is never stored in the configuration. If the variable is not set, the configuration is rejected. |
| `audit_log` | `<vault>/audit.jsonl` | Keep it outside the vault so a vault loss does not take the audit trail with it. |
| `chunk_size` | 1048576 | Chunk size in bytes. |
| `gc_grace_seconds` | 3600 | Unreferenced chunks younger than this are never deleted (protects running backups). |
| `alert_command` | none | Shell command run when a set enters or leaves `breach`. Receives `RECOVERYX_SET`, `RECOVERYX_STATE`, `RECOVERYX_PREVIOUS`, `RECOVERYX_MESSAGE`. |
| `scratch_dir` | system temp | Where drills restore to. |

### Protection sets

| Field | Default | Description |
|-------|---------|-------------|
| `name` | required | Letters, digits, `_`, `.`, `-`. |
| `sources` | required | List of `{name, path}`. |
| `exclude` | `[]` | Glob patterns matched against the path and every path component. |
| `interval_minutes` | 60 | How often the scheduler backs up this set. |
| `rpo_minutes` | 2 x interval | Maximum acceptable age of the newest backup. |
| `rto_minutes` | none | Maximum acceptable restore time, checked against the last drill. |
| `retention` | keep all | `keep_last`, `keep_daily`, `keep_weekly`, `keep_monthly`. The newest snapshot is always kept. |

### Plan steps

| Type | Fields |
|------|--------|
| `command` | `command` (shell; receives `RECOVERYX_PLAN`, `RECOVERYX_STEP`) |
| `restore` | `set`, `target`, optional `snapshot`, `before`, `only`, `overwrite` |
| `verify` | `set`, optional `snapshot`, `before`, `deep` (default true) |
| `http` | `url`, `expect_status` (default 200) |
| `wait` | `seconds` |

Common fields: `depends_on`, `timeout` (60), `retries` (0), `retry_delay` (5), `on_failure` (`abort` or `continue`), `rollback` (shell command).

Execution rules:

- Steps run in dependency order; independent steps run in parallel (up to `max_parallel`).
- A preflight check makes sure every `restore`/`verify` step has a snapshot available before anything runs.
- On failure with `abort`, remaining steps are skipped and completed steps that define `rollback` are rolled back in reverse order.
- With `continue`, only steps that depend on the failed one are skipped.
- `--dry-run` runs the preflight and prints the order without executing anything.

## RPO, RTO and drills

`status` marks each set `ok`, `warning` or `breach`:

- **breach:** no backups, newest backup older than `rpo_minutes`, last drill failed, or last drill slower than `rto_minutes`.
- **warning:** no drill recorded (RTO unverified), partial backup (unreadable files skipped), or a replica is behind.

Run `drill` regularly: a backup that has never been restored is only a hope.

## Security notes

- **Integrity, not secrecy.** Manifests and the audit log are authenticated, but chunk data is **not encrypted**. Put the vault on encrypted storage, or encrypt at the transport and filesystem layer.
- Treat the signing key like any other secret and keep a copy outside the vault.
- The audit log detects edits and deletions in the middle of the chain. Truncating its tail cannot be detected locally, so ship it to an external system.
- The configuration is trusted: `command` steps, rollbacks and `alert_command` run through the shell with the privileges of the RecoveryX process.
- Restore rejects manifest paths that would escape the target directory.

## Limitations

- Backups are consistent per file, not across files. For databases or busy volumes, create a filesystem or database snapshot first and back that up.
- Fixed-size chunking: inserting data in the middle of a file shifts later chunks and reduces deduplication for that file.
- Vaults are plain directories (local disks, NFS, mounted object storage). There are no native cloud backends.
- One scheduler per vault is assumed; concurrent backups of the same set are not coordinated.

## Tests

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

## License

**All rights reserved.** See [LICENSE](./LICENSE).
