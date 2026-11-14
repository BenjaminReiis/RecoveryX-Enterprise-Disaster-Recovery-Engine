"""Shared helpers: errors, time, JSON, atomic writes, shell, formatting."""
from __future__ import annotations

import fnmatch
import json
import os
import signal
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional


class RecoveryXError(Exception):
    """Base class for all expected RecoveryX errors."""


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def atomic_write(path: Path, data: bytes) -> None:
    """Write `data` so that readers see either the old or the new file, never a partial one."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def is_excluded(rel: str, patterns: Iterable[str]) -> bool:
    """True if the path (or any component of it) matches one of the glob patterns."""
    parts = rel.split("/")
    for pat in patterns:
        if fnmatch.fnmatch(rel, pat) or any(fnmatch.fnmatch(part, pat) for part in parts):
            return True
    return False


def join_rel(base: str, name: str) -> str:
    return f"{base}/{name}" if base else name


def parse_time(text: str) -> float:
    """Parse an ISO 8601 timestamp (naive values are taken as UTC) into epoch seconds."""
    value = text.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        raise RecoveryXError(f"invalid timestamp '{text}' (use ISO 8601, e.g. 2026-11-13T10:00:00Z)")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def iso_time(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds")


def fmt_bytes(n: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if abs(n) < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TiB"


def fmt_duration(seconds: float) -> str:
    total = int(round(seconds))
    if total < 60:
        return f"{total}s"
    minutes, secs = divmod(total, 60)
    if minutes < 60:
        return f"{minutes}m {secs:02d}s"
    hours, mins = divmod(minutes, 60)
    if hours < 48:
        return f"{hours}h {mins:02d}m"
    days, hrs = divmod(hours, 24)
    return f"{days}d {hrs:02d}h"


@dataclass(frozen=True)
class ShellResult:
    returncode: int
    output: str
    timed_out: bool

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def run_shell(command: str, timeout: float, env: Optional[Mapping[str, str]] = None) -> ShellResult:
    """Run `command` through the shell with a hard timeout (kills the whole process group)."""
    kwargs = {"start_new_session": True} if os.name == "posix" else {}
    proc = subprocess.Popen(
        command, shell=True, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **kwargs,
    )
    try:
        out, _ = proc.communicate(timeout=timeout)
        timed_out = False
    except subprocess.TimeoutExpired:
        try:
            if os.name == "posix":
                os.killpg(proc.pid, signal.SIGKILL)
            else:
                proc.kill()
        except ProcessLookupError:
            pass
        out, _ = proc.communicate()
        timed_out = True
    text = out.decode("utf-8", errors="replace").strip()
    return ShellResult(proc.returncode, text[-500:], timed_out)
