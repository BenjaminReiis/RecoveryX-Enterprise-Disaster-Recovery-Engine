"""Configuration loading and validation (JSON)."""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from .util import RecoveryXError, parse_time


class ConfigError(RecoveryXError):
    """Invalid configuration."""


NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
STEP_TYPES = ("command", "restore", "verify", "http", "wait")


@dataclass
class Source:
    name: str
    path: Path


@dataclass
class Retention:
    keep_last: int = 0
    keep_daily: int = 0
    keep_weekly: int = 0
    keep_monthly: int = 0

    @property
    def active(self) -> bool:
        return any((self.keep_last, self.keep_daily, self.keep_weekly, self.keep_monthly))


@dataclass
class ProtectionSet:
    name: str
    sources: List[Source]
    exclude: List[str] = field(default_factory=list)
    interval_minutes: float = 60.0
    rpo_minutes: float = 120.0
    rto_minutes: Optional[float] = None
    retention: Retention = field(default_factory=Retention)


@dataclass
class StepConfig:
    name: str
    type: str
    depends_on: List[str] = field(default_factory=list)
    timeout: float = 60.0
    retries: int = 0
    retry_delay: float = 5.0
    on_failure: str = "abort"  # "abort" | "continue"
    rollback: Optional[str] = None
    params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PlanConfig:
    name: str
    steps: List[StepConfig]
    rto_minutes: Optional[float] = None
    rollback_on_failure: bool = True
    max_parallel: int = 4


@dataclass
class Config:
    vault: Path
    sets: List[ProtectionSet]
    audit_log: Path
    replicas: List[Path] = field(default_factory=list)
    key: Optional[bytes] = None
    chunk_size: int = 1024 * 1024
    gc_grace_seconds: float = 3600.0
    alert_command: Optional[str] = None
    scratch_dir: Optional[Path] = None
    plans: List[PlanConfig] = field(default_factory=list)


# --------------------------------------------------------------------- helpers
def _obj(value: Any, ctx: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{ctx}: must be an object")
    return value


def _number(raw: Dict[str, Any], key: str, default: Any, ctx: str,
            minimum: float = 0.0, integer: bool = False):
    value = raw.get(key, default)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{ctx}.{key}: must be a number")
    if value < minimum:
        raise ConfigError(f"{ctx}.{key}: must be >= {minimum}")
    if integer:
        if int(value) != value:
            raise ConfigError(f"{ctx}.{key}: must be an integer")
        return int(value)
    return float(value)


def _name(value: Any, ctx: str) -> str:
    if not isinstance(value, str) or not NAME_RE.match(value):
        raise ConfigError(f"{ctx}.name: required, letters/digits/'_'/'.'/'-' only")
    return value


def _string(raw: Dict[str, Any], key: str, ctx: str, required: bool = True) -> Optional[str]:
    value = raw.get(key)
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{ctx}.{key}: must be a non-empty string")
    return value


def _path(base: Path, value: Any, ctx: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{ctx}: must be a non-empty string")
    p = Path(value).expanduser()
    return (p if p.is_absolute() else base / p).resolve()


def _str_list(value: Any, ctx: str) -> List[str]:
    if not isinstance(value, list) or any(not isinstance(v, str) for v in value):
        raise ConfigError(f"{ctx}: must be a list of strings")
    return list(value)


# --------------------------------------------------------------------- plans
def step_levels(steps: List[StepConfig]) -> List[List[StepConfig]]:
    """Group steps into dependency levels (steps in a level can run in parallel)."""
    by_name = {s.name: s for s in steps}
    remaining = {s.name: set(s.depends_on) for s in steps}
    done: set = set()
    levels: List[List[StepConfig]] = []
    while remaining:
        ready = [n for n, deps in remaining.items() if deps <= done]
        if not ready:
            raise ConfigError("dependency cycle among steps: " + ", ".join(sorted(remaining)))
        levels.append([by_name[n] for n in ready])
        done.update(ready)
        for n in ready:
            del remaining[n]
    return levels


def parse_step(raw: Any, ctx: str, set_names: set, base: Path) -> StepConfig:
    raw = _obj(raw, ctx)
    name = _name(raw.get("name"), ctx)
    kind = raw.get("type")
    if kind not in STEP_TYPES:
        raise ConfigError(f"{ctx}.type: must be one of {list(STEP_TYPES)}")
    params: Dict[str, Any] = {}
    if kind == "command":
        params["command"] = _string(raw, "command", ctx)
    elif kind in ("restore", "verify"):
        set_name = _string(raw, "set", ctx)
        if set_name not in set_names:
            raise ConfigError(f"{ctx}.set: unknown protection set '{set_name}'")
        params["set"] = set_name
        if "snapshot" in raw:
            params["snapshot"] = _string(raw, "snapshot", ctx)
        if "before" in raw:
            params["before"] = _string(raw, "before", ctx)
            parse_time(params["before"])
        if kind == "restore":
            params["target"] = str(_path(base, _string(raw, "target", ctx), f"{ctx}.target"))
            if "only" in raw:
                params["only"] = _str_list(raw["only"], f"{ctx}.only")
            params["overwrite"] = bool(raw.get("overwrite", False))
        else:
            params["deep"] = bool(raw.get("deep", True))
    elif kind == "http":
        url = _string(raw, "url", ctx)
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ConfigError(f"{ctx}.url: must be an http(s) URL")
        params["url"] = url
        params["expect_status"] = _number(raw, "expect_status", 200, ctx, 100, integer=True)
    else:  # wait
        params["seconds"] = _number(raw, "seconds", None, ctx, 0)
        if params["seconds"] is None:
            raise ConfigError(f"{ctx}.seconds: required for wait steps")
    deps = _str_list(raw.get("depends_on", []), f"{ctx}.depends_on")
    on_failure = raw.get("on_failure", "abort")
    if on_failure not in ("abort", "continue"):
        raise ConfigError(f"{ctx}.on_failure: must be 'abort' or 'continue'")
    return StepConfig(
        name=name,
        type=kind,
        depends_on=deps,
        timeout=_number(raw, "timeout", 60, ctx, 0.1),
        retries=_number(raw, "retries", 0, ctx, 0, integer=True),
        retry_delay=_number(raw, "retry_delay", 5, ctx, 0),
        on_failure=on_failure,
        rollback=_string(raw, "rollback", ctx, required=False),
        params=params,
    )


def parse_plan(raw: Any, ctx: str, set_names: set, base: Path) -> PlanConfig:
    raw = _obj(raw, ctx)
    name = _name(raw.get("name"), ctx)
    steps_raw = raw.get("steps")
    if not isinstance(steps_raw, list) or not steps_raw:
        raise ConfigError(f"{ctx}.steps: must be a non-empty list")
    steps = [parse_step(s, f"{ctx}.steps[{i}]", set_names, base) for i, s in enumerate(steps_raw)]
    names = [s.name for s in steps]
    if len(set(names)) != len(names):
        raise ConfigError(f"{ctx}: duplicate step names")
    for step in steps:
        for dep in step.depends_on:
            if dep not in names:
                raise ConfigError(f"{ctx}: step '{step.name}' depends on unknown step '{dep}'")
            if dep == step.name:
                raise ConfigError(f"{ctx}: step '{step.name}' depends on itself")
    step_levels(steps)  # detects cycles
    return PlanConfig(
        name=name,
        steps=steps,
        rto_minutes=_number(raw, "rto_minutes", None, ctx, 0),
        rollback_on_failure=bool(raw.get("rollback_on_failure", True)),
        max_parallel=_number(raw, "max_parallel", 4, ctx, 1, integer=True),
    )


# ------------------------------------------------------------ protection sets
def parse_set(raw: Any, ctx: str, base: Path) -> ProtectionSet:
    raw = _obj(raw, ctx)
    name = _name(raw.get("name"), ctx)
    sources_raw = raw.get("sources")
    if not isinstance(sources_raw, list) or not sources_raw:
        raise ConfigError(f"{ctx}.sources: must be a non-empty list")
    sources: List[Source] = []
    for i, s in enumerate(sources_raw):
        sctx = f"{ctx}.sources[{i}]"
        s = _obj(s, sctx)
        sname = _name(s.get("name"), sctx)
        if any(x.name == sname for x in sources):
            raise ConfigError(f"{ctx}: duplicate source name '{sname}'")
        sources.append(Source(sname, _path(base, s.get("path"), f"{sctx}.path")))
    ret = _obj(raw.get("retention", {}), f"{ctx}.retention")
    retention = Retention(*(
        _number(ret, key, 0, f"{ctx}.retention", 0, integer=True)
        for key in ("keep_last", "keep_daily", "keep_weekly", "keep_monthly")
    ))
    interval = _number(raw, "interval_minutes", 60, ctx, 1)
    return ProtectionSet(
        name=name,
        sources=sources,
        exclude=_str_list(raw.get("exclude", []), f"{ctx}.exclude"),
        interval_minutes=interval,
        rpo_minutes=_number(raw, "rpo_minutes", interval * 2, ctx, 1),
        rto_minutes=_number(raw, "rto_minutes", None, ctx, 0),
        retention=retention,
    )


def parse_config(raw: Any, base_dir: Path) -> Config:
    raw = _obj(raw, "config")
    vault = _path(base_dir, raw.get("vault"), "vault")
    sets_raw = raw.get("protection_sets")
    if not isinstance(sets_raw, list) or not sets_raw:
        raise ConfigError("protection_sets: must be a non-empty list")
    sets = [parse_set(s, f"protection_sets[{i}]", base_dir) for i, s in enumerate(sets_raw)]
    names = [s.name for s in sets]
    if len(set(names)) != len(names):
        raise ConfigError("duplicate protection set names")

    replicas_raw = raw.get("replicas", [])
    if not isinstance(replicas_raw, list):
        raise ConfigError("replicas: must be a list of paths")
    replicas = [_path(base_dir, r, f"replicas[{i}]") for i, r in enumerate(replicas_raw)]
    if any(r == vault for r in replicas):
        raise ConfigError("a replica cannot be the same location as the primary vault")

    key: Optional[bytes] = None
    key_env = raw.get("signing_key_env")
    if key_env is not None:
        if not isinstance(key_env, str) or not key_env:
            raise ConfigError("signing_key_env: must be an environment variable name")
        value = os.environ.get(key_env)
        if not value:
            raise ConfigError(f"signing key environment variable '{key_env}' is not set")
        key = value.encode("utf-8")

    plans_raw = raw.get("plans", [])
    if not isinstance(plans_raw, list):
        raise ConfigError("plans: must be a list")
    plans = [parse_plan(p, f"plans[{i}]", set(names), base_dir) for i, p in enumerate(plans_raw)]
    if len({p.name for p in plans}) != len(plans):
        raise ConfigError("duplicate plan names")

    audit = raw.get("audit_log")
    return Config(
        vault=vault,
        sets=sets,
        audit_log=_path(base_dir, audit, "audit_log") if audit else vault / "audit.jsonl",
        replicas=replicas,
        key=key,
        chunk_size=_number(raw, "chunk_size", 1024 * 1024, "config", 1, integer=True),
        gc_grace_seconds=_number(raw, "gc_grace_seconds", 3600, "config", 0),
        alert_command=_string(raw, "alert_command", "config", required=False),
        scratch_dir=_path(base_dir, raw["scratch_dir"], "scratch_dir") if raw.get("scratch_dir") else None,
        plans=plans,
    )


def load_config(path) -> Config:
    path = Path(path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ConfigError(f"config file not found: {path}")
    except json.JSONDecodeError as exc:
        raise ConfigError(f"invalid JSON in {path}: {exc}")
    return parse_config(raw, base_dir=path.resolve().parent)
