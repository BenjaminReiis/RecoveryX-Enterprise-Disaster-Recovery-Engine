"""Recovery plans: dependency-ordered runbooks with retries, rollback and RTO tracking."""
from __future__ import annotations

import logging
import os
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Callable, List, Optional, Tuple

from .config import PlanConfig, StepConfig, step_levels
from .util import RecoveryXError, fmt_bytes, parse_time, run_shell

if TYPE_CHECKING:  # pragma: no cover
    from .engine import Engine

log = logging.getLogger("recoveryx")


@dataclass
class StepResult:
    name: str
    status: str  # ok | failed | skipped | dry_run | rolled_back | rollback_failed
    attempts: int = 0
    seconds: float = 0.0
    detail: str = ""


@dataclass
class PlanReport:
    plan: str
    dry_run: bool
    ok: bool
    started: float
    seconds: float
    rto_seconds: Optional[float] = None
    rto_met: Optional[bool] = None
    steps: List[StepResult] = field(default_factory=list)
    rollbacks: List[StepResult] = field(default_factory=list)
    preflight: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def describe(step: StepConfig) -> str:
    p = step.params
    if step.type == "command":
        return f"run: {p['command']}"
    if step.type == "restore":
        return f"restore '{p['set']}' into {p['target']}"
    if step.type == "verify":
        return f"verify '{p['set']}' ({'deep' if p['deep'] else 'shallow'})"
    if step.type == "http":
        return f"GET {p['url']} expecting {p['expect_status']}"
    return f"wait {p['seconds']:g}s"


class PlanRunner:
    def __init__(
        self,
        engine: "Engine",
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        wall: Callable[[], float] = time.time,
    ):
        self.engine = engine
        self.sleep = sleep
        self.clock = clock
        self.wall = wall

    # ------------------------------------------------------------------- run
    def run(self, plan: PlanConfig, dry_run: bool = False) -> PlanReport:
        started, t0 = self.wall(), self.clock()
        levels = step_levels(plan.steps)
        problems = self._preflight(plan)
        if problems:
            return self._report(plan, dry_run, False, started, t0, [], [], problems)
        if dry_run:
            steps = [StepResult(s.name, "dry_run", 0, 0.0, describe(s)) for lvl in levels for s in lvl]
            return self._report(plan, True, True, started, t0, steps, [], [])

        results: List[StepResult] = []
        status = {}
        completed: List[StepConfig] = []
        aborted = False
        for level in levels:
            runnable: List[StepConfig] = []
            for step in level:
                if aborted:
                    results.append(StepResult(step.name, "skipped", detail="plan aborted"))
                    status[step.name] = "skipped"
                    continue
                unmet = [d for d in step.depends_on if status.get(d) != "ok"]
                if unmet:
                    results.append(StepResult(step.name, "skipped",
                                              detail="dependency not satisfied: " + ", ".join(unmet)))
                    status[step.name] = "skipped"
                    continue
                runnable.append(step)
            if not runnable:
                continue
            with ThreadPoolExecutor(max_workers=min(plan.max_parallel, len(runnable))) as pool:
                outcomes = list(pool.map(lambda s: self._execute(plan, s), runnable))
            for step, outcome in zip(runnable, outcomes):
                results.append(outcome)
                status[step.name] = outcome.status
                if outcome.status == "ok":
                    completed.append(step)
                elif step.on_failure == "abort":
                    aborted = True
        ok = all(r.status == "ok" for r in results)
        rollbacks = self._rollback(plan, completed) if aborted and plan.rollback_on_failure else []
        return self._report(plan, False, ok, started, t0, results, rollbacks, [])

    def _report(self, plan, dry_run, ok, started, t0, steps, rollbacks, problems) -> PlanReport:
        seconds = self.clock() - t0
        rto = plan.rto_minutes * 60 if plan.rto_minutes else None
        return PlanReport(
            plan=plan.name, dry_run=dry_run, ok=ok, started=started, seconds=round(seconds, 3),
            rto_seconds=rto, rto_met=(seconds <= rto) if (rto and not dry_run and ok) else None,
            steps=steps, rollbacks=rollbacks, preflight=problems,
        )

    # ------------------------------------------------------------- internals
    def _preflight(self, plan: PlanConfig) -> List[str]:
        problems = []
        for step in plan.steps:
            if step.type in ("restore", "verify"):
                sid, before = self._snapshot_args(step)
                problem = self.engine.check_snapshot_available(step.params["set"], sid, before)
                if problem:
                    problems.append(f"step '{step.name}': {problem}")
        return problems

    @staticmethod
    def _snapshot_args(step: StepConfig) -> Tuple[Optional[str], Optional[float]]:
        before = step.params.get("before")
        return step.params.get("snapshot"), (parse_time(before) if before else None)

    def _env(self, plan: PlanConfig, step: StepConfig) -> dict:
        env = dict(os.environ)
        env.update({"RECOVERYX_PLAN": plan.name, "RECOVERYX_STEP": step.name})
        return env

    def _execute(self, plan: PlanConfig, step: StepConfig) -> StepResult:
        attempts = step.retries + 1
        t0 = self.clock()
        detail = ""
        for attempt in range(1, attempts + 1):
            ok, detail = self._run_once(plan, step)
            if ok:
                return StepResult(step.name, "ok", attempt, round(self.clock() - t0, 3), detail)
            log.warning("[%s] step '%s' attempt %d/%d failed: %s", plan.name, step.name, attempt, attempts, detail)
            if attempt < attempts:
                self.sleep(step.retry_delay)
        return StepResult(step.name, "failed", attempts, round(self.clock() - t0, 3), detail)

    def _run_once(self, plan: PlanConfig, step: StepConfig) -> Tuple[bool, str]:
        p = step.params
        try:
            if step.type == "command":
                res = run_shell(p["command"], step.timeout, self._env(plan, step))
                if res.timed_out:
                    return False, f"timed out after {step.timeout:g}s"
                return res.ok, f"exit {res.returncode}" + (f": {res.output[:200]}" if res.output else "")
            if step.type == "restore":
                sid, before = self._snapshot_args(step)
                result = self.engine.restore(p["set"], p["target"], sid, before, p.get("only"), p["overwrite"])
                return True, f"restored {result.files} file(s), {fmt_bytes(result.bytes)} into {p['target']}"
            if step.type == "verify":
                sid, _ = self._snapshot_args(step)
                vr = self.engine.verify(p["set"], sid, p["deep"], fallback=True)
                return vr.ok, ("snapshot " + vr.snapshot + " verified" if vr.ok else "; ".join(vr.problems[:3]))
            if step.type == "http":
                return self._http(p["url"], p["expect_status"], step.timeout)
            self.sleep(p["seconds"])
            return True, f"waited {p['seconds']:g}s"
        except RecoveryXError as exc:
            return False, str(exc)
        except Exception as exc:  # a broken step must not take the runner down
            return False, f"{type(exc).__name__}: {exc}"

    @staticmethod
    def _http(url: str, expect: int, timeout: float) -> Tuple[bool, str]:
        request = urllib.request.Request(url, headers={"User-Agent": "recoveryx"})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as resp:
                status = resp.status
        except urllib.error.HTTPError as exc:
            status = exc.code
        except Exception as exc:
            return False, f"{type(exc).__name__}: {exc}"
        return status == expect, f"HTTP {status}" + ("" if status == expect else f" (expected {expect})")

    def _rollback(self, plan: PlanConfig, completed: List[StepConfig]) -> List[StepResult]:
        out: List[StepResult] = []
        for step in reversed(completed):
            if not step.rollback:
                continue
            t0 = self.clock()
            res = run_shell(step.rollback, step.timeout, self._env(plan, step))
            detail = "timed out" if res.timed_out else f"exit {res.returncode}" + (f": {res.output[:200]}" if res.output else "")
            out.append(StepResult(f"rollback:{step.name}", "rolled_back" if res.ok else "rollback_failed",
                                  1, round(self.clock() - t0, 3), detail))
        return out
