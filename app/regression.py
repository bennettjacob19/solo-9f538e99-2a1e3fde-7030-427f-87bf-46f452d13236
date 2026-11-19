"""Regression-case executor for one round.

A round's case is at most 12 steps, in order:

  mode  -- switch the authoritative endpoint (A address / delay / nxdomain /
           timeout).  The step number is stamped into the control row, so the
           authoritative endpoint reports which setting actually answered.
  wait  -- sleep.  The sum of all wait steps is capped at 30s per case.
  query -- send a real UDP A query for the fixed domain at the round's own
           resolver and compare the actual reply field by field with the
           expectations: RCODE, A address and authoritative setting step
           number.  The last two may be "none" (no address / no step).

Two rounds may run in parallel; each has its own endpoints, cache and logs and
starts from an empty cache.

If an endpoint fails to start, a process dies, or a query gets no DNS reply at
all, the run is interrupted at that point with the reason recorded; results
measured so far are kept, and the round's processes and ports are recycled
either way.
"""
from __future__ import annotations

import ipaddress
import threading
import time

from . import common, rounds

MAX_STEPS = 12
MAX_TOTAL_WAIT = 30.0
VALID_MODES = ("a", "nxdomain", "delay", "timeout")
VALID_RCODES = ("NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED", "NODATA")

PROGRESS_LOCK = threading.Lock()


class StepError(ValueError):
    """Invalid case definition (rejected before anything runs)."""


def _as_optional_int(value, field: str) -> int | None:
    if value is None or value == "" or value == "none":
        return None
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise StepError(f"{field} 必须是整数或留空") from exc
    if number < 0:
        raise StepError(f"{field} 不能为负")
    return number


def _as_optional_ip(value, field: str) -> str | None:
    if value is None or value == "" or value == "none":
        return None
    try:
        return str(ipaddress.IPv4Address(str(value).strip()))
    except ValueError as exc:
        raise StepError(f"{field} 不是合法 IPv4 地址：{value!r}") from exc


def validate_case(raw_steps) -> list[dict]:
    """Normalize and validate a case.  Raises StepError when it cannot run."""
    if not isinstance(raw_steps, list) or not raw_steps:
        raise StepError("用例为空，至少需要 1 个步骤")
    if len(raw_steps) > MAX_STEPS:
        raise StepError(f"最多 {MAX_STEPS} 步，收到 {len(raw_steps)} 步")
    steps: list[dict] = []
    total_wait = 0.0
    for index, raw in enumerate(raw_steps, start=1):
        if not isinstance(raw, dict):
            raise StepError(f"第 {index} 步格式错误")
        kind = str(raw.get("type", "")).strip()
        if kind == "mode":
            mode = str(raw.get("mode", "a")).strip()
            if mode not in VALID_MODES:
                raise StepError(f"第 {index} 步：未知权威模式 {mode!r}")
            ip = _as_optional_ip(raw.get("ip"), f"第 {index} 步 A 地址")
            delay = raw.get("delay_seconds", raw.get("delay"))
            try:
                delay = 0.0 if delay in (None, "") else float(delay)
            except (TypeError, ValueError) as exc:
                raise StepError(f"第 {index} 步延迟必须是数字") from exc
            if not (0 <= delay <= 60):
                raise StepError(f"第 {index} 步延迟必须在 0..60 秒")
            steps.append({"type": "mode", "step_no": index, "mode": mode,
                          "ip": ip, "delay_seconds": delay})
        elif kind == "wait":
            try:
                seconds = float(raw.get("seconds", 0))
            except (TypeError, ValueError) as exc:
                raise StepError(f"第 {index} 步等待秒数必须是数字") from exc
            if seconds < 0:
                raise StepError(f"第 {index} 步等待秒数不能为负")
            total_wait += seconds
            steps.append({"type": "wait", "step_no": index, "seconds": seconds})
        elif kind == "query":
            expect_rcode = str(raw.get("expect_rcode", "")).strip().upper()
            if expect_rcode not in VALID_RCODES:
                raise StepError(
                    f"第 {index} 步：预期 RCODE 必须是 {'/'.join(VALID_RCODES)}")
            expect_ip = _as_optional_ip(raw.get("expect_ip"),
                                        f"第 {index} 步预期 A 地址")
            expect_step = _as_optional_int(raw.get("expect_step"),
                                           f"第 {index} 步预期权威设置步骤号")
            steps.append({"type": "query", "step_no": index,
                          "expect_rcode": expect_rcode, "expect_ip": expect_ip,
                          "expect_step": expect_step})
        else:
            raise StepError(f"第 {index} 步：未知步骤类型 {kind!r}")
    if total_wait > MAX_TOTAL_WAIT + 1e-9:
        raise StepError(f"合计等待 {total_wait:g}s 超过上限 {MAX_TOTAL_WAIT:g}s")
    return steps


def _describe(step: dict) -> str:
    if step["type"] == "mode":
        return (f"切换权威端：{step['mode']}，A={step['ip'] or '沿用'}，"
                f"延迟={step['delay_seconds']:g}s")
    if step["type"] == "wait":
        return f"等待 {step['seconds']:g}s"
    expect_ip = step["expect_ip"] or "无"
    expect_step = "无" if step["expect_step"] is None else str(step["expect_step"])
    return (f"查询 {common.FIXED_DOMAIN} A：预期 RCODE={step['expect_rcode']}，"
            f"A={expect_ip}，设置步骤={expect_step}")


def _compare_query(step: dict, result: rounds.QueryResult) -> tuple[bool, list[str]]:
    problems: list[str] = []
    actual_rcode = result.rcode
    expect_rcode = step["expect_rcode"]
    if expect_rcode == "NODATA":
        if not (actual_rcode == "NOERROR" and not result.a_records):
            problems.append(f"RCODE/记录 实际 {actual_rcode} {result.a_records}")
    elif actual_rcode != expect_rcode:
        problems.append(f"RCODE 实际 {actual_rcode}，预期 {expect_rcode}")

    if step["expect_ip"] is None:
        if result.a_records:
            problems.append(f"A 地址 实际 {result.a_records}，预期无")
    elif result.a_records != [step["expect_ip"]]:
        problems.append(
            f"A 地址 实际 {result.a_records or '无'}，预期 {step['expect_ip']}")

    if step["expect_step"] is None:
        if result.auth_step is not None:
            problems.append(f"设置步骤 实际 {result.auth_step}，预期无")
    elif result.auth_step != str(step["expect_step"]):
        problems.append(
            f"设置步骤 实际 {result.auth_step or '无'}，"
            f"预期 {step['expect_step']}")
    return (not problems), problems


def _record(rnd: rounds.Round, step: dict | None, status: str,
            detail: str = "", actual: dict | None = None) -> dict:
    entry = {
        "step_no": step["step_no"] if step else None,
        "type": step["type"] if step else "start",
        "description": _describe(step) if step else "启动端点",
        "status": status,
        "detail": detail,
        "actual": actual,
    }
    with PROGRESS_LOCK:
        rnd.regression["results"].append(entry)
    return entry


def _summary(results: list[dict]) -> dict:
    return {
        "ok": sum(1 for r in results if r["status"] == "ok"),
        "fail": sum(1 for r in results if r["status"] == "fail"),
        "skipped": sum(1 for r in results if r["status"] == "skipped"),
        "interrupted": sum(1 for r in results if r["status"] == "interrupted"),
    }


def record_startup_failure(rnd: rounds.Round, steps: list[dict]) -> None:
    """Publish a case whose round never came up: interruption at startup, all
    steps marked skipped.  The cause is already in ``rnd.failure``."""
    reason = rnd.failure["reason"] if rnd.failure else "端点启动失败"
    _record(rnd, None, "interrupted", reason)
    for step in steps:
        _record(rnd, step, "skipped", "轮次启动失败，未执行")


def execute(rnd: rounds.Round, steps: list[dict]) -> dict:
    """Run a validated case on an already-started round, in this thread.

    Returns the report; progress is also published on ``rnd.regression`` while
    it runs.  The caller owns ``rnd.finish()``.
    """
    interrupted = rnd.failure is not None
    if interrupted:
        _record(rnd, None, "interrupted", rnd.failure["reason"])

    for step in steps:
        try:
            if interrupted:
                _record(rnd, step, "skipped", "前序步骤中断，未执行")
                continue
            if rnd.stopped.is_set():
                interrupted = True
                _record(rnd, step, "interrupted", "轮次被手动结束，资源已回收")
                continue
            failure = rnd.check_running()
            if failure:
                interrupted = True
                _record(rnd, step, "interrupted", failure["reason"])
                continue

            if step["type"] == "mode":
                try:
                    ip = step["ip"]
                    if ip is None:
                        # Address omitted: keep the round's current A address.
                        current = common.get_control(rnd.db_path) or {}
                        ip = current.get("ip") or common.DEFAULT_IP
                    rnd.set_control(step["mode"], ip,
                                    step["delay_seconds"], step["step_no"])
                except Exception as exc:  # noqa: BLE001 - report and stop
                    interrupted = True
                    rnd.fail(step["step_no"], "control-write",
                             f"权威设置写入失败：{exc}")
                    _record(rnd, step, "interrupted", f"权威设置写入失败：{exc}")
                    continue
                _record(rnd, step, "ok")

            elif step["type"] == "wait":
                deadline = time.monotonic() + step["seconds"]
                while time.monotonic() < deadline and not rnd.stopped.is_set():
                    time.sleep(min(0.2, max(0.0, deadline - time.monotonic())))
                if rnd.stopped.is_set():
                    interrupted = True
                    _record(rnd, step, "interrupted", "轮次被手动结束，资源已回收")
                    continue
                _record(rnd, step, "ok", f"已等待 {step['seconds']:g}s")

            else:  # query
                result = rnd.query()
                if result.error == rounds.ERR_NO_REPLY:
                    interrupted = True
                    rnd.fail_no_reply(
                        step["step_no"],
                        f"查询步骤 {step['step_no']} 未收到 DNS 报文"
                        f"（解析器 udp/{rnd.resolver_port}）")
                    _record(rnd, step, "interrupted", rnd.failure["reason"],
                            result.as_dict())
                    continue
                if result.error:
                    interrupted = True
                    rnd.fail(step["step_no"], "query-error",
                             f"查询失败：{result.error}")
                    _record(rnd, step, "interrupted", rnd.failure["reason"],
                            result.as_dict())
                    continue
                ok, problems = _compare_query(step, result)
                _record(rnd, step, "ok" if ok else "fail",
                        "；".join(problems) if problems else "与预期一致",
                        result.as_dict())
        except Exception as exc:  # noqa: BLE001 - one bad step must not hang
            interrupted = True
            rnd.fail(step["step_no"], "internal",
                     f"{type(exc).__name__}: {exc}")
            _record(rnd, step, "interrupted", rnd.failure["reason"])

    results = list(rnd.regression["results"])
    return {
        "round": rnd.round_id,
        "steps": results,
        "summary": _summary(results),
        "interrupted": rnd.failure is not None,
        "failure": rnd.as_dict()["failure"],
        "round_state": rnd.as_dict(),
    }


def run_case(round_id: str, steps: list[dict]) -> dict:
    """Run a complete case in its own round, waiting for it to finish.

    Convenience for tests and non-interactive use; the console uses
    ``Round.run_case`` so the page stays responsive while a case runs.
    """
    rnd = rounds.start_round(round_id)
    try:
        rnd.run_case(steps)
        rnd.wait_case()
    finally:
        rnd.finish()
    results = list(rnd.regression["results"]) if rnd.regression else []
    return {
        "round": rnd.round_id,
        "steps": results,
        "summary": _summary(results),
        "interrupted": rnd.failure is not None,
        "failure": rnd.as_dict()["failure"],
    }
