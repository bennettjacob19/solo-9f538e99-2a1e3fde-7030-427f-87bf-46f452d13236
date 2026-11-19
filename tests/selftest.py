#!/usr/bin/env python3
"""Self-test for the regression console (runs without Docker).

It spawns the web console on loopback with production timings (fresh TTL 5s,
stale window 20s, upstream timeout 2s) and checks:

  1. case validation: at most 12 steps, waits add up to at most 30s, RCODE and
     "none" handling;
  2. round A: basic upstream/fresh-cache steps, the setting-step number
     returned by the authoritative side, and the same A configured twice being
     told apart by the step number;
  3. round B running *in parallel* with its own authoritative configuration,
     cache and logs;
  4. NXDOMAIN is cached fresh with its step number and purged A record; stale
     serving keeps the old step number;
  5. a query step with no DNS reply interrupts the round at that step; earlier
     results stay; the round's processes are recycled;
  6. an endpoint that cannot start interrupts the round at startup with the
     cause, and still recycles.
  7. the page and API responses are present.

Exits non-zero if any check fails.  Runtime: ~70s.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

TMP = tempfile.mkdtemp(prefix="dns-regtest-")
WEB_PORT = 18000
BASE = f"http://127.0.0.1:{WEB_PORT}"
env = dict(os.environ)
env.update(
    DB_PATH=os.path.join(TMP, "app.db"),
    ROUND_DB_DIR=os.path.join(TMP, "rounds"),
    FIXED_DOMAIN="service.example",
    WEB_PORT=str(WEB_PORT),
    FRESH_TTL="5",
    STALE_WINDOW="20",
    UPSTREAM_TIMEOUT="2",
    PYTHONPATH=ROOT,
    PYTHONUNBUFFERED="1",
)

FAILS: list[str] = []
proc: subprocess.Popen | None = None


def check(name: str, cond: bool, info: str = "") -> None:
    print(f"  [{'PASS' if cond else 'FAIL'}] {name} {info}", flush=True)
    if not cond:
        FAILS.append(name)


def http(method: str, path: str, body=None, timeout: float = 40):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        BASE + path, data=data, method=method,
        headers={"Content-Type": "application/json"} if data else {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.load(exc)
        except Exception:
            return exc.code, {"error": exc.reason}


def run(round_id: str, steps: list[dict]) -> dict:
    status, payload = http("POST", f"/api/rounds/{round_id}/run", {"steps": steps})
    if status != 200 or not payload.get("ok"):
        return {"ok": False, "error": payload.get("error"), "status": status}
    deadline = time.time() + 90
    while time.time() < deadline:
        _, st = http("GET", f"/api/rounds/{round_id}")
        reg = st.get("regression")
        if reg and reg.get("status") != "running":
            return {"ok": True, "state": st, "reg": reg}
        time.sleep(0.4)
    return {"ok": False, "error": "case did not finish in time"}


def st_after_active(round_id: str) -> bool:
    """True when the round still reports live child processes."""
    _, st = http("GET", f"/api/rounds/{round_id}")
    return bool(st.get("active") or st.get("pids"))


def wait_web(timeout: float = 25) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(BASE + "/api/params", timeout=2) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.3)
    return False


def alive_ports(state: dict) -> list[int]:
    return [p for p in (state.get("auth_port"), state.get("resolver_port")) if p]


def burstable(port: int) -> bool:
    """True when something still answers an A query on that UDP port."""
    from dnslib import DNSRecord
    q = DNSRecord.question("service.example", "A")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(0.6)
        sock.sendto(q.pack(), ("127.0.0.1", port))
        sock.recvfrom(4096)
        return True
    except OSError:
        return False
    finally:
        sock.close()


def main() -> int:
    global proc
    print(f"[regtest] workdir={TMP}", flush=True)
    proc = subprocess.Popen([sys.executable, "-m", "app.web"], cwd=ROOT, env=env,
                            stdout=open(os.path.join(TMP, "web.log"), "ab"),
                            stderr=subprocess.STDOUT)
    try:
        if not wait_web():
            print("  [FAIL] web console did not come up")
            return 1

        # -- 1. validation ---------------------------------------------------
        print("1. 用例校验", flush=True)
        _, p = http("GET", "/api/params")
        check("1a 参数上限", p["max_steps"] == 12 and p["max_total_wait"] == 30)
        too_many = [{"type": "wait", "seconds": 0}] * 13
        st, r = http("POST", "/api/rounds/A/run", {"steps": too_many})
        check("1b 超过 12 步被拒绝", st == 400 and "12" in r.get("error", ""),
              r.get("error"))
        too_long = [{"type": "wait", "seconds": 20},
                    {"type": "wait", "seconds": 11}]
        st, r = http("POST", "/api/rounds/A/run", {"steps": too_long})
        check("1c 合计等待超过 30s 被拒绝", st == 400, r.get("error"))
        st, r = http("POST", "/api/rounds/A/run",
                     {"steps": [{"type": "query", "expect_rcode": "BOGUS"}]})
        check("1d 非法 RCODE 被拒绝", st == 400, r.get("error"))

        # -- 2. round A: steps and step numbers ------------------------------
        print("2. 轮次 A：步骤号区分相同 A 地址", flush=True)
        case_a = [
            {"type": "mode", "mode": "a", "ip": "192.0.2.10", "delay_seconds": 3},
            {"type": "query", "expect_rcode": "NOERROR",
             "expect_ip": "192.0.2.10", "expect_step": 1},
            {"type": "query", "expect_rcode": "NOERROR",
             "expect_ip": "192.0.2.10", "expect_step": 1},
            {"type": "wait", "seconds": 6},
            {"type": "mode", "mode": "a", "ip": "192.0.2.10", "delay_seconds": 1},
            {"type": "query", "expect_rcode": "NOERROR",
             "expect_ip": "192.0.2.10", "expect_step": 5},
        ]
        res_a = run("A", case_a)
        check("2a 轮次 A 用例完成", res_a.get("ok"), res_a.get("error"))
        if res_a.get("ok"):
            steps = res_a["reg"]["results"]
            statuses = [s["status"] for s in steps]
            check("2b 全部步骤通过", statuses == ["ok"] * 6, str(statuses))
            check("2c 第二次同址设置为新步骤号",
                  steps[5]["actual"]["auth_step"] == "5"
                  and steps[1]["actual"]["auth_step"] == "1",
                  str([s["actual"] and s["actual"].get("auth_step") for s in steps]))
            sources = [s["actual"]["source"] for s in steps if s["actual"]]
            check("2d 来源为 upstream 与缓存",
                  sources[0] in ("upstream",) and sources[1] == "cache-fresh"
                  and sources[2] == "upstream", str(sources))
            ports = alive_ports(res_a["state"])
            check("2e 轮次结束后进程已回收",
                  not burstable(ports[1]) and not burstable(ports[0]),
                  f"ports={ports}")

        # -- 2f. live operations while a case is running ----------------------
        print("2f. 用例运行中现场查询/切换照常", flush=True)
        http("POST", "/api/rounds/A/run", {"steps": [
            {"type": "mode", "mode": "a", "ip": "192.0.2.10", "delay_seconds": 1},
            {"type": "query", "expect_rcode": "NOERROR",
             "expect_ip": "192.0.2.10", "expect_step": 1},
            {"type": "wait", "seconds": 4},
            {"type": "query", "expect_rcode": "NOERROR",
             "expect_ip": "192.0.2.10", "expect_step": 1},
        ]})
        time.sleep(0.8)
        st, live_q = http("POST", "/api/rounds/A/query", {})
        check("2f1 运行中现场查询照常", st == 200 and live_q.get("ok")
              and live_q.get("a_records") == ["192.0.2.10"], str(live_q))
        st, live_m = http("POST", "/api/rounds/A/mode",
                          {"mode": "a", "ip": "192.0.2.99", "delay_seconds": 1})
        check("2f2 运行中手动切换照常", st == 200 and live_m.get("ok"), str(live_m))
        time.sleep(6)  # let the running case finish (its step 2 may now differ)
        deadline = time.time() + 30
        reg = None
        while time.time() < deadline:
            _, st_a = http("GET", "/api/rounds/A")
            reg = st_a.get("regression")
            if reg and reg.get("status") != "running":
                break
            time.sleep(0.4)
        check("2f3 并行现场操作后用例正常结束", reg is not None
              and reg.get("status") == "done", str(reg and reg.get("status")))

        # -- 4. NXDOMAIN + stale keep their step numbers ---------------------
        print("4. NXDOMAIN 与 stale 携带步骤号", flush=True)
        case_nx = [
            {"type": "mode", "mode": "a", "ip": "192.0.2.30", "delay_seconds": 3},
            {"type": "query", "expect_rcode": "NOERROR",
             "expect_ip": "192.0.2.30", "expect_step": 1},
            {"type": "mode", "mode": "nxdomain", "ip": "192.0.2.30", "delay_seconds": 3},
            {"type": "wait", "seconds": 6},
            {"type": "query", "expect_rcode": "NXDOMAIN",
             "expect_ip": "", "expect_step": 3},
            {"type": "query", "expect_rcode": "NXDOMAIN",
             "expect_ip": "", "expect_step": 3},
        ]
        res_nx = run("A", case_nx)
        check("4a NXDOMAIN 步骤全部通过", res_nx.get("ok")
              and all(s["status"] == "ok" for s in res_nx["reg"]["results"]),
              str([s["status"] for s in res_nx.get("reg", {}).get("results", [])]))
        if res_nx.get("ok"):
            cache = res_nx["state"]["cache"]
            check("4b 缓存保存 NXDOMAIN 与步骤号",
                  cache["rcode"] == "NXDOMAIN" and cache["a_record"] is None
                  and cache["auth_step"] == "3", str(cache))

        case_stale = [
            {"type": "mode", "mode": "a", "ip": "192.0.2.40", "delay_seconds": 3},
            {"type": "query", "expect_rcode": "NOERROR",
             "expect_ip": "192.0.2.40", "expect_step": 1},
            {"type": "mode", "mode": "timeout", "ip": "192.0.2.40", "delay_seconds": 3},
            {"type": "wait", "seconds": 6},
            {"type": "query", "expect_rcode": "NOERROR",
             "expect_ip": "192.0.2.40", "expect_step": 1},
        ]
        res_stale = run("A", case_stale)
        check("4c stale 沿用旧 A 的步骤号", res_stale.get("ok")
              and res_stale["reg"]["results"][4]["actual"]["source"] == "cache-stale"
              and res_stale["reg"]["results"][4]["actual"]["auth_step"] == "1",
              str(res_stale.get("reg", {}).get("results", [{}])[4] if res_stale.get("ok") else res_stale.get("error")))

        # -- 3. rounds A and B in parallel, isolated -------------------------
        print("3. 两轮并行、各自权威/缓存/日志", flush=True)
        case_b = [
            {"type": "mode", "mode": "a", "ip": "198.51.100.77", "delay_seconds": 2},
            {"type": "query", "expect_rcode": "NOERROR",
             "expect_ip": "198.51.100.77", "expect_step": 1},
            {"type": "query", "expect_rcode": "NOERROR",
             "expect_ip": "198.51.100.77", "expect_step": 1},
        ]
        par_a = [
            {"type": "mode", "mode": "a", "ip": "203.0.113.9", "delay_seconds": 2},
            {"type": "query", "expect_rcode": "NOERROR",
             "expect_ip": "203.0.113.9", "expect_step": 1},
            {"type": "wait", "seconds": 2},
            {"type": "query", "expect_rcode": "NOERROR",
             "expect_ip": "203.0.113.9", "expect_step": 1},
        ]
        out: dict[str, dict] = {}
        threads = [threading.Thread(target=lambda rid=rid, case=case:
                                    out.__setitem__(rid, run(rid, case)))
                   for rid, case in (("A", par_a), ("B", case_b))]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        check("3a 两轮并行均完成", out["A"].get("ok") and out["B"].get("ok"),
              f"A={out['A'].get('error')} B={out['B'].get('error')}")
        if out["A"].get("ok") and out["B"].get("ok"):
            ra, rb = out["A"]["state"], out["B"]["state"]
            ips_a = [s["actual"]["a_records"] for s in out["A"]["reg"]["results"] if s["actual"]]
            ips_b = [s["actual"]["a_records"] for s in out["B"]["reg"]["results"] if s["actual"]]
            check("3b 各自使用自己的权威地址",
                  ips_a == [["203.0.113.9"]] * 2 and ips_b == [["198.51.100.77"]] * 2,
                  f"A={ips_a} B={ips_b}")
            check("3c 缓存互不干扰",
                  ra["cache"]["a_record"] == "203.0.113.9"
                  and rb["cache"]["a_record"] == "198.51.100.77",
                  f"A={ra['cache']['a_record']} B={rb['cache']['a_record']}")
            check("3d 端口与数据库相互独立",
                  ra["auth_port"] != rb["auth_port"]
                  and ra["resolver_port"] != rb["resolver_port"]
                  and ra["db_path"] != rb["db_path"])
            check("3e 日志各自独立",
                  {r["qname"] for r in ra["auth_log"]}
                  == {r["qname"] for r in rb["auth_log"]}
                  and len(ra["auth_log"]) > 0)

        # -- 5. no DNS reply interrupts, results kept, resources recycled ------
        print("5. 未收到 DNS 报文时中断并保留结果", flush=True)
        # Start a case whose first steps pass, then freeze the round's resolver
        # (SIGSTOP keeps the process but stops it answering).  The next query
        # receives no reply at all, so the round is interrupted at that step;
        # earlier results are still reported and resources are recycled.
        http("POST", "/api/rounds/A/run", {"steps": [
            {"type": "mode", "mode": "a", "ip": "192.0.2.50", "delay_seconds": 1},
            {"type": "query", "expect_rcode": "NOERROR",
             "expect_ip": "192.0.2.50", "expect_step": 1},
            {"type": "wait", "seconds": 3},
            {"type": "query", "expect_rcode": "NOERROR",
             "expect_ip": "192.0.2.50", "expect_step": 1},
        ]})
        # Wait until the first query step has actually been measured, then
        # freeze the resolver during the wait step.
        deadline = time.time() + 20
        running = {}
        while time.time() < deadline:
            _, running = http("GET", "/api/rounds/A")
            reg = running.get("regression") or {}
            done = [r for r in reg.get("results", []) if r["step_no"] is not None]
            if any(r["step_no"] == 2 and r["status"] == "ok" for r in done):
                break
            time.sleep(0.2)
        pids = running.get("pids") or {}
        resolver_pid = pids.get("resolver")
        check("5a 用例运行中且可见子进程", bool(resolver_pid),
              f"pids={pids} reg={running.get('regression', {}).get('status')}")
        if resolver_pid:
            os.kill(resolver_pid, 19)  # SIGSTOP: alive but no replies
        deadline = time.time() + 45
        reg = None
        while time.time() < deadline:
            _, st = http("GET", "/api/rounds/A")
            reg = st.get("regression")
            if reg and reg.get("status") != "running":
                break
            time.sleep(0.4)
        if resolver_pid:
            try:
                os.kill(resolver_pid, 9)  # release the frozen child for cleanup
            except ProcessLookupError:
                pass
        check("5b 轮次被中断", reg is not None and reg.get("status") == "interrupted",
              str(reg and reg.get("status")))
        if reg:
            statuses = [s["status"] for s in reg["results"]]
            kept = statuses.count("ok")
            last = reg["results"][-1]
            check("5c 中断前结果保留、中断处被标出",
                  kept >= 2 and "fail" not in statuses
                  and last["status"] == "interrupted" and last["step_no"] == 4,
                  f"statuses={statuses} last={last['detail']}")
            check("5d 原因写明未收到 DNS 报文",
                  "未收到 DNS 报文" in (last["detail"] or ""),
                  str(last["detail"]))
        check("5e 中断后资源已回收", st_after_active("A") is False,
              str(http("GET", "/api/rounds/A")[1].get("pids")))

        # live operation without a case: start the round, query, then recycle
        st, started = http("POST", "/api/rounds/A/start", {})
        check("5f 可单独启动轮次供现场操作", st == 200 and started.get("ok"),
              str(started.get("error")))
        st, started_again = http("POST", "/api/rounds/A/start", {})
        check("5g 重复启动返回同一轮次", started_again.get("already") is True)
        st, empty = http("POST", "/api/rounds/A/mode",
                         {"mode": "a", "ip": "192.0.2.71", "delay_seconds": 1})
        st, live = http("POST", "/api/rounds/A/query", {})
        check("5h 空缓存现场查询回源且步骤号为空",
              live.get("ok") and live.get("source") == "upstream"
              and live.get("a_records") == ["192.0.2.71"]
              and live.get("auth_step") is None, str(live))
        http("POST", "/api/rounds/A/stop", {})

        # -- 6. endpoint start failure is reported at the interruption point --
        print("6. 端点启动失败：标注中断处与原因", flush=True)
        # Occupy the UDP ports the console would hand to round B, so its
        # authoritative endpoint cannot bind and startup fails.
        blockers = []
        try:
            # Block round B's whole probe window (base + 200), so port
            # allocation itself fails and neither endpoint can start.
            for port in range(26353, 26353 + 200):
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    s.bind(("127.0.0.1", port))
                    blockers.append(s)
                except OSError:
                    s.close()
            st, r = http("POST", "/api/rounds/B/run", {"steps": [
                {"type": "mode", "mode": "a", "ip": "192.0.2.60"},
                {"type": "query", "expect_rcode": "NOERROR", "expect_ip": "192.0.2.60"},
            ]})
            _, st_b = http("GET", "/api/rounds/B")
            reg = st_b.get("regression")
            check("6a 启动失败标记为中断", reg is not None
                  and reg.get("status") == "interrupted",
                  str(reg and reg.get("status")))
            if reg:
                check("6b 原因写明端点启动失败",
                      "启动" in reg["results"][0]["detail"]
                      or "失败" in reg["results"][0]["detail"],
                      reg["results"][0]["detail"])
                check("6c 未执行步骤标记为 skipped",
                      all(s["status"] in ("interrupted", "skipped")
                          for s in reg["results"]),
                      str([s["status"] for s in reg["results"]]))
            check("6d 启动失败后未残留进程", not st_b.get("active"),
                  str(st_b.get("pids")))
        finally:
            for s in blockers:
                s.close()

        # -- 7. page and API -------------------------------------------------
        print("7. 页面与接口", flush=True)
        with urllib.request.urlopen(BASE + "/", timeout=5) as r:
            body = r.read().decode()
        check("7a 页面包含用例编排与两轮",
              r.status == 200 and "回归" in body
              and "ROUND_IDS = [\'A\', \'B\']" in body
              and "const MAX_STEPS = 12, MAX_WAIT = 30" in body)
        check("7b 参数接口", p["domain"] == "service.example")
    finally:
        http("POST", "/api/rounds/A/stop", {}) if proc.poll() is None else None
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(8)
            except subprocess.TimeoutExpired:
                proc.kill()
        print(f"[regtest] logs in {TMP}", flush=True)

    print(f"\n{'=' * 60}")
    if FAILS:
        print(f"结果: {len(FAILS)} 项失败")
        for name in FAILS:
            print("  -", name)
        return 1
    print("结果: 全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
