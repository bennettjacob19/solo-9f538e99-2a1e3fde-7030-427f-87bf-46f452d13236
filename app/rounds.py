"""Per-round process supervision for the regression console.

A "round" (轮次) is an isolated regression lane: its own authoritative
endpoint, its own resolver, its own SQLite database and its own log ring.
Rounds share nothing, so two of them may run at the same time -- each uses its
own authoritative configuration, cache and logs, and every round starts from
an empty cache.

The web console is the only supervisor.  For each round it:

  * picks a free UDP port pair (auth, resolver) and creates the round's
    database under ``ROUND_DB_DIR``;
  * starts ``app.auth_server`` and ``app.resolver`` as child processes with
    round-specific ``DB_PATH`` / ports / upstream address, clearing the cache
    first so the round begins empty;
  * if either endpoint cannot be started or does not become reachable, marks
    the round interrupted ("启动失败") and records the cause, keeping the
    results measured so far;
  * on finish or interruption terminates both children and releases the ports
    and database, so nothing of that round leaks.

While a round is active, ad-hoc queries and manual authoritative mode switches
keep working through the same round endpoints: ``Round.query`` sends a real UDP
query to the round's resolver, ``Round.set_control`` switches the round's
authoritative endpoint.  A manual switch carries no regression step number, so
its answers report an empty setting step.

The regression executor (``app.regression``) drives ``Round.run_case``, which
executes the steps in a background thread so the console can poll progress and
keep serving live operations.
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field

from dnslib import QTYPE, RCODE, DNSRecord

from . import common

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROUND_IDS = ("A", "B")

# Error taxonomy surfaced to the executor / UI.
ERR_ENDPOINT_START = "endpoint-start"
ERR_ENDPOINT_DOWN = "endpoint-down"
ERR_NO_REPLY = "no-reply"
ERR_NO_REPLY_HINT = "未收到 DNS 报文"

PORT_BASES = {"A": 25353, "B": 26353}
PORT_LOCK = threading.Lock()
ROUNDS: dict[str, "Round"] = {}


def _free_udp_port(start: int, used: set[int]) -> int:
    for port in range(start, start + 200):
        if port in used:
            continue
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(("127.0.0.1", port))
            return port
        except OSError:
            continue
        finally:
            sock.close()
    raise OSError(f"no free UDP port near {start}")


def _probe(port: int, timeout: float) -> bool:
    """Send a real A query and expect any DNS reply."""
    query = DNSRecord.question(common.FQDN, "A")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(query.pack(), ("127.0.0.1", port))
        sock.recvfrom(4096)
        return True
    except OSError:
        return False
    finally:
        sock.close()


def _wait(probe, timeout: float, interval: float = 0.2) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if probe():
            return True
        time.sleep(interval)
    return False


@dataclass
class QueryResult:
    rcode: str | None
    answers: list[dict]
    source: str | None
    auth_step: str | None
    elapsed_ms: int
    error: str | None = None

    @property
    def a_records(self) -> list[str]:
        return [a["data"] for a in self.answers if a["type"] == "A"]

    def as_dict(self) -> dict:
        return {
            "rcode": self.rcode,
            "answers": self.answers,
            "a_records": self.a_records,
            "source": self.source,
            "auth_step": self.auth_step,
            "elapsed_ms": self.elapsed_ms,
            "error": self.error,
        }


@dataclass
class Round:
    round_id: str
    db_path: str
    auth_port: int = 0
    resolver_port: int = 0
    procs: dict = field(default_factory=dict)
    log_handles: list = field(default_factory=list)
    logs: list[str] = field(default_factory=list)
    started_at: float = 0.0
    # failure: dict(step, kind, reason, hint) or None
    failure: dict | None = None
    finished: bool = False
    current_step: int | None = None
    # regression progress: dict(status, results, started_at, finished_at, ...)
    regression: dict | None = None
    case_thread: threading.Thread | None = None
    case_lock: threading.Lock = field(default_factory=threading.Lock)
    stopped: threading.Event = field(default_factory=threading.Event)

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> None:
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        common.init_db(self.db_path)
        self.started_at = time.time()
        self._log(f"轮次 {self.round_id} 正在启动")

        with PORT_LOCK:
            used = _rounds_ports()
            try:
                self.auth_port = _free_udp_port(PORT_BASES[self.round_id], used)
                used.add(self.auth_port)
                self.resolver_port = _free_udp_port(self.auth_port + 1, used)
            except OSError as exc:
                self.fail(None, ERR_ENDPOINT_START,
                          f"端点启动失败：无法分配 UDP 端口：{exc}")
                return

        env = dict(os.environ)
        env.update(
            DB_PATH=self.db_path,
            FIXED_DOMAIN=common.FIXED_DOMAIN,
            AUTH_PORT=str(self.auth_port),
            RESOLVER_PORT=str(self.resolver_port),
            AUTH_HOST="127.0.0.1",
            PYTHONPATH=ROOT,
            PYTHONUNBUFFERED="1",
        )
        log_dir = os.path.join(os.path.dirname(self.db_path),
                               f"round-{self.round_id}-{int(self.started_at)}")
        os.makedirs(log_dir, exist_ok=True)

        if not self._spawn("auth", "app.auth_server", env, log_dir):
            return
        if not _wait(lambda: self._alive("auth")
                     and _probe(self.auth_port, 0.8), timeout=10):
            self.fail(None, ERR_ENDPOINT_START,
                      f"端点启动失败：权威端未能在 udp/{self.auth_port} 启动")
            self.stop_processes()
            return

        if not self._spawn("resolver", "app.resolver", env, log_dir):
            return
        if not _wait(lambda: self._alive("resolver")
                     and _probe(self.resolver_port, 3.5), timeout=12):
            self.fail(None, ERR_ENDPOINT_START,
                      f"端点启动失败：解析器未能在 udp/{self.resolver_port} 启动")
            self.stop_processes()
            return

        # Readiness probes filled the cache and logs; a round must start empty.
        common.reset_round_state(self.db_path)
        self._log(f"轮次 {self.round_id} 就绪"
                  f"（权威端 udp/{self.auth_port}，解析器 udp/{self.resolver_port}）")

    def _spawn(self, name: str, module: str, env: dict, log_dir: str) -> bool:
        handle = open(os.path.join(log_dir, f"{name}.log"), "ab")
        self.log_handles.append(handle)
        try:
            self.procs[name] = subprocess.Popen(
                [sys.executable, "-m", module],
                cwd=ROOT, env=env, stdout=handle, stderr=subprocess.STDOUT,
            )
        except OSError as exc:
            self.fail(None, ERR_ENDPOINT_START, f"{name} 启动失败：{exc}")
            self.stop_processes()
            return False
        return True

    def check_running(self) -> dict | None:
        """Detect a died endpoint.  Returns failure info (or None if healthy)."""
        if self.failure:
            return self.failure
        for name in ("auth", "resolver"):
            proc = self.procs.get(name)
            if proc is not None and proc.poll() is not None:
                label = "权威端" if name == "auth" else "解析器"
                self.fail(self.current_step, ERR_ENDPOINT_DOWN,
                          f"{label}进程已退出（rc={proc.returncode}）")
                return self.failure
        return None

    # -- operations --------------------------------------------------------
    def set_control(self, mode: str, ip: str, delay: float,
                    step_no: int | None = None) -> None:
        common.set_control(mode, ip, delay, step_no=step_no, db_path=self.db_path)
        where = f"step {step_no}" if step_no is not None else "手动"
        self._log(f"{where}: 权威设置 mode={mode} ip={ip} delay={delay:g}s")

    def query(self, timeout: float = 12.0) -> QueryResult:
        """One real A query at this round's resolver."""
        t0 = time.time()
        query = DNSRecord.question(common.FQDN, "A")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(timeout)
            sock.sendto(query.pack(), ("127.0.0.1", self.resolver_port))
            data, _ = sock.recvfrom(4096)
        except socket.timeout:
            return QueryResult(None, [], None, None,
                               int((time.time() - t0) * 1000),
                               error=ERR_NO_REPLY)
        except OSError as exc:
            return QueryResult(None, [], None, None,
                               int((time.time() - t0) * 1000),
                               error=f"{type(exc).__name__}: {exc}")
        finally:
            sock.close()

        rep = DNSRecord.parse(data)
        answers = [
            {"name": str(rr.rname), "type": QTYPE[rr.rtype],
             "data": str(rr.rdata), "ttl": rr.ttl}
            for rr in rep.rr
        ]
        source = auth_step = None
        for rr in rep.ar:
            if rr.rtype != QTYPE.TXT:
                continue
            text = str(rr.rdata).strip('"')
            if text.startswith("source="):
                source = text.split("=", 1)[1].split()[0]
                for part in text.split():
                    if part.startswith("auth_step="):
                        auth_step = part.split("=", 1)[1] or None
        return QueryResult(rcode=RCODE[rep.header.rcode], answers=answers,
                           source=source, auth_step=auth_step,
                           elapsed_ms=int((time.time() - t0) * 1000))

    # -- case execution ----------------------------------------------------
    def run_case(self, steps: list[dict]) -> None:
        """Start a regression case in the background (at most one at a time)."""
        if self.finished:
            raise RuntimeError("轮次已结束，资源已回收")
        with self.case_lock:
            thread = self.case_thread
            if thread is not None and thread.is_alive():
                raise RuntimeError("轮次仍在运行")
            self.regression = {
                "status": "running",
                "results": [],
                "steps": steps,
                "started_at": time.time(),
                "finished_at": None,
            }
            if self.failure:
                # Endpoints never came up: report the interruption at startup
                # and keep every step unexecuted.  Nothing is left running.
                from . import regression
                regression.record_startup_failure(self, steps)
                self.regression["status"] = "interrupted"
                self.regression["finished_at"] = time.time()
                self.finish()
                return
            self.stopped.clear()
            self.case_thread = threading.Thread(
                target=self._run_case_thread, args=(steps,), daemon=True)
            self.case_thread.start()

    def _run_case_thread(self, steps: list[dict]) -> None:
        from . import regression
        try:
            regression.execute(self, steps)
        except Exception as exc:  # noqa: BLE001 - never leave a round half-open
            self.fail(self.current_step, "internal", f"执行器异常：{exc}")
            self.regression["results"].append({
                "step_no": self.current_step, "type": "internal",
                "description": "执行器异常", "status": "interrupted",
                "detail": f"{type(exc).__name__}: {exc}", "actual": None,
            })
        finally:
            was_stopped = self.stopped.is_set()
            self.finish()
            self.regression["status"] = (
                "interrupted" if (self.failure or was_stopped) else "done")
            self.regression["finished_at"] = time.time()

    def wait_case(self, timeout: float | None = None) -> None:
        if self.case_thread is not None:
            self.case_thread.join(timeout)

    def _record_stop(self) -> None:
        """Note an externally triggered stop in the case results."""
        if not self.regression or self.regression.get("status") != "running":
            return
        from .regression import PROGRESS_LOCK
        with PROGRESS_LOCK:
            self.regression["results"].append({
                "step_no": self.current_step, "type": "stop",
                "description": "轮次被手动结束", "status": "interrupted",
                "detail": "轮次被手动结束，资源已回收", "actual": None,
            })

    def finish(self) -> None:
        """Round complete: stop its processes and release its resources."""
        if not self.finished:
            running = (self.case_thread is not None
                       and self.case_thread.is_alive()
                       and threading.current_thread() is not self.case_thread)
            if running and not self.failure:
                # Stopped from outside while a case was mid-flight: mark the
                # interruption at whichever step was running so the report
                # says what happened instead of the next step failing blindly.
                self._log(f"中断于步骤 {self.current_step}：轮次被手动结束，资源已回收")
                self._record_stop()
            self._log(f"轮次 {self.round_id} 结束，回收资源")
            self.stopped.set()
            self.stop_processes()
            self.finished = True

    def stop_processes(self) -> None:
        for name, proc in self.procs.items():
            if proc.poll() is None:
                proc.terminate()
        for name, proc in list(self.procs.items()):
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass
            self._log(f"{name} 已回收")
        self.procs.clear()
        for handle in self.log_handles:
            try:
                handle.close()
            except OSError:
                pass
        self.log_handles.clear()

    # -- failure / logging -------------------------------------------------
    def fail(self, step_no, kind: str, reason: str, hint: str = "") -> None:
        self.current_step = step_no
        self.failure = {"step": step_no, "kind": kind, "reason": reason,
                        "hint": hint}
        self._log(f"中断于步骤 {step_no if step_no is not None else '启动'}："
                  f"{reason}")

    def fail_no_reply(self, step_no: int, reason: str = "未收到 DNS 报文") -> None:
        self.fail(step_no, ERR_NO_REPLY, reason, ERR_NO_REPLY_HINT)

    def _log(self, message: str) -> None:
        self.logs.append(f"[{time.strftime('%H:%M:%S')}] {message}")
        del self.logs[:-300]

    def _alive(self, name: str) -> bool:
        proc = self.procs.get(name)
        return proc is not None and proc.poll() is None

    def as_dict(self) -> dict:
        failure = None
        if self.failure:
            step = self.failure["step"]
            failure = dict(self.failure)
            failure["message"] = (
                f"步骤 {step if step is not None else '启动'} 中断："
                f"{self.failure['reason']}"
            )
        return {
            "round": self.round_id,
            "db_path": self.db_path,
            "auth_port": self.auth_port,
            "resolver_port": self.resolver_port,
            "pids": {name: p.pid for name, p in self.procs.items()},
            "active": bool(self.procs),
            "cache": common.get_cache(self.db_path),
            "failure": failure,
            "finished": self.finished,
            "regression": self.regression,
            "logs": list(self.logs[-60:]),
            "resolver_log": common.recent("query_log", 30, self.db_path),
            "auth_log": common.recent("auth_log", 30, self.db_path),
        }


def _rounds_ports() -> set[int]:
    """UDP ports currently held by live rounds (best effort)."""
    ports: set[int] = set()
    for rnd in ROUNDS.values():
        if not rnd.finished:
            if rnd.auth_port:
                ports.add(rnd.auth_port)
            if rnd.resolver_port:
                ports.add(rnd.resolver_port)
    return ports


def get_round(round_id: str) -> Round | None:
    return ROUNDS.get(round_id)


def start_round(round_id: str) -> Round:
    # One starter at a time, so two requests for the same round can never
    # allocate the same ports or share a database file name.
    with START_LOCK:
        old = ROUNDS.get(round_id)
        if old is not None and not old.finished:
            old.finish()
        stamp = time.strftime("%Y%m%d-%H%M%S") + f"-{time.time_ns() % 1_000_000:06d}"
        db_path = os.path.join(common.ROUND_DB_DIR, f"round-{round_id}-{stamp}.db")
        rnd = Round(round_id=round_id, db_path=db_path)
        ROUNDS[round_id] = rnd
        rnd.start()
        return rnd


START_LOCK = threading.Lock()
