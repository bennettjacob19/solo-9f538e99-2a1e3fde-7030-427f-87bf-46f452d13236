"""Local authoritative endpoint for one round of the fixed domain.

Its behaviour is switched at runtime via the round's control table (read on
every query, so changes take effect immediately):

  a        -- answer the configured A record (TTL = FRESH_TTL)
  nxdomain -- answer NXDOMAIN
  delay    -- answer the A record only after `delay_seconds` (longer than the
              resolver's upstream timeout, to exercise late-answer handling)
  timeout  -- never answer (simulates the authoritative endpoint being lost)

Each control row records the regression step (``step_no``) that applied it.
Every reply carries that number in an additional-section TXT record
(``_auth.<domain> TXT "step=<n>"``, empty when the setting came from outside
the regression) so the resolver can show which setting actually answered --
two steps may set the same A address, and the address alone cannot tell them
apart.

Every received query is logged to auth_log so the console can show what the
upstream actually saw and did.
"""
from __future__ import annotations

import os
import socket
import threading
import time
import traceback

from dnslib import A, QTYPE, RCODE, RR, TXT, DNSRecord

from . import common

AUTH_STEP_TXT = "_auth."


def _step_tag(step_no) -> str:
    if step_no is None or str(step_no).strip() == "":
        return "step="
    return f"step={step_no}"


def _add_step(rep: DNSRecord, step_no) -> None:
    rep.add_ar(RR(AUTH_STEP_TXT + common.FQDN, QTYPE.TXT, rdata=TXT(
        _step_tag(step_no)), ttl=0))


def handle(data: bytes, addr, sock: socket.socket) -> None:
    qname = qtype = "?"
    mode = "?"
    db_path = os.environ.get("DB_PATH") or common.DB_PATH
    try:
        query = DNSRecord.parse(data)
        qname = str(query.q.qname)
        qtype = QTYPE[query.q.qtype]
        ctl = common.get_control(db_path) or {
            "mode": "a", "ip": common.DEFAULT_IP,
            "delay_seconds": common.DEFAULT_DELAY, "step_no": None,
        }
        mode = ctl["mode"]
        step_no = ctl.get("step_no")
        step_tag = _step_tag(step_no)

        in_scope = (
            str(query.q.qname).rstrip(".").lower() == common.FIXED_DOMAIN.lower()
            and query.q.qtype in (QTYPE.A, QTYPE.ANY)
        )
        if not in_scope:
            rep = query.reply()
            rep.header.rcode = RCODE.NXDOMAIN
            _add_step(rep, step_no)
            sock.sendto(rep.pack(), addr)
            common.log_auth(qname, qtype, mode, "nxdomain",
                            f"out-of-scope name/qtype {step_tag}", db_path)
            return

        if mode == "timeout":
            common.log_auth(qname, qtype, mode, "dropped",
                            f"simulating lost authoritative endpoint {step_tag}",
                            db_path)
            return  # no answer at all -> the resolver's upstream times out

        if mode == "delay":
            time.sleep(max(0.0, float(ctl["delay_seconds"])))

        if mode == "nxdomain":
            rep = query.reply()
            rep.header.rcode = RCODE.NXDOMAIN
            _add_step(rep, step_no)
            sock.sendto(rep.pack(), addr)
            common.log_auth(qname, qtype, mode, "nxdomain",
                            f"confirmed negative {step_tag}", db_path)
            return

        # modes "a" and "delay": answer the configured A record
        rep = query.reply()
        rep.add_answer(
            RR(common.FQDN, QTYPE.A, rdata=A(ctl["ip"]), ttl=int(common.FRESH_TTL))
        )
        _add_step(rep, step_no)
        sock.sendto(rep.pack(), addr)
        suffix = (f" after {ctl['delay_seconds']}s delay" if mode == "delay" else "")
        common.log_auth(qname, qtype, mode, "answered",
                        f"A={ctl['ip']}{suffix} {step_tag}", db_path)
    except Exception:
        common.log_auth(qname, qtype, mode, "error",
                        traceback.format_exc(limit=3), db_path)


def main() -> None:
    db_path = os.environ.get("DB_PATH") or common.DB_PATH
    port = int(os.environ.get("AUTH_PORT", common.AUTH_PORT))
    common.init_db(db_path)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    print(f"[auth] authoritative for {common.FQDN} on udp/{port}", flush=True)
    while True:
        data, addr = sock.recvfrom(4096)
        threading.Thread(target=handle, args=(data, addr, sock),
                         daemon=True).start()


if __name__ == "__main__":
    main()
