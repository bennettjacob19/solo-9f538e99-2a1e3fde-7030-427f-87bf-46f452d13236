"""Caching UDP DNS resolver for one round of the fixed domain.

Behaviour (all timings from app.common, defaults are the spec values):

  * a successful A answer is cached fresh for FRESH_TTL (5s) and served from
    cache with the remaining TTL;
  * after expiry the resolver re-fetches.  If the upstream times out (or its
    reply is unusable) the old A record may be served stale for at most
    STALE_WINDOW (20s) past expiry; beyond that the answer is SERVFAIL;
  * NXDOMAIN is cached fresh only -- it is never used as stale backup;
  * confirming NXDOMAIN purges the old A record durably (SQLite), so no later
    answer contains the old A again;
  * every upstream attempt uses a dedicated socket with a random transaction
    ID and matches the question section, so a late answer to an already
    timed-out query is never read and can never resurrect the old A;
  * cache deadlines are absolute epochs persisted in SQLite, so a restart does
    not extend the validity of an old A record;
  * the authoritative endpoint tags each reply with the regression setting
    step it used (additional TXT ``_auth.<domain> "step=<n>"``).  That number
    is stored with the cached A / NXDOMAIN and echoed on every answer --
    upstream fetch, fresh cache hit and stale serve -- so two settings that
    use the same A address are still distinguishable.  It is empty when no
    setting step applies.

The resolver reports where each answer came from in an additional-section TXT
record (_src.<domain> TXT "source=upstream|cache-fresh|cache-stale|none
auth_step=<n>") and logs every query to the query_log table for the console.
"""
from __future__ import annotations

import os
import random
import socket
import threading
import time
import traceback

from dnslib import A, CLASS, QTYPE, RCODE, RR, TXT, DNSHeader, DNSRecord

from . import common

SRC_TXT = "_src."
AUTH_STEP_TXT = "_auth."


def _same_name(a, b) -> bool:
    return str(a).rstrip(".").lower() == str(b).rstrip(".").lower()


def _norm_step(step) -> str | None:
    """Normalize an authoritative step tag to a number string, or None."""
    if step is None:
        return None
    text = str(step).strip()
    return text or None


def _extract_auth_step(resp: DNSRecord) -> str | None:
    """Read the setting step the authoritative endpoint reports in ``_auth``."""
    for rr in resp.ar:
        if rr.rtype != QTYPE.TXT:
            continue
        if not _same_name(rr.rname, AUTH_STEP_TXT + common.FQDN):
            continue
        value = str(rr.rdata).strip('"')
        for part in value.split():
            if part.startswith("step="):
                return _norm_step(part.split("=", 1)[1])
    return None


def upstream_query() -> DNSRecord | None:
    """One-shot upstream A query for the fixed domain.

    A dedicated UDP socket per attempt plus a random transaction ID means a
    late answer to an earlier, already timed-out query can never be read back
    (the socket is closed) and can never be mistaken for the answer to a later
    query (ID + question must match).
    """
    query = DNSRecord.question(common.FQDN, "A")
    query.header.id = random.randint(0, 0xFFFF)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(query.pack(), (common.AUTH_HOST, common.AUTH_PORT))
        deadline = time.monotonic() + common.UPSTREAM_TIMEOUT
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            sock.settimeout(remaining)
            try:
                data, _addr = sock.recvfrom(4096)
            except socket.timeout:
                return None
            try:
                resp = DNSRecord.parse(data)
            except Exception:
                continue  # unparsable stray datagram: keep waiting
            if resp.header.id != query.header.id:
                continue  # stray/late packet for someone else: ignore
            if not _same_name(resp.q.qname, query.q.qname):
                continue
            return resp
    except OSError:
        return None
    finally:
        sock.close()


def _a_rr(ip: str, ttl: int) -> RR:
    return RR(common.FQDN, QTYPE.A, CLASS.IN, ttl, A(ip))


def _reply(query: DNSRecord, rcode: int, answers=(), source="none",
           detail="", auth_step: str | None = None) -> DNSRecord:
    rep = DNSRecord(
        DNSHeader(
            id=query.header.id, qr=1, aa=0, ra=1, rd=query.header.rd, rcode=rcode
        ),
        q=query.q,
    )
    for rr in answers:
        rep.add_answer(rr)
    step = _norm_step(auth_step)
    meta = f"source={source}" + (f" auth_step={step}" if step else " auth_step=")
    if detail:
        meta += f" {detail}"
    rep.add_ar(RR(SRC_TXT + common.FQDN, QTYPE.TXT, CLASS.IN, 0, TXT(meta)))
    return rep


def resolve_a(query: DNSRecord, db_path: str | None = None) -> tuple[DNSRecord, str, str]:
    """Resolve the fixed domain's A record.  Returns (reply, source, detail)."""
    now = time.time()
    row = common.get_cache(db_path)

    # 1) fresh cache hits -- the cached setting step travels with the answer
    if row and row["rcode"] == "NOERROR" and row["a_record"] and now < row["fresh_until"]:
        ttl = max(1, int(row["fresh_until"] - now + 0.999))
        return (
            _reply(query, RCODE.NOERROR, [_a_rr(row["a_record"], ttl)], "cache-fresh",
                   f"fresh_left={row['fresh_until'] - now:.1f}",
                   row["auth_step"]),
            "cache-fresh",
            "fresh A from cache",
        )
    if row and row["rcode"] == "NXDOMAIN" and now < row["fresh_until"]:
        return (
            _reply(query, RCODE.NXDOMAIN, [], "cache-fresh",
                   f"fresh_left={row['fresh_until'] - now:.1f}", row["auth_step"]),
            "cache-fresh",
            "fresh NXDOMAIN from cache",
        )

    # 2) expired: ask the authoritative endpoint
    resp = upstream_query()
    now2 = time.time()

    if resp is not None and resp.header.rcode == RCODE.NOERROR:
        ips = [str(rr.rdata) for rr in resp.rr if rr.rtype == QTYPE.A]
        if ips:
            auth_step = _extract_auth_step(resp)
            common.put_cache_a(ips[0], now2, auth_step=auth_step, db_path=db_path)
            return (
                _reply(query, RCODE.NOERROR, [_a_rr(ips[0], int(common.FRESH_TTL))],
                       "upstream", auth_step=auth_step),
                "upstream",
                f"fetched A={ips[0]}",
            )

    if resp is not None and resp.header.rcode == RCODE.NXDOMAIN:
        # Confirming NXDOMAIN purges the old A record (durably, in SQLite),
        # and keeps the setting step that produced the negative answer.
        auth_step = _extract_auth_step(resp)
        common.put_cache_nxdomain(now2, auth_step=auth_step, db_path=db_path)
        return (
            _reply(query, RCODE.NXDOMAIN, [], "upstream", "nxdomain-confirmed",
                   auth_step),
            "upstream",
            "NXDOMAIN confirmed; old A purged",
        )

    # 3) upstream timeout / unusable reply: maybe serve the stale A record
    #    (NXDOMAIN is never served stale).  The step cached with the A record
    #    is echoed again, since the stale answer still comes from that setting.
    row = common.get_cache(db_path)
    if (
        row
        and row["rcode"] == "NOERROR"
        and row["a_record"]
        and row["stale_until"]
        and now2 < row["stale_until"]
    ):
        ttl = max(1, int(row["stale_until"] - now2 + 0.999))
        return (
            _reply(query, RCODE.NOERROR, [_a_rr(row["a_record"], ttl)], "cache-stale",
                   f"stale_left={row['stale_until'] - now2:.1f}", row["auth_step"]),
            "cache-stale",
            "upstream timeout; serving stale A",
        )

    return (
        _reply(query, RCODE.SERVFAIL, [], "none", "upstream-timeout"),
        "none",
        "upstream timeout; no usable cache",
    )


def handle_packet(data: bytes, addr, sock: socket.socket,
                  db_path: str | None = None) -> None:
    qname = qtype = "?"
    try:
        query = DNSRecord.parse(data)
        qname = str(query.q.qname)
        qtype = QTYPE[query.q.qtype]
        if not _same_name(query.q.qname, common.FQDN):
            rep = _reply(query, RCODE.REFUSED, [], "none", "out-of-scope")
            source, detail = "none", "out-of-scope"
        elif query.q.qtype == QTYPE.A:
            rep, source, detail = resolve_a(query, db_path)
        else:
            rep = _reply(query, RCODE.NOERROR, [], "none", "nodata")
            source, detail = "none", "nodata"
        sock.sendto(rep.pack(), addr)
        answers = ";".join(
            f"{QTYPE[rr.rtype]}={rr.rdata}(ttl={rr.ttl})" for rr in rep.rr
        ) or "-"
        common.log_query(qname, qtype, source, RCODE[rep.header.rcode], answers,
                         detail, db_path)
    except Exception:
        common.log_query(qname, qtype, "error", "SERVFAIL", "-",
                         traceback.format_exc(limit=3), db_path)


def main() -> None:
    db_path = os.environ.get("DB_PATH") or common.DB_PATH
    port = int(os.environ.get("RESOLVER_PORT", common.RESOLVER_PORT))
    common.init_db(db_path)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    print(
        f"[resolver] {common.FQDN} on udp/{port}, "
        f"upstream {common.AUTH_HOST}:{common.AUTH_PORT}, db={db_path}, "
        f"fresh={common.FRESH_TTL}s stale={common.STALE_WINDOW}s "
        f"timeout={common.UPSTREAM_TIMEOUT}s",
        flush=True,
    )
    while True:
        data, addr = sock.recvfrom(4096)
        threading.Thread(target=handle_packet, args=(data, addr, sock, db_path),
                         daemon=True).start()


if __name__ == "__main__":
    main()
