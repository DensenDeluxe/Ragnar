#!/usr/bin/env python3
"""
DNS Doctor passive tier -- three-thread engine.

  1. CAPTURE   blocks in scapy's sniff(), enqueues raw frames
  2. DETECT    dequeues, parses, runs the detectors, enqueues findings
  3. EMIT      formats JSON-lines, rate-limits, writes

Splitting capture from detection is what keeps a slow detector from
dropping packets: the capture thread does nothing but hand bytes to a
BOUNDED queue. When the queue is full frames are DROPPED and COUNTED
rather than buffered without limit -- an unbounded queue on a 512 MB
Pi is just a slower crash, and a silent drop is worse than a counted
one.

PASSIVE INVARIANT: this module never transmits. Unlike ntpwatch (which
has a --probe mode and therefore needs an allowlist), DNS Doctor's
passive tier is transmit-free outright, so the invariant is a flat ban
on sending primitives -- enforced by an AST check in conformance.py
rather than a grep, because a grep trips over this very docstring
(the legacywatch lesson).
"""
import argparse
import json
import queue
import sys
import threading
import time

import parse
import detect
import netscope
import mdns as mdns_tier
import ddns as ddns_tier
import rdns as rdns_tier
import llmnr as llmnr_tier
import nbns as nbns_tier
import encrypted as enc_tier
from bailiwick import zone_of_query
from state import (Config, ZoneTable, InFlight, XferTable, CensusTable,
                   UpdatePending, WalkTable, CounterTable)
from findings import (FINDINGS, BASELINE_DEPENDENT, PREFIX_DEPENDENT,
                      PREFIX_CONFIG_KEY)

# Port 5353 joins the filter for the mDNS tier. Kept as ONE filter
# rather than two captures so there is a single capture path to reason
# about, with the port split done in software immediately after parse.
# Five protocols now share one capture. Kept as ONE filter rather
# than five captures so there is a single capture path to reason
# about, with the fork done in software immediately after L4 parsing.
BPF_FILTER = ("(udp or tcp) and (port 53 or port 5353 or port 5355 "
              "or port 137 or port 853)")
MDNS_PORT = 5353
LLMNR_PORT = 5355
NBNS_PORT = 137
ENCRYPTED_PORT = 853

# The CLI flag that arms each prefix-dependent code. This map exists
# instead of deriving the flag from the config key, because the two are
# NOT the same string -- and the first version of --print-codes did
# derive it, which printed "[needs --mdns-local-prefixes]" for a flag
# actually spelled --mdns-prefix. A gate label that names a flag the
# parser does not accept is worse than no label: it tells an operator
# the check is armable and then fails them at the shell.
# conformance.py asserts every flag here is one argparse really takes.
PREFIX_CLI_FLAG = {
    "xfr_allowed_secondary_prefixes": "--xfr-secondary-prefix",
    "mdns_local_prefixes": "--mdns-prefix",
    "ddns_allowed_updater_prefixes": "--ddns-updater-prefix",
    "rdns_internal_prefixes": "--rdns-internal-prefix",
}


class Stats:
    __slots__ = ("frames", "parsed", "dropped", "findings", "malformed", "not_dns")

    def __init__(self):
        self.frames = self.parsed = self.dropped = 0
        self.findings = self.malformed = self.not_dns = 0


class Engine:
    """
    Detection core. Deliberately constructible and drivable WITHOUT
    any capture: handle_frame() takes bytes. Every offline tier uses
    this entry point, and the lab drives the same one through a real
    NIC, so there is no separate 'test path' that can diverge from
    production.
    """

    def __init__(self, cfg=None, emit=None):
        self.cfg = cfg or Config()
        self.zones = ZoneTable(self.cfg)
        self.inflight = InFlight(self.cfg)
        self.xfers = XferTable(self.cfg)
        self.census = CensusTable(self.cfg.mdns_census_max)
        self.mdns_local_nets, bad = netscope.parse_prefixes(
            self.cfg.mdns_local_prefixes)
        self.mdns_bad_prefixes = bad

        # DDNS: pending requests awaiting a verdict, plus a
        # first-sighting set so a steady-state posture fact is not
        # re-reported on every update a DHCP server sends.
        self.pending = UpdatePending(self.cfg)
        self.ddns_allowed_nets, bad_d = netscope.parse_prefixes(
            self.cfg.ddns_allowed_updater_prefixes)
        self.ddns_bad_prefixes = bad_d
        self.ddns_seen = CensusTable(self.cfg.mdns_census_max)

        # rDNS: per-source walk windows, and a first-sighting set keyed
        # on (destination, leaked network) -- a misconfigured resolver
        # leaks the same prefix thousands of times a day.
        self.walks = WalkTable(self.cfg)
        self.rdns_internal_nets, bad_r = netscope.parse_prefixes(
            self.cfg.rdns_internal_prefixes)
        self.rdns_bad_prefixes = bad_r
        self.rdns_seen = CensusTable(self.cfg.mdns_census_max)

        # One shared first-sighting table for every posture code that
        # reports a STATE rather than an event (LLMNR/NBNS in use,
        # WPAD queries, encrypted-transport sessions, DNS-SD
        # enumeration, SIG(0)). Shared rather than one per tier
        # because every key is already prefixed with its code, so a
        # single bounded table cannot confuse them -- and five
        # separate LRUs would each need their own cap to tune.
        self.posture = CensusTable(self.cfg.posture_seen_max)
        self.nbstat = CounterTable(cap=self.cfg.walk_max_sources,
                                   window=self.cfg.nbstat_window_seconds)
        self.own_resolver_nets, bad_o = netscope.parse_prefixes(
            self.cfg.dns_own_resolver_prefixes)
        self.own_resolver_bad_prefixes = bad_o
        self.xfr_secondary_nets, bad_x = netscope.parse_prefixes(
            self.cfg.xfr_allowed_secondary_prefixes)
        self.xfr_bad_prefixes = bad_x
        self.stats = Stats()
        self._emit = emit or (lambda f: None)
        self._last_sweep = 0.0

    # -- detection ----------------------------------------------------
    def handle_frame(self, frame, now=None):
        now = time.monotonic() if now is None else now
        self.stats.frames += 1

        r = parse.parse_l3_l4(frame)
        if r is None:
            self.stats.not_dns += 1
            return []
        src, dst, sport, dport, proto, payload, ip_ttl = r
        is_tcp = proto == "tcp"

        # PORT ROUTING. mDNS and unicast DNS share a wire format but
        # not a rule set, and crossing them is a false-positive
        # generator in both directions. Every mDNS name ends in
        # .local and is out of bailiwick for any queried zone, so
        # MaginotDNS (DNSD-006) alone would fire on essentially every
        # mDNS announcement on the network. The unicast detectors
        # therefore run ONLY on port 53 and the mDNS tier ONLY on
        # 5353; neither ever sees the other's traffic.
        # ============ PORT FORK ============
        # Five protocols, five rule sets, and three of them share the
        # DNS header layout while meaning different things by it. Every
        # fork below exists because crossing it produces plausible
        # findings rather than obvious failures:
        #
        #   5353 mDNS   -- every name ends .local and is out of
        #                  bailiwick, so DNSD-006 alone would fire on
        #                  essentially every announcement.
        #   5355 LLMNR  -- same wire format as DNS, but RFC 4795 does
        #                  NOT require TTL 255 the way mDNS does, so
        #                  the mDNS scope rule must not reach it.
        #   137  NBNS   -- OPCODE 5 MEANS NAME REGISTRATION HERE, and
        #                  in DNS it means UPDATE. Reaching the opcode
        #                  fork, an ordinary Windows registration storm
        #                  would be reported as unsigned dynamic
        #                  updates being accepted. Forked FIRST, before
        #                  the opcode router, for exactly that reason.
        #   853  DoT/DoQ -- encrypted. There is nothing to parse, and
        #                  attempting it would read ciphertext as a
        #                  DNS header and report malformed packets
        #                  forever.
        #   53   DNS    -- the ordinary tier, itself forked by opcode.
        #
        # conformance.py asserts the whole matrix, in both directions
        # for every pair.

        # --- 853: encrypted. Never parsed as DNS. -------------------
        if sport == ENCRYPTED_PORT or dport == ENCRYPTED_PORT:
            out = enc_tier.detect_encrypted_session(
                self.cfg, self.posture, src, dst, sport, dport, proto, payload,
                self.own_resolver_nets, now)
            for f in out:
                self.stats.findings += 1
                self._emit(f)
            return out

        # --- 137: NBNS. Forked BEFORE the opcode router. ------------
        if sport == NBNS_PORT or dport == NBNS_PORT:
            if not self.cfg.nbns_enabled:
                return []
            msg = parse.parse_dns(payload)
            self.stats.parsed += 1
            if msg.malformed:
                self.stats.malformed += 1
            out = nbns_tier.handle_nbns(msg, self.cfg, self.posture, self.nbstat,
                                        src, dst, now)
            for f in out:
                self.stats.findings += 1
                self._emit(f)
            return out

        # --- 5355: LLMNR. DNS wire format, different rules. ---------
        if sport == LLMNR_PORT or dport == LLMNR_PORT:
            if not self.cfg.llmnr_enabled:
                return []
            msg = parse.parse_dns(payload)
            self.stats.parsed += 1
            if msg.malformed:
                self.stats.malformed += 1
            out = llmnr_tier.handle_llmnr(msg, self.cfg, self.posture, src, dst, now)
            for f in out:
                self.stats.findings += 1
                self._emit(f)
            return out

        is_mdns = (sport == MDNS_PORT or dport == MDNS_PORT)
        if is_mdns:
            if not self.cfg.mdns_enabled:
                return []
            msg = parse.parse_dns(payload)
            self.stats.parsed += 1
            if msg.malformed:
                self.stats.malformed += 1
            out = mdns_tier.handle_mdns(msg, self.cfg, self.census,
                                        src, dst, ip_ttl, self.mdns_local_nets, now)
            for f in out:
                self.stats.findings += 1
                self._emit(f)
            return out

        msg = parse.parse_dns(payload)
        self.stats.parsed += 1
        if msg.malformed:
            self.stats.malformed += 1

        q = msg.questions[0] if msg.questions else None
        cfg = self.cfg
        is_update = ddns_tier.is_update(msg)
        if is_update:
            # RFC 2136 names the zone outright in the ZONE section;
            # deriving it by bailiwick would only add a way to be wrong.
            zone = ddns_tier._zone_of_update(msg)
        else:
            zone = zone_of_query(q["name"]) if q else "."
        zstate = self.zones.get(zone, now)
        out = []

        # ---- OPCODE-INDEPENDENT STRUCTURAL LAYER -------------------
        # These four judge the WIRE ENCODING, which an opcode cannot
        # change, so they run on QUERY and UPDATE alike.
        #
        # TuDoor first: a malformed message may still have partial
        # sections worth looking at, but the malformation is itself
        # the finding and should be reported even if nothing else is.
        out += detect.detect_tudoor(msg, cfg, zone)
        # DNSD-008 is deliberately evaluated alongside (not instead of)
        # DNSD-007: a pointer anomaly is a memory-safety primitive and
        # must not be buried under the generic malformed-packet notice.
        out += detect.detect_pointer_anomaly(msg, cfg, zone)
        # TSIG and SIG structure. Both appear in queries, responses,
        # transfers and updates; neither assertion cares which.
        out += detect.detect_tsig_malformed(msg, cfg, zone)
        out += detect.detect_sigred(msg, cfg, zone, is_tcp)
        # TSIG and SIG(0) posture. Opcode-independent for the same
        # reason the structural checks are: TSIG covers queries,
        # responses, transfers, NOTIFY and updates alike, and a weak
        # algorithm or a wide replay window is the same weakness in
        # each.
        out += detect.detect_tsig_posture(msg, cfg, zone)
        out += detect.detect_sig0(msg, cfg, zone, self.posture, src, now)

        # ---- OPCODE ROUTING ----------------------------------------
        # An UPDATE reuses all four section counts with different
        # meanings (ZONE / PREREQUISITE / UPDATE / ADDITIONAL), so
        # handing one to the QUERY detectors produces a quiet drip of
        # plausible-looking findings -- a prerequisite failure is a
        # perfectly ordinary NXDOMAIN, an updater's source port is not
        # a resolver's, and a bulk update legitimately repeats records.
        # This is the same hazard the mDNS port split exists for, and
        # it is handled the same way: one hard fork, no overlap.
        if is_update:
            out += ddns_tier.handle_ddns(msg, cfg, self.pending, self.ddns_seen,
                                         src, dst, sport, dport,
                                         self.ddns_allowed_nets, now)
            if now - self._last_sweep > 5.0:
                self.inflight.sweep(now)
                self.xfers.sweep(now)
                self.pending.sweep(now)
                self._last_sweep = now
            for f in out:
                self.stats.findings += 1
                self._emit(f)
            return out

        if msg.qr:
            # ---- response path ----
            out += detect.detect_keytrap(msg, cfg, zone)
            out += detect.detect_nxnsattack(msg, cfg, zone, zstate, now)
            out += detect.detect_maginotdns(msg, cfg, zone)
            out += detect.detect_nsec3_iterations(msg, cfg, zone)
            out += detect.detect_algo_downgrade(msg, cfg, zone)
            out += detect.detect_dnskey_malformed(msg, cfg, zone)
            out += detect.detect_rrsig_label_mismatch(msg, cfg, zone)
            out += detect.detect_nsec_next_out_of_zone(msg, cfg, zone)
            out += detect.detect_nsec3_apex_impersonation(msg, cfg, zone)
            out += detect.detect_nsec_nsec3_coexistence(msg, cfg, zone)
            out += detect.detect_svcb_alias_abuse(msg, cfg, zone)
            out += detect.detect_edns_option_duplication(msg, cfg, zone)
            out += detect.detect_duplicate_rr_flood(msg, cfg, zone)
            out += detect.detect_dnssd_fanout(msg, cfg, zone)
            out += enc_tier.handle_encrypted_dns_query(msg, cfg, self.posture,
                                                       src, dst, now)
            out += detect.detect_dnsbomb(msg, cfg, zone, zstate, now)
            out += detect.detect_nsec3_encloser(msg, cfg, zone, zstate, now)
            out += detect.detect_water_torture(msg, cfg, zone, zstate, now)
            if q is not None:
                key = (msg.txid, tuple(q["name"].lower_labels()), q["qtype"], dport)
                out += detect.detect_sad_dns_conflict(msg, cfg, zone, self.inflight, key, now)
            # A transfer RESPONSE may legally omit the Question section
            # after the first message (RFC 5936 s2.2), so the stream is
            # looked up whenever one exists for this conversation --
            # not only when the qtype is still visible in the packet.
            # Keying on the question alone would have dropped every
            # message after the first on a conforming multi-message
            # transfer, which is precisely the traffic DNSD-060..063
            # exist to judge.
            xkey = (bytes(src), bytes(dst), sport, dport)
            xs = self.xfers.streams.get(xkey) if is_tcp else None
            if xs is None and is_tcp and q is not None \
                    and q["qtype"] in (parse.QT_IXFR, parse.QT_AXFR):
                xs = self.xfers.get(xkey, now, q["qtype"], client=bytes(dst))
            if xs is not None:
                xs.last_seen = now
                # Structure is judged BEFORE the counters advance, so
                # "is this the first message" and "has an SOA been seen
                # already" still describe the state this message
                # arrived into.
                out += detect.detect_axfr_structure(msg, cfg, zone, xs, is_tcp)
                out += detect.detect_ixfr_soa_apex(msg, cfg, zone, xs, is_tcp)
                out += detect.detect_xfr_tsig_absent(msg, cfg, zone, xs, now, is_tcp)
                xs.records += len(msg.answers)
                xs.first_message_done = True
                out += detect.detect_xfr_completed_disclosure(
                    msg, cfg, zone, xs, self.xfr_secondary_nets, bytes(dst), now, is_tcp)
        else:
            # ---- query path ----
            out += detect.detect_tkey_query(msg, cfg, zone)
            if is_tcp and q is not None and q["qtype"] in (parse.QT_IXFR, parse.QT_AXFR):
                # Register the transfer from the QUERY side so the
                # response stream is keyed on the same conversation,
                # and record WHO asked -- the client address is what
                # DNSD-061 judges, and by the time the terminating SOA
                # arrives the query is long gone.
                self.xfers.get((bytes(dst), bytes(src), dport, sport), now,
                               q["qtype"], client=bytes(src))
            # RFC 5936 s4.2 leaves AXFR over UDP undefined. Checked on
            # the UDP path specifically, and AXFR-only: RFC 1995 s2
            # permits IXFR over UDP outright.
            out += detect.detect_axfr_over_udp(msg, cfg, zone, is_tcp)
            if q is not None:
                key = (msg.txid, tuple(q["name"].lower_labels()), q["qtype"], sport)
                self.inflight.note_query(key, now)
                zstate.push("query_times", now, cfg.ring_size)
                out += detect.detect_source_port_entropy(cfg, zone, zstate, sport, now)
            # rDNS leg. Query-side only: both checks are about what a
            # client ASKS FOR and who it asks, neither about answers.
            out += rdns_tier.handle_rdns(msg, cfg, self.walks, self.rdns_seen,
                                         src, dst, self.rdns_internal_nets, now)
            out += detect.detect_dnssd_enumeration(msg, cfg, self.posture, src, now)
            # The encrypted-DNS precursors: both travel in cleartext
            # on port 53, because a client probing for an encrypted
            # endpoint does not yet know where it is.
            out += enc_tier.handle_encrypted_dns_query(msg, cfg, self.posture,
                                                       src, dst, now)

        if now - self._last_sweep > 5.0:
            self.inflight.sweep(now)
            self.xfers.sweep(now)
            self.pending.sweep(now)
            self._last_sweep = now

        for f in out:
            self.stats.findings += 1
            self._emit(f)
        return out

    # -- live capture (LESSON C: the one path no offline tier runs) ---
    def sniff_live(self, iface, count=0, timeout=None, _sniff=None, _queue=None):
        """
        Wraps scapy's sniff(). scapy is imported HERE, lazily, so every
        offline tier can import this module on a host without it.

        `_sniff` and `_queue` exist so conformance.py can drive this
        exact function with a recorder and assert what it passes:
        iface, BPF filter installed, store=False, and offline= NOT set
        (an offline= kwarg would mean it was reading a file, not a
        wire). That is the whole point of the seam -- the live path is
        otherwise never executed until it runs on a Pi.
        """
        if _sniff is None:
            from scapy.all import sniff as _sniff  # noqa: N806

        q = _queue if _queue is not None else queue.Queue(maxsize=4096)

        def _cb(pkt):
            try:
                raw = bytes(pkt)
            except Exception:
                return
            try:
                q.put_nowait(raw)
            except queue.Full:
                self.stats.dropped += 1

        _sniff(iface=iface, filter=BPF_FILTER, prn=_cb, store=False,
               count=count, timeout=timeout)
        return q

    def drain(self, q, now=None):
        """Detection thread body, callable synchronously for tests."""
        out = []
        while True:
            try:
                frame = q.get_nowait()
            except queue.Empty:
                break
            out += self.handle_frame(frame, now)
        return out


class RateLimiter:
    """Per-zone emission cap. A flood must not turn into a finding
    flood -- the alert path is a phone notification, and 10k pages is
    the same as none."""
    __slots__ = ("per_second", "buckets")

    def __init__(self, per_second=100):
        self.per_second = per_second
        self.buckets = {}

    def allow(self, zone, now):
        sec = int(now)
        cur = self.buckets.get(zone)
        if cur is None or cur[0] != sec:
            self.buckets[zone] = [sec, 1]
            return True
        if cur[1] >= self.per_second:
            return False
        cur[1] += 1
        return True


def run(iface, cfg=None, out_stream=None, timeout=None):
    """Wire the three threads together."""
    cfg = cfg or Config()
    out_stream = out_stream or sys.stdout
    frames = queue.Queue(maxsize=4096)
    findings_q = queue.Queue(maxsize=4096)
    limiter = RateLimiter()
    stop = threading.Event()

    engine = Engine(cfg, emit=lambda f: findings_q.put_nowait(f))

    def capture():
        try:
            engine.sniff_live(iface, timeout=timeout, _queue=frames)
        finally:
            stop.set()

    def detect_loop():
        while not stop.is_set() or not frames.empty():
            try:
                frame = frames.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                engine.handle_frame(frame)
            except Exception as e:  # a detector bug must not kill capture
                print(f"detector error: {type(e).__name__}: {e}", file=sys.stderr)

    def emit_loop():
        while not stop.is_set() or not findings_q.empty():
            try:
                f = findings_q.get(timeout=0.2)
            except queue.Empty:
                continue
            now = time.time()
            if not limiter.allow(f["zone"], now):
                continue
            f["ts"] = now
            out_stream.write(json.dumps(f) + "\n")
            out_stream.flush()

    threads = [threading.Thread(target=t, daemon=True)
               for t in (capture, detect_loop, emit_loop)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return engine.stats


def main():
    p = argparse.ArgumentParser(description="DNS Doctor -- passive DNS/DNSSEC tier")
    p.add_argument("-i", "--iface")
    p.add_argument("--timeout", type=float, default=None)
    p.add_argument("--enable-baseline-detectors", action="store_true",
                   help=f"enable the baseline-dependent detectors "
                        f"({', '.join(sorted(BASELINE_DEPENDENT))}). OFF by default: they "
                        f"cannot emit until a per-zone baseline is warm, which a "
                        f"grab-and-go deployment does not have time to build.")
    p.add_argument("--exclude-zone", action="append", default=[],
                   help="zone to suppress behavioural findings for (repeatable)")
    p.add_argument("--max-zones", type=int, default=None)
    p.add_argument("--mdns-prefix", action="append", default=[],
                   dest="mdns_prefixes", metavar="CIDR",
                   help="CIDR belonging to THIS link; enables DNSD-075/076 "
                        "(repeatable). Without it both stay silent, because "
                        "guessing off-link from address class is wrong on a "
                        "publicly-addressed LAN.")
    p.add_argument("--ddns-updater-prefix", action="append", default=[],
                   dest="ddns_prefixes", metavar="CIDR",
                   help="CIDR permitted to send dynamic updates; enables "
                        "DNSD-082 (repeatable).")
    p.add_argument("--rdns-internal-prefix", action="append", default=[],
                   dest="rdns_prefixes", metavar="CIDR",
                   help="CIDR of your own resolvers/networks; enables DNSD-090 "
                        "(repeatable).")
    p.add_argument("--no-ddns", action="store_true",
                   help="disable the DDNS tier (RFC 2136 opcode 5)")
    p.add_argument("--no-rdns", action="store_true",
                   help="disable the rDNS tier (PTR)")
    p.add_argument("--own-resolver-prefix", action="append", default=[],
                   dest="own_resolver_prefixes", metavar="CIDR",
                   help="CIDR of resolvers YOU run; lets DNSD-130/131 say whether an "
                        "encrypted session went to your resolver or past it "
                        "(repeatable).")
    p.add_argument("--xfr-secondary-prefix", action="append", default=[],
                   dest="xfr_secondary_prefixes", metavar="CIDR",
                   help="CIDR of secondaries permitted to pull your zones; enables "
                        "DNSD-061 (repeatable).")
    p.add_argument("--no-llmnr", action="store_true", help="disable the LLMNR tier")
    p.add_argument("--no-nbns", action="store_true", help="disable the NBT-NS tier")
    p.add_argument("--no-encrypted-dns", action="store_true",
                   help="disable the encrypted-DNS transport tier (DoT/DoQ/DDR)")
    p.add_argument("--no-dnssd", action="store_true",
                   help="disable unicast DNS-SD enumeration detection")
    p.add_argument("--print-codes", action="store_true",
                   help="print the finding-code registry and exit")
    args = p.parse_args()

    if args.print_codes:
        for code in sorted(FINDINGS):
            m = FINDINGS[code]
            if code in BASELINE_DEPENDENT:
                gate = "  [baseline-gated]"
            elif code in PREFIX_DEPENDENT:
                # Named rather than left to fire never: a check that is
                # silent for want of config is indistinguishable from a
                # check that is broken, unless something says so.
                gate = f"  [needs {PREFIX_CLI_FLAG[PREFIX_CONFIG_KEY[code]]}]"
            else:
                gate = ""
            print(f"{code}  {m['name']:34s} {m['severity']:8s} {m['confidence']:6s}{gate}")
        return 0

    if not args.iface:
        p.error("-i/--iface is required unless --print-codes is given")

    cfg = Config()
    cfg.enable_baseline_detectors = args.enable_baseline_detectors
    cfg.excluded_zones = set(args.exclude_zone)
    if args.max_zones:
        cfg.max_zones = args.max_zones
    cfg.mdns_local_prefixes = tuple(args.mdns_prefixes)
    cfg.ddns_allowed_updater_prefixes = tuple(args.ddns_prefixes)
    cfg.rdns_internal_prefixes = tuple(args.rdns_prefixes)
    cfg.ddns_enabled = not args.no_ddns
    cfg.rdns_enabled = not args.no_rdns
    cfg.dns_own_resolver_prefixes = tuple(args.own_resolver_prefixes)
    cfg.xfr_allowed_secondary_prefixes = tuple(args.xfr_secondary_prefixes)
    cfg.llmnr_enabled = not args.no_llmnr
    cfg.nbns_enabled = not args.no_nbns
    cfg.encrypted_dns_enabled = not args.no_encrypted_dns
    cfg.dnssd_enabled = not args.no_dnssd

    stats = run(args.iface, cfg, timeout=args.timeout)
    print(f"frames={stats.frames} parsed={stats.parsed} findings={stats.findings} "
          f"malformed={stats.malformed} dropped={stats.dropped}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
