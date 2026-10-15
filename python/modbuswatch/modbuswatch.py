#!/usr/bin/env python3
"""
modbuswatch — service entrypoint.

Live passive capture on an interface, or offline pcap replay. Receive-only.

  modbuswatch.py --iface eth0 [--ot-subnet 10.20.0.0/24[,2001:db8:ac::/64]] [--window 3600]
  modbuswatch.py --pcap capture.pcap

OT subnets may also come from the MBW_OT_SUBNET environment variable
(comma-separated; empty = MBW-040 disabled). systemd sets it via the unit.

Findings are written to stdout (one per line) and, when --log is given, appended
to that file. systemd runs the --iface form; see modbuswatch.service.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import socket
import sys

try:  # Ragnar: relative inside the vendored package, bare for flat standalone.
    from .findings import Engine
    from .state import Baseline
    from .sensor import process_packet, run_pcap
except ImportError:
    from findings import Engine
    from state import Baseline
    from sensor import process_packet, run_pcap

OT_SUBNET_ENV = "MBW_OT_SUBNET"


def build_bpf() -> str:
    """
    Kernel capture filter. IPv4 stays port-scoped; IPv6 is admitted whole.

    libpcap's "tcp port N" reads the IPv6 Next Header at a fixed offset, so any
    v6 packet carrying a Hop-by-Hop / Routing / Destination Options / Fragment
    header is dropped in the kernel before sensor._tcp_from_v6 can walk the
    chain. The port decision for v6 therefore lives in sensor.process_packet,
    which already makes it. Same shape as tlswatch build_bpf.
    """
    return "(tcp port 502 or tcp port 802) or ip6"


def _parse_subnets(specs):
    """Accept a list of entries, each optionally comma-separated. Blanks ignored."""
    out = []
    for spec in specs or []:
        for s in spec.split(","):
            s = s.strip()
            if not s:
                continue
            net = ipaddress.ip_network(s, strict=False)
            fam = socket.AF_INET6 if net.version == 6 else socket.AF_INET
            out.append((fam, net))
    return out


def ot_subnets(cli_specs, env=None):
    """CLI --ot-subnet values plus MBW_OT_SUBNET from the environment."""
    env = os.environ if env is None else env
    return _parse_subnets(list(cli_specs or []) + [env.get(OT_SUBNET_ENV, "")])


def main(argv=None):
    ap = argparse.ArgumentParser(prog="modbuswatch")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--iface", help="interface to sniff (live)")
    src.add_argument("--pcap", help="pcap file to replay (offline)")
    ap.add_argument("--ot-subnet", action="append", default=[],
                    help="declared OT subnet(s), comma-separated or repeated "
                         "(enables MBW-040); also read from $MBW_OT_SUBNET")
    ap.add_argument("--window", type=float, default=3600.0,
                    help="baseline learning window, seconds (default 3600)")
    ap.add_argument("--log", help="append findings to this file")
    args = ap.parse_args(argv)

    baseline = Baseline(window_s=args.window)
    engine = Engine(baseline=baseline, ot_subnets=ot_subnets(args.ot_subnet))

    logfh = open(args.log, "a") if args.log else None

    def emit_new(seen_before):
        for f in engine.findings[seen_before:]:
            line = str(f)
            print(line, flush=True)
            if logfh:
                logfh.write(line + "\n"); logfh.flush()

    if args.pcap:
        run_pcap(args.pcap, engine)
        emit_new(0)
        return 0

    # live capture
    from scapy.all import sniff
    seen = [0]

    def handle(pkt):
        process_packet(pkt, engine)
        emit_new(seen[0])
        seen[0] = len(engine.findings)

    # store=False: never buffer
    sniff(iface=args.iface, prn=handle, store=False, filter=build_bpf())
    return 0


if __name__ == "__main__":
    sys.exit(main())
