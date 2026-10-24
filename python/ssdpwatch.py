#!/usr/bin/env python3
"""
ssdpwatch - Ragnar passive SSDP / UPnP detector.

Scope: the PROTOCOL only (UPnP Device Architecture wire grammar + GENA + IGD
control). Vendor / implementation CVEs are out of scope by design.

Tiers
  A  SSDP discovery plane .... UDP/1900, IPv4 239.255.255.250 + IPv6 FF0x::C
  B  GENA eventing ........... TCP, SUBSCRIBE/UNSUBSCRIBE (CallStranger)
  C  IGD control ............. TCP, SOAP WANIPConnection/WANPPPConnection

Passive only. Never transmits. Dual-stack with full IPv4/IPv6 parity.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Iterable, List, Optional, Tuple

__version__ = "0.1.0-dev"
MODULE = "ssdpwatch"

SSDP_PORT = 1900
SSDP_V4_GROUP = ipaddress.ip_address("239.255.255.250")
# UPnP Device Architecture 1.1 / 2.0 multicast scopes
SSDP_V6_GROUPS = {
    ipaddress.ip_address("ff02::c"): "link",
    ipaddress.ip_address("ff05::c"): "site",
    ipaddress.ip_address("ff08::c"): "organization",
    ipaddress.ip_address("ff0e::c"): "global",
}
# UDA 1.1/2.0 default the multicast TTL / hop limit to 2; UDA 1.0 gear
# shipped 4 and is still everywhere in homes. Anything at or below 4 is
# within historical spec, so only a value ABOVE 4 is a deliberate escape.
UDA_DEFAULT_TTL = 2
UDA_MAX_SANE_TTL = 4


# --------------------------------------------------------------------------
# finding registry
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class CodeDef:
    code: str
    tier: str
    severity: str
    title: str
    cve: Optional[str] = None


REGISTRY: Dict[str, CodeDef] = {}


def _reg(code, tier, severity, title, cve=None):
    REGISTRY[code] = CodeDef(code, tier, severity, title, cve)
    return code


# --- Tier B: CallStranger, the one CVE trigger -----------------------------
SSDP_001 = _reg("SSDP-001", "B", "high",
                "GENA SUBSCRIBE CALLBACK points off-link (CallStranger)",
                "CVE-2020-12695")
SSDP_002 = _reg("SSDP-002", "B", "high",
                "GENA SUBSCRIBE CALLBACK host differs from subscriber source",
                "CVE-2020-12695")
SSDP_003 = _reg("SSDP-003", "B", "medium",
                "GENA SUBSCRIBE carries multiple CALLBACK URLs (fan-out amplifier)",
                "CVE-2020-12695")
SSDP_004 = _reg("SSDP-004", "B", "medium",
                "GENA SUBSCRIBE CALLBACK uses non-http scheme or odd port")
SSDP_005 = _reg("SSDP-005", "B", "low",
                "GENA SUBSCRIBE requests unbounded / excessive TIMEOUT")

# --- Tier A: discovery-plane abuse and posture -----------------------------
SSDP_010 = _reg("SSDP-010", "A", "high",
                "Unicast M-SEARCH from off-link source (reflection probe)")
SSDP_011 = _reg("SSDP-011", "A", "medium",
                "Unicast M-SEARCH with ST: ssdp:all (targeted inventory sweep)")
SSDP_012 = _reg("SSDP-012", "A", "high",
                "SSDP response sent to off-link destination (amplifier exposure)")
SSDP_013 = _reg("SSDP-013", "A", "high",
                "One responder sent duplicate responses to a single host "
                "(amplification multiplier)")
SSDP_014 = _reg("SSDP-014", "A", "high",
                "Response storm converging on a single destination")
SSDP_015 = _reg("SSDP-015", "A", "medium",
                "SSDP multicast TTL / hop limit above the UDA range of 2-4 "
                "(deliberate scope escape)")
SSDP_016 = _reg("SSDP-016", "A", "medium",
                "SSDP sent to a wider-than-link IPv6 scope (FF05/FF08/FF0E)")
SSDP_017 = _reg("SSDP-017", "A", "medium",
                "NOTIFY LOCATION host does not match packet source (advert spoof)")
SSDP_018 = _reg("SSDP-018", "A", "medium",
                "ssdp:byebye storm (device-eviction flood)")
SSDP_019 = _reg("SSDP-019", "A", "medium",
                "BOOTID.UPNP.ORG regression for a known USN (impersonation)")
SSDP_020 = _reg("SSDP-020", "A", "low",
                "M-SEARCH missing or malformed MAN: \"ssdp:discover\"")
SSDP_021 = _reg("SSDP-021", "A", "low",
                "M-SEARCH MX value out of UDA range (1-5)")
SSDP_022 = _reg("SSDP-022", "A", "low",
                "Malformed or oversized SSDP message")
SSDP_023 = _reg("SSDP-023", "A", "medium",
                "NOTIFY LOCATION points at a routable off-link host")
SSDP_024 = _reg("SSDP-024", "A", "medium",
                "Unsolicited SSDP 200 OK to a host that issued no M-SEARCH "
                "(reflection victim)")

# --- Tier C: IGD control-plane abuse ---------------------------------------
SSDP_030 = _reg("SSDP-030", "C", "high",
                "IGD AddPortMapping NewInternalClient differs from requester "
                "(pinhole punched for a third party)")
SSDP_031 = _reg("SSDP-031", "C", "high",
                "IGD control request arrives from an off-link source "
                "(WAN-side control)")
SSDP_032 = _reg("SSDP-032", "C", "medium",
                "IGD AddPortMapping targets an infrastructure / admin port")
SSDP_033 = _reg("SSDP-033", "C", "medium",
                "IGD DeletePortMapping / DeletePortMappingRange for a mapping "
                "the requester does not own")
SSDP_034 = _reg("SSDP-034", "C", "low",
                "IGD AddPortMapping with unbounded lease duration")

SENSITIVE_PORTS = {
    22: "ssh", 23: "telnet", 53: "dns", 139: "netbios-ssn", 445: "smb",
    1900: "ssdp", 3389: "rdp", 5555: "adb", 8291: "winbox", 9100: "jetdirect",
}


# --------------------------------------------------------------------------
# normalized packet
# --------------------------------------------------------------------------

@dataclass
class Packet:
    ts: float
    proto: str              # "udp" | "tcp"
    src: str
    dst: str
    sport: int
    dport: int
    payload: bytes
    ttl: int = 64           # IPv4 TTL or IPv6 hop limit
    iface: str = "-"

    @property
    def family(self) -> int:
        return ipaddress.ip_address(self.src).version


@dataclass
class Finding:
    ts: float
    code: str
    severity: str
    title: str
    cve: Optional[str]
    tier: str
    src: str
    dst: str
    family: int
    detail: Dict[str, object] = field(default_factory=dict)

    def as_dict(self):
        d = {
            "ts": round(self.ts, 3),
            "module": MODULE,
            "code": self.code,
            "severity": self.severity,
            "title": self.title,
            "tier": self.tier,
            "src": self.src,
            "dst": self.dst,
            "af": f"ipv{self.family}",
        }
        if self.cve:
            d["cve"] = self.cve
        if self.detail:
            d["detail"] = self.detail
        return d

    def line(self):
        cve = f" [{self.cve}]" if self.cve else ""
        det = ""
        if self.detail:
            det = " " + " ".join(f"{k}={v}" for k, v in self.detail.items())
        return (f"{time.strftime('%H:%M:%S', time.localtime(self.ts))} "
                f"{self.severity.upper():<6} {self.code} ipv{self.family} "
                f"{self.src} -> {self.dst}{cve} :: {self.title}{det}")


# --------------------------------------------------------------------------
# address scope
# --------------------------------------------------------------------------

class Scope:
    """Decides on-link vs off-link.

    Home default: RFC1918, ULA, link-local and loopback are on-link;
    everything else is off-link.

    CGNAT (100.64.0.0/10) is deliberately OFF-link. It is carrier shared
    space upstream of the CPE, never a home LAN, so a CALLBACK or
    NewInternalClient pointing into it is pointing off the premises -- which
    is exactly the CallStranger primitive. Treating it as on-link would be a
    silent blind spot. A site that really does number internally out of
    100.64/10 adds it back with --local.
    """

    def __init__(self, extra_prefixes: Iterable[str] = ()):
        self.local_nets = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("169.254.0.0/16"),     # v4 link-local
            ipaddress.ip_network("127.0.0.0/8"),
            ipaddress.ip_network("fc00::/7"),           # ULA
            ipaddress.ip_network("fe80::/10"),          # v6 link-local
            ipaddress.ip_network("::1/128"),
        ]
        for p in extra_prefixes:
            self.local_nets.append(ipaddress.ip_network(p, strict=False))

    @staticmethod
    def parse(addr: str):
        a = addr.strip()
        if a.startswith("[") and "]" in a:
            a = a[1:a.index("]")]
        if "%" in a:
            a = a.split("%", 1)[0]
        try:
            return ipaddress.ip_address(a)
        except ValueError:
            return None

    def is_local(self, addr) -> bool:
        ip = addr if isinstance(addr, (ipaddress.IPv4Address,
                                       ipaddress.IPv6Address)) else self.parse(addr)
        if ip is None:
            return False
        if ip.is_multicast:
            return True
        return any(ip in n for n in self.local_nets if n.version == ip.version)

    def is_offlink(self, addr) -> bool:
        ip = addr if isinstance(addr, (ipaddress.IPv4Address,
                                       ipaddress.IPv6Address)) else self.parse(addr)
        if ip is None:
            return False
        if ip.is_multicast:
            return False
        return not self.is_local(ip)


def canon(addr: str) -> str:
    """RFC 5952 canonical form where possible, else the raw string."""
    ip = Scope.parse(addr)
    return str(ip) if ip is not None else addr.strip()


# --------------------------------------------------------------------------
# HTTPU / HTTP message parser (hand-rolled, tolerant)
# --------------------------------------------------------------------------

_START_RE = re.compile(rb"^([A-Z\-]+)[ \t]+(\S+)[ \t]+HTTP/(\d\.\d)\s*$")
_STATUS_RE = re.compile(rb"^HTTP/(\d\.\d)[ \t]+(\d{3})(?:[ \t]+(.*))?\s*$")
MAX_SANE = 8192


class HTTPUMessage:
    __slots__ = ("kind", "method", "uri", "status", "version",
                 "headers", "body", "errors", "raw_len")

    def __init__(self):
        self.kind: Optional[str] = None     # "request" | "response"
        self.method: Optional[str] = None
        self.uri: Optional[str] = None
        self.status: Optional[int] = None
        self.version: Optional[str] = None
        self.headers: Dict[str, List[str]] = {}
        self.body: bytes = b""
        self.errors: List[str] = []
        self.raw_len = 0

    def get(self, name: str, default=None) -> Optional[str]:
        v = self.headers.get(name.lower())
        return v[0] if v else default

    def all(self, name: str) -> List[str]:
        return self.headers.get(name.lower(), [])

    def has(self, name: str) -> bool:
        return name.lower() in self.headers


def parse_httpu(data: bytes) -> Optional[HTTPUMessage]:
    if not data:
        return None
    msg = HTTPUMessage()
    msg.raw_len = len(data)

    head, sep, body = data.partition(b"\r\n\r\n")
    if not sep:
        head, sep, body = data.partition(b"\n\n")
        if sep:
            msg.errors.append("lf_only_terminator")
    msg.body = body

    lines = head.replace(b"\r\n", b"\n").split(b"\n")
    if not lines or not lines[0].strip():
        return None
    start = lines[0]

    m = _STATUS_RE.match(start)
    if m:
        msg.kind = "response"
        msg.version = m.group(1).decode()
        msg.status = int(m.group(2))
    else:
        m = _START_RE.match(start)
        if not m:
            return None
        msg.kind = "request"
        msg.method = m.group(1).decode()
        msg.uri = m.group(2).decode("latin-1")
        msg.version = m.group(3).decode()

    for raw in lines[1:]:
        if not raw.strip():
            continue
        if raw[:1] in (b" ", b"\t"):          # obs-fold continuation
            msg.errors.append("obs_fold")
            continue
        if b":" not in raw:
            msg.errors.append("headerless_line")
            continue
        name, _, value = raw.partition(b":")
        key = name.strip().lower().decode("latin-1", "replace")
        if not key:
            msg.errors.append("empty_header_name")
            continue
        msg.headers.setdefault(key, []).append(
            value.strip().decode("latin-1", "replace"))
    return msg


def url_host_port(url: str) -> Tuple[Optional[str], Optional[int], Optional[str]]:
    """Return (host, port, scheme). Handles bracketed IPv6 literals."""
    u = url.strip().strip("<>")
    scheme = None
    if "://" in u:
        scheme, _, rest = u.partition("://")
        scheme = scheme.lower()
    else:
        rest = u
    authority = rest.split("/", 1)[0]
    if "@" in authority:
        authority = authority.rsplit("@", 1)[1]
    port = None
    if authority.startswith("["):
        end = authority.find("]")
        if end == -1:
            return None, None, scheme
        host = authority[1:end]
        tail = authority[end + 1:]
        if tail.startswith(":") and tail[1:].isdigit():
            port = int(tail[1:])
    else:
        if authority.count(":") == 1:
            host, _, p = authority.partition(":")
            if p.isdigit():
                port = int(p)
        else:
            host = authority
    if not host:
        return None, None, scheme
    if port is None and scheme in ("http", "https"):
        port = 80 if scheme == "http" else 443
    return host, port, scheme


def split_callbacks(value: str) -> List[str]:
    """CALLBACK is one or more <absolute-URI> in angle brackets."""
    found = re.findall(r"<([^>]*)>", value)
    if found:
        return [f.strip() for f in found if f.strip()]
    v = value.strip()
    return [v] if v else []


# --------------------------------------------------------------------------
# detection engine
# --------------------------------------------------------------------------

@dataclass
class Config:
    local_prefixes: Tuple[str, ...] = ()
    # SSDP-013 counts responses from ONE responder to ONE destination.
    # Counting total responses would fire on any media-heavy home, where a
    # single ssdp:all legitimately draws a reply from every device.
    response_ratio: int = 6           # dupes from one responder in ratio_window
    ratio_window: float = 5.0
    storm_responses: int = 40         # responses to one dst in storm_window
    storm_window: float = 10.0
    byebye_threshold: int = 20
    byebye_window: float = 10.0
    max_timeout_seconds: int = 1800   # GENA TIMEOUT ceiling
    max_message_bytes: int = MAX_SANE
    emit_low: bool = True


class SSDPWatch:
    def __init__(self, config: Optional[Config] = None):
        self.cfg = config or Config()
        self.scope = Scope(self.cfg.local_prefixes)
        self.findings: List[Finding] = []
        self._seen: set = set()

        # per-exchange state (no baseline learning anywhere)
        self._msearch: Dict[Tuple[str, int], Deque[float]] = defaultdict(deque)
        self._resp_to: Dict[Tuple[str, int], Deque[float]] = defaultdict(deque)
        self._resp_pair: Dict[Tuple[str, str, int], Deque[float]] = defaultdict(deque)
        self._seen_hosts: set = set()
        self._mappings: Dict[Tuple[str, str], str] = {}   # (extport,proto)->owner
        self._byebye: Dict[str, Deque[float]] = defaultdict(deque)
        self._bootid: Dict[str, int] = {}
        self._location_ports: Dict[str, set] = defaultdict(set)
        self.stats = defaultdict(int)

    # -- emit -------------------------------------------------------------
    def _emit(self, pkt: Packet, code: str, **detail):
        d = REGISTRY[code]
        if d.severity == "low" and not self.cfg.emit_low:
            return
        key = (code, pkt.src, pkt.dst, tuple(sorted(
            (k, str(v)) for k, v in detail.items())))
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append(Finding(
            ts=pkt.ts, code=code, severity=d.severity, title=d.title,
            cve=d.cve, tier=d.tier, src=canon(pkt.src), dst=canon(pkt.dst),
            family=pkt.family, detail=detail))

    def _noop(self, *a, **k):
        """Sink used only by the bite test's mutation harness."""
        return None

    # -- entry point ------------------------------------------------------
    def observe(self, pkt: Packet):
        self.stats["packets"] += 1
        self._seen_hosts.add(canon(pkt.src))
        if pkt.proto == "udp" and (pkt.dport == SSDP_PORT or pkt.sport == SSDP_PORT):
            self._tier_a(pkt)
        elif pkt.proto == "tcp":
            self._tier_bc(pkt)

    # -- Tier A : discovery plane ----------------------------------------
    def _tier_a(self, pkt: Packet):
        if len(pkt.payload) > self.cfg.max_message_bytes:
            self._emit(pkt, SSDP_022, reason="oversized", bytes=len(pkt.payload))
            return
        msg = parse_httpu(pkt.payload)
        if msg is None:
            if pkt.payload.strip():
                self._emit(pkt, SSDP_022, reason="unparseable",
                           head=pkt.payload[:24].decode("latin-1", "replace"))
            return
        self.stats["ssdp_messages"] += 1
        if msg.errors:
            self._emit(pkt, SSDP_022, reason=",".join(sorted(set(msg.errors))))

        dst_ip = Scope.parse(pkt.dst)
        is_mcast = dst_ip is not None and dst_ip.is_multicast

        # scope posture -- applies to any multicast SSDP
        if is_mcast:
            if pkt.ttl > UDA_MAX_SANE_TTL:
                self._emit(pkt, SSDP_015, ttl=pkt.ttl,
                           field="hop_limit" if pkt.family == 6 else "ttl")
            if pkt.family == 6 and dst_ip in SSDP_V6_GROUPS:
                sc = SSDP_V6_GROUPS[dst_ip]
                if sc != "link":
                    self._emit(pkt, SSDP_016, scope=sc, group=str(dst_ip))

        if msg.kind == "request" and msg.method == "M-SEARCH":
            self._msearch_rules(pkt, msg, is_mcast)
        elif msg.kind == "request" and msg.method == "NOTIFY":
            self._notify_rules(pkt, msg)
        elif msg.kind == "response":
            self._response_rules(pkt, msg)

    def _msearch_rules(self, pkt, msg, is_mcast):
        self.stats["m_search"] += 1
        man = (msg.get("man") or "").strip()
        if man.strip('"').lower() != "ssdp:discover":
            self._emit(pkt, SSDP_020, man=man or "<absent>")

        mx = msg.get("mx")
        if mx is not None:
            try:
                mxv = int(mx.strip())
                if mxv < 1 or mxv > 5:
                    self._emit(pkt, SSDP_021, mx=mxv)
            except ValueError:
                self._emit(pkt, SSDP_021, mx=mx.strip() or "<empty>")

        st = (msg.get("st") or "").strip()
        # A MULTICAST ssdp:all is ordinary startup discovery -- every control
        # point in the house emits it. Only a UNICAST ssdp:all is a sweep:
        # it enumerates one chosen host rather than announcing interest.
        if st.lower() == "ssdp:all" and not is_mcast:
            self._emit(pkt, SSDP_011, st=st, target=canon(pkt.dst))

        if not is_mcast and self.scope.is_offlink(pkt.src):
            self._emit(pkt, SSDP_010, st=st or "<absent>", dport=pkt.dport)

        q = self._msearch[(canon(pkt.src), pkt.sport)]
        q.append(pkt.ts)
        self._prune(q, pkt.ts, self.cfg.ratio_window)

    def _notify_rules(self, pkt, msg):
        self.stats["notify"] += 1
        nts = (msg.get("nts") or "").strip().lower()
        usn = (msg.get("usn") or "").strip()
        loc = msg.get("location")

        if loc:
            host, port, _scheme = url_host_port(loc)
            if host:
                hip = Scope.parse(host)
                if hip is not None and canon(host) != canon(pkt.src):
                    self._emit(pkt, SSDP_017, location_host=canon(host))
                if hip is not None and self.scope.is_offlink(hip):
                    self._emit(pkt, SSDP_023, location_host=canon(host))
                if port:
                    self._location_ports[canon(pkt.src)].add(port)

        if nts == "ssdp:byebye":
            q = self._byebye[canon(pkt.src)]
            q.append(pkt.ts)
            self._prune(q, pkt.ts, self.cfg.byebye_window)
            if len(q) >= self.cfg.byebye_threshold:
                self._emit(pkt, SSDP_018, count=len(q),
                           window_s=self.cfg.byebye_window)

        boot = msg.get("bootid.upnp.org")
        if boot is not None and usn:
            try:
                b = int(boot.strip())
            except ValueError:
                b = None
            if b is not None:
                prev = self._bootid.get(usn)
                if prev is not None and b < prev:
                    self._emit(pkt, SSDP_019, usn=usn, bootid=b, previous=prev)
                self._bootid[usn] = max(b, prev) if prev is not None else b

    def _response_rules(self, pkt, msg):
        self.stats["responses"] += 1
        loc = msg.get("location")
        if loc:
            host, port, _ = url_host_port(loc)
            if host and port:
                self._location_ports[canon(pkt.src)].add(port)
            if host:
                hip = Scope.parse(host)
                if hip is not None and self.scope.is_offlink(hip):
                    self._emit(pkt, SSDP_023, location_host=canon(host))

        if self.scope.is_offlink(pkt.dst):
            self._emit(pkt, SSDP_012, dport=pkt.dport,
                       bytes=len(pkt.payload))

        key = (canon(pkt.dst), pkt.dport)
        q = self._resp_to[key]
        q.append(pkt.ts)
        self._prune(q, pkt.ts, self.cfg.storm_window)

        # amplification = ONE responder repeating itself at ONE victim.
        # A big house answering ssdp:all from 20 distinct devices is normal.
        pair = self._resp_pair[(canon(pkt.src), canon(pkt.dst), pkt.dport)]
        pair.append(pkt.ts)
        self._prune(pair, pkt.ts, self.cfg.ratio_window)
        if len(pair) >= self.cfg.response_ratio:
            self._emit(pkt, SSDP_013, responder=canon(pkt.src),
                       duplicates=len(pair), window_s=self.cfg.ratio_window)

        # a 200 OK is only ever a reply to M-SEARCH. One sent to a host the
        # tap has seen talking, but which never searched, is reflected traffic.
        dst_host = canon(pkt.dst)
        if dst_host in self._seen_hosts:
            searched = any(k[0] == dst_host for k, v in self._msearch.items()
                           if v and v[-1] >= pkt.ts - self.cfg.ratio_window)
            if not searched:
                self._emit(pkt, SSDP_024, dport=pkt.dport)

        if len(q) >= self.cfg.storm_responses:
            self._emit(pkt, SSDP_014, responses=len(q),
                       window_s=self.cfg.storm_window)

    # -- Tier B / C : TCP side -------------------------------------------
    def _tier_bc(self, pkt: Packet):
        data = pkt.payload
        if not data:
            return
        head = data[:16].upper()
        if head.startswith(b"SUBSCRIBE ") or head.startswith(b"UNSUBSCRIBE "):
            msg = parse_httpu(data)
            if msg:
                self._gena_rules(pkt, msg)
        elif head.startswith(b"POST ") or head.startswith(b"M-POST "):
            msg = parse_httpu(data)
            if msg and (msg.has("soapaction") or b"urn:schemas-upnp-org:service"
                        in data[:2048]):
                self._igd_rules(pkt, msg)

    def _gena_rules(self, pkt, msg):
        self.stats["gena"] += 1
        if msg.method == "UNSUBSCRIBE":
            return
        cb_raw = msg.all("callback")
        if not cb_raw:
            return
        callbacks: List[str] = []
        for v in cb_raw:
            callbacks.extend(split_callbacks(v))
        if not callbacks:
            return

        if len(callbacks) > 1:
            self._emit(pkt, SSDP_003, callbacks=len(callbacks),
                       sample=callbacks[0][:80])

        for cb in callbacks:
            host, port, scheme = url_host_port(cb)
            if not host:
                self._emit(pkt, SSDP_004, callback=cb[:80], reason="unparseable")
                continue
            if scheme not in (None, "http"):
                self._emit(pkt, SSDP_004, callback=cb[:80],
                           scheme=scheme or "<none>")
            hip = Scope.parse(host)
            if hip is not None:
                if self.scope.is_offlink(hip):
                    # the CallStranger primitive
                    self._emit(pkt, SSDP_001, callback_host=canon(host),
                               callback_port=port if port else "-",
                               service=(msg.uri or "")[:60])
                elif canon(host) != canon(pkt.src):
                    self._emit(pkt, SSDP_002, callback_host=canon(host),
                               subscriber=canon(pkt.src))
            else:
                # DNS name in CALLBACK: cannot be resolved passively
                self._emit(pkt, SSDP_004, callback=cb[:80], reason="named_host")
            if port is not None and port in SENSITIVE_PORTS and port != 80:
                self._emit(pkt, SSDP_004, callback_port=port,
                           service_name=SENSITIVE_PORTS[port])

        tmo = msg.get("timeout")
        if tmo:
            t = tmo.strip().lower()
            if t in ("second-infinite", "infinite"):
                self._emit(pkt, SSDP_005, timeout=t)
            elif t.startswith("second-"):
                try:
                    secs = int(t.split("-", 1)[1])
                    if secs > self.cfg.max_timeout_seconds:
                        self._emit(pkt, SSDP_005, timeout_s=secs)
                except ValueError:
                    pass

    _SOAP_ACTION_RE = re.compile(r'[#"]([A-Za-z]+)"?\s*$')

    def _igd_rules(self, pkt, msg):
        self.stats["igd"] += 1
        action_hdr = msg.get("soapaction") or ""
        m = self._SOAP_ACTION_RE.search(action_hdr.strip())
        action = m.group(1) if m else ""
        body = msg.body.decode("latin-1", "replace")
        if not action:
            m2 = re.search(r"<(?:\w+:)?(AddPortMapping|DeletePortMapping"
                           r"|DeletePortMappingRange|AddAnyPortMapping)\b", body)
            action = m2.group(1) if m2 else ""

        if self.scope.is_offlink(pkt.src):
            self._emit(pkt, SSDP_031, action=action or "<unknown>",
                       dport=pkt.dport)

        def arg(name):
            mm = re.search(rf"<(?:\w+:)?{name}>\s*(.*?)\s*</", body, re.S)
            return mm.group(1).strip() if mm else None

        ext = arg("NewExternalPort") or arg("NewStartPort")
        proto = (arg("NewProtocol") or "").upper()

        if action in ("AddPortMapping", "AddAnyPortMapping"):
            if ext:
                self._mappings[(ext, proto)] = canon(pkt.src)
            client = arg("NewInternalClient")
            if client:
                cip = Scope.parse(client)
                if cip is not None and canon(client) != canon(pkt.src):
                    self._emit(pkt, SSDP_030, internal_client=canon(client),
                               requester=canon(pkt.src),
                               external_port=arg("NewExternalPort") or "-")
            iport = arg("NewInternalPort")
            if iport and iport.isdigit() and int(iport) in SENSITIVE_PORTS:
                self._emit(pkt, SSDP_032, internal_port=int(iport),
                           service_name=SENSITIVE_PORTS[int(iport)],
                           external_port=arg("NewExternalPort") or "-")
            lease = arg("NewLeaseDuration")
            if lease is not None and lease.strip() in ("0", ""):
                self._emit(pkt, SSDP_034, lease="0 (indefinite)",
                           external_port=arg("NewExternalPort") or "-")

        elif action in ("DeletePortMapping", "DeletePortMappingRange"):
            # Deleting your own mapping is ordinary housekeeping. Only a
            # delete aimed at a mapping THIS host did not create is a finding,
            # and only once the tap has actually witnessed the Add.
            owner = self._mappings.get((ext, proto)) if ext else None
            if owner is not None and owner != canon(pkt.src):
                self._emit(pkt, SSDP_033, action=action,
                           external_port=ext or "-",
                           owner=owner, requester=canon(pkt.src))

    @staticmethod
    def _prune(q: Deque[float], now: float, window: float):
        while q and q[0] < now - window:
            q.popleft()

    # -- reporting --------------------------------------------------------
    def report(self, as_json=False) -> str:
        if as_json:
            return json.dumps({
                "module": MODULE, "version": __version__,
                "stats": dict(self.stats),
                "findings": [f.as_dict() for f in self.findings],
            }, indent=2)
        if not self.findings:
            return "no findings"
        return "\n".join(f.line() for f in self.findings)


# --------------------------------------------------------------------------
# live capture (passive, read-only) + pcap offline
# --------------------------------------------------------------------------

# Tier A is UDP/1900. Tier B/C ride TCP on whatever description port SSDP
# advertised in LOCATION, so the port is not known ahead of capture.
#
# Two tempting filters are both WRONG:
#   "tcp portrange 49152-65535" -- ephemeral SOURCE ports live in that range,
#     so it captures the whole household's browsing, the opposite of intent.
#   a payload-byte match on the method token -- libpcap's tcp[offset]
#     arithmetic is IPv4-ONLY, and the ip6[] workaround breaks on extension
#     headers. That filter would silently go blind on every IPv6 SUBSCRIBE,
#     which is the same BPF/IPv6-EH trap that bit juniperwatch, and it breaks
#     the dual-stack rule by construction.
#
# So the BPF stays coarse and provably not-blind, and the precision lives in
# Python where no such limitation exists. _wanted() runs on every packet
# whether or not libpcap is present, so behaviour is identical either way.
# A home link carries little enough TCP for this to be the cheap trade.
BPF = "(udp port 1900) or tcp"

# GENA and SOAP control requests; the only TCP ssdpwatch has any use for.
UPNP_TCP_METHODS = (b"SUBSCRIBE ", b"UNSUBSCRIBE ", b"POST ", b"M-POST ")


def _wanted(p) -> bool:
    """Precise second-stage filter. Dual-stack by construction: it reads the
    decoded payload, never a hard-coded header offset."""
    from scapy.layers.inet import TCP, UDP
    if UDP in p:
        return p[UDP].sport == SSDP_PORT or p[UDP].dport == SSDP_PORT
    if TCP in p:
        head = bytes(p[TCP].payload)[:16].upper()
        return any(head.startswith(m) for m in UPNP_TCP_METHODS)
    return False


def _scapy_to_packet(p) -> Optional[Packet]:
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    if IP in p:
        src, dst, ttl = p[IP].src, p[IP].dst, p[IP].ttl
    elif IPv6 in p:
        src, dst, ttl = p[IPv6].src, p[IPv6].dst, p[IPv6].hlim
    else:
        return None
    if UDP in p:
        l4, proto = p[UDP], "udp"
    elif TCP in p:
        l4, proto = p[TCP], "tcp"
    else:
        return None
    payload = bytes(l4.payload)
    if not payload:
        return None
    return Packet(ts=float(p.time), proto=proto, src=src, dst=dst,
                  sport=int(l4.sport), dport=int(l4.dport),
                  payload=payload, ttl=int(ttl))


def run_live(iface: str, engine: SSDPWatch, count: int = 0, timeout=None,
             bpf: Optional[str] = None, on_finding=None):
    """Passive capture. Opens a receive socket only -- never transmits."""
    from scapy.all import sniff
    from scapy.error import Scapy_Exception

    seen = 0

    def handler(p):
        nonlocal seen
        if not _wanted(p):          # always applied, libpcap or not
            return
        pk = _scapy_to_packet(p)
        if not pk:
            return
        pk.iface = iface
        before = len(engine.findings)
        engine.observe(pk)
        if on_finding:
            for f in engine.findings[before:]:
                on_finding(f)

    kw = dict(iface=iface, prn=handler, store=False,
              count=count, timeout=timeout)
    try:
        sniff(filter=bpf or BPF, **kw)
    except Scapy_Exception as exc:
        # scapy compiles BPF through libpcap. A stripped host (a bare WSL
        # image, a minimal Pi build) has none, and the filter -- not the
        # capture -- is what fails. Fall back to an unfiltered socket with
        # the same predicate applied in Python.
        if "libpcap" not in str(exc).lower() and "filter" not in str(exc).lower():
            raise
        print(f"{MODULE}: no libpcap, capturing unfiltered and selecting "
              f"in software", file=sys.stderr)
        sniff(lfilter=_wanted, **kw)


def run_pcap(path: str, engine: SSDPWatch):
    from scapy.all import rdpcap
    for p in rdpcap(path):
        pk = _scapy_to_packet(p)
        if pk:
            engine.observe(pk)


# --------------------------------------------------------------------------
# cli
# --------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(prog=MODULE,
                                 description="Passive SSDP/UPnP protocol detector")
    ap.add_argument("-i", "--iface", help="interface for live passive capture")
    ap.add_argument("-r", "--pcap", help="read from pcap instead of the wire")
    ap.add_argument("--local", action="append", default=[],
                    metavar="PREFIX", help="additional on-link prefix")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--count", type=int, default=0)
    ap.add_argument("--timeout", type=int, default=None)
    ap.add_argument("--bpf", help="override the capture filter")
    ap.add_argument("--no-low", action="store_true", help="suppress low severity")
    ap.add_argument("--codes", action="store_true", help="print finding registry")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--version", action="version",
                    version=f"{MODULE} {__version__}")
    args = ap.parse_args(argv)

    if args.codes:
        for c in sorted(REGISTRY.values(), key=lambda d: d.code):
            cve = f"  {c.cve}" if c.cve else ""
            print(f"{c.code}  tier {c.tier}  {c.severity:<6} {c.title}{cve}")
        return 0

    if args.selftest:
        from ssdpwatch_selftest import run_selftest
        return run_selftest()

    cfg = Config(local_prefixes=tuple(args.local), emit_low=not args.no_low)
    engine = SSDPWatch(cfg)

    if args.pcap:
        run_pcap(args.pcap, engine)
    elif args.iface:
        run_live(args.iface, engine, count=args.count, timeout=args.timeout,
                 bpf=args.bpf, on_finding=lambda f: print(f.line(), flush=True))
    else:
        ap.error("need -i/--iface or -r/--pcap")

    print(engine.report(as_json=args.json))
    return 0


if __name__ == "__main__":
    sys.exit(main())
