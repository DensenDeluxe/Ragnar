"""
Hand-rolled dual-stack DNS parser for DNS Doctor's passive tier.

No regex, no dnspython on the hot path -- per the Pi Zero 2W budget.
Pure bytes in, structured records out. Every function is total: it
returns a MalformedDNS marker rather than raising, because a passive
sensor that crashes on hostile input is worse than one that misses a
packet, and malformed packets are themselves a finding (DNSD-007).

THREE THINGS THIS FILE GETS RIGHT ON PURPOSE, each a known trap:

1. COMPRESSION POINTER LOOPS. A name can point backwards to another
   name. Two pointers aimed at each other hang a naive parser forever
   -- a one-packet CPU denial of service against the sensor itself.
   Guarded two ways: pointers must strictly DECREASE (a pointer may
   only ever point earlier in the message), and a hard jump budget.
   The strictly-decreasing rule is the stronger of the two and is what
   makes a loop structurally impossible rather than merely bounded.

2. FORWARD POINTERS ARE REJECTED. RFC 1035 s4.1.4 defines compression
   as a pointer to a PRIOR occurrence. Forward pointers are a classic
   parser-differential evasion: some stacks follow them, some don't,
   so an attacker can make one name mean two things to two readers.

3. OFFSET ARITHMETIC IS DUAL-STACK BUT NOT DUPLICATED. The IPv4 and
   IPv6 paths differ only in where the L4 header starts; everything
   above that is one code path, because DNS records are byte-identical
   over either. The version nibble decides the offset and nothing else
   branches -- so there is no second implementation to drift.
"""

MAX_NAME_LEN = 255
MAX_LABEL_LEN = 63
MAX_POINTER_JUMPS = 32

ETH_HDR = 14
ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
ETH_P_VLAN = 0x8100

# DNS rdata type numbers we care about.
T_A, T_NS, T_CNAME, T_SOA, T_AAAA = 1, 2, 5, 6, 28
T_DS, T_RRSIG, T_NSEC, T_DNSKEY, T_NSEC3 = 43, 46, 47, 48, 50
T_OPT, T_DNAME, T_SVCB, T_HTTPS, T_TKEY, T_TSIG = 41, 39, 64, 65, 249, 250
T_PTR, T_SRV, T_TXT = 12, 33, 16

# mDNS (RFC 6762). Same wire format as DNS, different transport rules.
MDNS_PORT = 5353
MDNS_V4_GROUP = bytes([224, 0, 0, 251])
MDNS_V6_GROUP = bytes.fromhex("ff0200000000000000000000000000fb")
# RFC 6762 s11: every mDNS message MUST be sent with IP TTL / hop limit
# 255, and a receiver SHOULD check it. A value other than 255 means the
# packet either crossed a router or was not generated as link-local --
# which is the whole premise of the VU#550620 scope-violation family.
MDNS_REQUIRED_TTL = 255
# Top bit of the question qclass = QU (unicast response requested,
# RFC 6762 s5.4). Top bit of an RR's class = cache-flush (s10.2).
# Both MUST be masked off before comparing a class to IN(1), or every
# mDNS record reads as class 32769 and nothing matches.
MDNS_CLASS_MASK = 0x7FFF
MDNS_UNICAST_BIT = 0x8000
MDNS_CACHE_FLUSH_BIT = 0x8000
QT_IXFR, QT_AXFR, QT_TKEY = 251, 252, 249

# SIG (24) is the OBSOLETE predecessor of RRSIG (46) with an identical
# rdata layout. It matters because Windows DNS parses BOTH through one
# function (SigWireRead) -- so SIGRed is reachable through either type
# number and a detector that watches only RRSIG misses half of it.
T_SIG = 24

# --- RFC 2136 dynamic update (opcode 5) ----------------------------
# An UPDATE message REUSES the four section counts with completely
# different meanings, which is why it must never be fed to the
# ordinary QUERY detectors:
#   qdcount -> ZONE          (exactly one, ZTYPE=SOA)
#   ancount -> PREREQUISITE
#   nscount -> UPDATE        (the actual mutations)
#   arcount -> ADDITIONAL    (where TSIG / SIG(0) live)
OPCODE_QUERY = 0
OPCODE_UPDATE = 5
# Classes legal in an UPDATE section. NONE deletes one RR, ANY deletes
# a whole RRset; IN adds. RFC 2136 s2.5.
CLASS_IN, CLASS_NONE, CLASS_ANY = 1, 254, 255

# TSIG error codes (RFC 8945 s4.3). A response whose TSIG reports one
# of the failure values while the message rcode says the operation
# SUCCEEDED is a self-contradiction no correct server emits.
TSIG_ERR_NOERROR = 0
TSIG_ERR_BADSIG, TSIG_ERR_BADKEY, TSIG_ERR_BADTIME, TSIG_ERR_BADTRUNC = 16, 17, 18, 22
TSIG_FAILURE_CODES = {
    TSIG_ERR_BADSIG: "BADSIG", TSIG_ERR_BADKEY: "BADKEY",
    TSIG_ERR_BADTIME: "BADTIME", TSIG_ERR_BADTRUNC: "BADTRUNC",
}

# Full digest length per TSIG algorithm, for the truncation check in
# RFC 8945 s5.2. gss-tsig is deliberately ABSENT: its MAC is a GSS
# checksum of variable length, so length-checking it would be a
# false-positive generator on every Windows AD exchange.
TSIG_DIGEST_LEN = {
    "hmac-md5.sig-alg.reg.int.": 16,
    "hmac-sha1.": 20,
    "hmac-sha224.": 28,
    "hmac-sha256.": 32,
    "hmac-sha384.": 48,
    "hmac-sha512.": 64,
}
TSIG_GSS_ALGOS = {"gss-tsig.", "gss.microsoft.com."}

# The gss exemption in _parse_tsig is BELT AND BRACES, and this
# assertion is what makes that honest rather than sloppy. A mutation
# that deleted the exemption changed no test result, because no GSS
# algorithm appears in TSIG_DIGEST_LEN in the first place -- the elif
# can never reach one (LESSON L: an escaped mutation is usually an
# unexercised guard, not a detection gap).
#
# The guard still earns its place, because the plausible future edit
# is someone adding a nominal gss length to the table above. If that
# happens this assertion fires at import instead of the truncation
# rule quietly firing on every Windows AD exchange on the tap.
assert not (TSIG_GSS_ALGOS & set(TSIG_DIGEST_LEN)), (
    "a GSS algorithm must not carry a fixed digest length: its MAC is a "
    "variable-length GSS checksum, so the RFC 8945 s5.2 truncation rule "
    "does not apply to it")

# TKEY modes (RFC 2930 s2.5). Mode 3 is GSS-API, the only one that
# carries a SPNEGO token and therefore the only one that can reach
# the BIND SPNEGO overflow.
TKEY_MODE_GSSAPI = 3
# DER tag/length constants for the SPNEGO structural walk.
DER_APPLICATION_0 = 0x60
SPNEGO_OID = bytes([0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02])

# SIGRed (CVE-2020-1350). Windows computes its allocation as
#   uncompressed_signer_name_length + 0x14 + signature_length
# and then truncates the result to 16 bits inside RR_AllocateEx, so a
# computed size at or above 65536 wraps to a far smaller buffer that a
# memcpy then overruns. Both terms are attacker-controlled, and the
# name term is the subtle one: a compression POINTER costs two bytes
# on the wire while contributing its full uncompressed length here.
SIGRED_ALLOC_OVERHEAD = 0x14
SIGRED_ALLOC_WRAP = 0x10000

# EDNS0 option codes that RFC permits AT MOST ONCE in one OPT record.
# Repeating one is CVE-2026-42944's denial-of-service primitive.
EDNS_SINGLETON_OPTIONS = {
    3: "NSID", 8: "ECS", 9: "DAU", 10: "DHU", 11: "N3U",
    10500: "PADDING", 12: "PADDING", 10: "DHU", 11: "N3U",
}
EDNS_OPTION_NAMES = {3: "NSID", 8: "ECS", 9: "DAU", 10: "DHU", 11: "N3U",
                     12: "PADDING", 13: "CHAIN", 14: "KEY-TAG",
                     15: "EXTENDED-ERROR", 10: "DHU", 10500: "PADDING"}
# DNS COOKIE is option 10 in some drafts and 10 (COOKIE) in RFC 7873 == 10.
EDNS_COOKIE = 10

# DNSSEC algorithms a modern validator can actually verify. Anything
# outside this set and not in DEPRECATED_ALGOS is simply unknown to us.
SUPPORTED_ALGOS = {5, 7, 8, 10, 13, 14, 15, 16}
DEPRECATED_ALGOS = {1, 3, 6, 12}


class MalformedDNS(Exception):
    """Carried as a value, not raised past parse_dns()."""


class NameTooLong(MalformedDNS):
    """A name whose expansion passes 255 octets.

    Carries the length reached and the labels decoded so far, because
    for SIGRed that overflow IS the measurement. The real exploit aims
    a compression pointer INTO the signature padding, where every byte
    is the same value, so each "length byte" spawns a label of that
    size and the name expands without bound from two wire bytes. A
    parser that raised a bare error here would discard the one number
    the detector needs and the attack would read as an ordinary
    malformed packet.
    """

    def __init__(self, message, accumulated=0, labels=()):
        super().__init__(message)
        self.accumulated = accumulated
        self.labels = tuple(labels)


class PointerAnomaly(MalformedDNS):
    """
    A compression-pointer failure specifically, as opposed to any other
    malformation.

    Kept as its own type because the two get very different findings.
    A truncated record is DNSD-007 (notice/low, malformed packets are
    ordinary on real networks). A pointer loop, a forward pointer, or a
    pointer into RDATA is DNSD-008 (critical/high) -- that is the shape
    behind an Unbound RCE and two dnsmasq memory-safety bugs, and
    collapsing it into the generic malformed bucket would bury a
    critical finding under an informational one.
    """


class Name:
    __slots__ = ("labels", "truncated")

    def __init__(self, labels, truncated=False):
        self.labels = labels
        self.truncated = truncated

    def text(self):
        if not self.labels:
            return "."
        return ".".join(l.decode("ascii", "replace") for l in self.labels) + "."

    def lower_labels(self):
        return [l.lower() for l in self.labels]

    def __repr__(self):
        return f"Name({self.text()!r})"


class RR:
    __slots__ = ("name", "rtype", "rclass", "ttl", "rdata", "rdlength", "section", "parsed")

    def __init__(self, name, rtype, rclass, ttl, rdata, rdlength, section):
        self.name = name
        self.rtype = rtype
        self.rclass = rclass
        self.ttl = ttl
        self.rdata = rdata
        self.rdlength = rdlength
        self.section = section
        self.parsed = {}


class DNSMessage:
    __slots__ = ("txid", "flags", "qr", "opcode", "aa", "tc", "rd", "ra", "ad", "cd",
                 "rcode", "questions", "answers", "authority", "additional",
                 "malformed", "malformed_reason", "pointer_anomaly",
                 "pointer_targets", "rdata_spans", "counts")

    def __init__(self):
        self.questions = []
        self.answers = []
        self.authority = []
        self.additional = []
        self.malformed = False
        self.malformed_reason = None
        self.pointer_anomaly = None
        self.pointer_targets = []
        self.rdata_spans = []
        self.counts = (0, 0, 0, 0)

    def all_rrs(self):
        return self.answers + self.authority + self.additional


def parse_l3_l4(frame):
    """
    Dual-stack. Returns
    (src_ip, dst_ip, sport, dport, proto, payload, ttl)
    or None if this frame isn't DNS-shaped. src/dst are returned as
    raw bytes -- formatting them costs CPU on the hot path and only
    matters when a finding actually fires.

    `ttl` is the IPv4 TTL or the IPv6 hop limit, read from the SAME
    position in meaning if not in offset. It is carried because RFC
    6762 s11 makes 255 a protocol requirement for mDNS, so the field
    is detection input here rather than plumbing. Appended last so
    existing positional unpacking of the first six stays valid.
    """
    if len(frame) < ETH_HDR:
        return None
    ethertype = int.from_bytes(frame[12:14], "big")
    off = ETH_HDR

    # One level of VLAN tag. On Linux AF_PACKET the OUTER tag is
    # usually stripped into auxdata before BPF runs and re-inserted by
    # libpcap for the reader (LESSON F), so a tag being visible here
    # is normal and must not be treated as an anomaly.
    if ethertype == ETH_P_VLAN:
        if len(frame) < off + 4:
            return None
        ethertype = int.from_bytes(frame[off + 2:off + 4], "big")
        off += 4

    if ethertype == ETH_P_IP:
        if len(frame) < off + 20:
            return None
        vihl = frame[off]
        if (vihl >> 4) != 4:
            return None
        ihl = (vihl & 0x0F) * 4
        if ihl < 20 or len(frame) < off + ihl:
            return None
        ip_ttl = frame[off + 8]
        proto = frame[off + 9]
        # A fragmented datagram cannot be parsed as DNS from one frame.
        frag = int.from_bytes(frame[off + 6:off + 8], "big")
        if frag & 0x1FFF:
            return None
        src, dst = frame[off + 12:off + 16], frame[off + 16:off + 20]
        l4 = off + ihl
    elif ethertype == ETH_P_IPV6:
        if len(frame) < off + 40:
            return None
        if (frame[off] >> 4) != 6:
            return None
        ip_ttl = frame[off + 7]          # hop limit
        proto = frame[off + 6]
        src, dst = frame[off + 8:off + 24], frame[off + 24:off + 40]
        l4 = off + 40
        # Walk extension headers. DNS itself is identical over v6, but
        # the L4 OFFSET is not fixed when EHs are present -- the exact
        # blind spot that bit juniperwatch and sshwatch. Hop-by-hop(0),
        # routing(43), destination(60) share the TLV shape.
        hops = 0
        while proto in (0, 43, 60) and hops < 8:
            if len(frame) < l4 + 2:
                return None
            nxt = frame[l4]
            ehlen = (frame[l4 + 1] + 1) * 8
            l4 += ehlen
            proto = nxt
            hops += 1
        if proto == 44:  # fragment header -- same reasoning as IPv4
            return None
    else:
        return None

    if proto == 17:  # UDP
        if len(frame) < l4 + 8:
            return None
        sport = int.from_bytes(frame[l4:l4 + 2], "big")
        dport = int.from_bytes(frame[l4 + 2:l4 + 4], "big")
        return (src, dst, sport, dport, "udp", frame[l4 + 8:], ip_ttl)
    if proto == 6:  # TCP
        if len(frame) < l4 + 20:
            return None
        sport = int.from_bytes(frame[l4:l4 + 2], "big")
        dport = int.from_bytes(frame[l4 + 2:l4 + 4], "big")
        doff = (frame[l4 + 12] >> 4) * 4
        if doff < 20 or len(frame) < l4 + doff:
            return None
        payload = frame[l4 + doff:]
        # DNS over TCP prefixes a 2-byte length.
        if len(payload) < 2:
            return None
        return (src, dst, sport, dport, "tcp", payload[2:], ip_ttl)
    return None


def parse_name(buf, offset, _jumps=0, _min_ptr=None, ptr_sink=None):
    """
    Returns (Name, next_offset). next_offset is the offset AFTER the
    name in the ORIGINAL stream (pointer jumps don't advance it).

    Raises MalformedDNS on: label overrun, oversized name, forward or
    equal pointer, jump budget exhaustion, or a truncated buffer.
    """
    labels = []
    total = 0
    next_offset = None
    cur = offset
    jumps = _jumps
    min_ptr = _min_ptr

    while True:
        if cur >= len(buf):
            raise MalformedDNS("name runs past end of message")
        ln = buf[cur]

        if ln == 0:
            cur += 1
            if next_offset is None:
                next_offset = cur
            return Name(labels), next_offset

        if (ln & 0xC0) == 0xC0:
            if cur + 1 >= len(buf):
                raise PointerAnomaly("compression pointer truncated")
            ptr = ((ln & 0x3F) << 8) | buf[cur + 1]
            if next_offset is None:
                next_offset = cur + 2
            jumps += 1
            if ptr_sink is not None:
                ptr_sink.append(ptr)
            if jumps > MAX_POINTER_JUMPS:
                raise PointerAnomaly("compression pointer jump budget exhausted")
            # STRICTLY DECREASING: a pointer must point earlier than
            # the pointer itself, and earlier than any pointer already
            # followed. This makes loops structurally impossible, and
            # rejects the forward-pointer parser-differential evasion.
            limit = cur if min_ptr is None else min(cur, min_ptr)
            if ptr >= limit:
                raise PointerAnomaly(
                    f"compression pointer must point strictly backwards "
                    f"(ptr={ptr}, limit={limit})")
            min_ptr = ptr
            cur = ptr
            continue

        if (ln & 0xC0) != 0:
            raise MalformedDNS(f"reserved label length bits set (0x{ln:02x})")
        if ln > MAX_LABEL_LEN:
            raise MalformedDNS(f"label longer than {MAX_LABEL_LEN}")
        if cur + 1 + ln > len(buf):
            raise MalformedDNS("label runs past end of message")

        total += ln + 1
        if total > MAX_NAME_LEN:
            raise NameTooLong(f"name longer than {MAX_NAME_LEN}",
                              accumulated=total, labels=labels)
        labels.append(buf[cur + 1:cur + 1 + ln])
        cur += 1 + ln


def _u16(buf, off):
    if off + 2 > len(buf):
        raise MalformedDNS("truncated u16")
    return int.from_bytes(buf[off:off + 2], "big")


def _u32(buf, off):
    if off + 4 > len(buf):
        raise MalformedDNS("truncated u32")
    return int.from_bytes(buf[off:off + 4], "big")


def parse_rr(buf, off, section, ptr_sink=None, rdata_spans=None):
    name, off = parse_name(buf, off, ptr_sink=ptr_sink)
    rtype = _u16(buf, off)
    rclass = _u16(buf, off + 2)
    ttl = _u32(buf, off + 4)
    rdlength = _u16(buf, off + 8)
    off += 10
    if off + rdlength > len(buf):
        raise MalformedDNS("rdlength runs past end of message")
    rr = RR(name, rtype, rclass, ttl, buf[off:off + rdlength], rdlength, section)
    if rdata_spans is not None and rdlength:
        rdata_spans.append((off, off + rdlength, rtype))
    _parse_rdata(rr, buf, off, ptr_sink=ptr_sink)
    return rr, off + rdlength


def _parse_rdata(rr, buf, rdoff, ptr_sink=None):
    """
    Decode the rdata fields the detectors actually read. Anything we
    don't decode stays available as raw bytes. Failures here are
    recorded on the RR rather than propagated -- a single unparseable
    rdata shouldn't discard an otherwise readable message.
    """
    try:
        if rr.rtype == T_DNSKEY and rr.rdlength >= 4:
            flags = _u16(buf, rdoff)
            proto = buf[rdoff + 2]
            algo = buf[rdoff + 3]
            key = rr.rdata[4:]
            rr.parsed = {"flags": flags, "protocol": proto, "algorithm": algo,
                         "key_tag": dnskey_key_tag(rr.rdata),
                         "zone_key": bool(flags & 0x0100),
                         "sep": bool(flags & 0x0001), "keylen": len(key)}
        elif rr.rtype == T_RRSIG and rr.rdlength >= 18:
            rr.parsed = {
                "type_covered": _u16(buf, rdoff),
                "algorithm": buf[rdoff + 2],
                "labels": buf[rdoff + 3],
                "original_ttl": _u32(buf, rdoff + 4),
                "expiration": _u32(buf, rdoff + 8),
                "inception": _u32(buf, rdoff + 12),
                "key_tag": _u16(buf, rdoff + 16),
            }
            # signer's name is NOT compressible inside RRSIG rdata per
            # RFC 4034 s3.1.7, so parse it standalone.
            try:
                signer, after = parse_name(buf, rdoff + 18, ptr_sink=ptr_sink)
                rr.parsed["signer"] = signer
                rr.parsed.update(_sigred_geometry(rr, signer, rdoff + 18, after))
            except NameTooLong as e:
                rr.parsed["signer"] = None
                g = _sigred_geometry_overflow(rr, e, rdoff + 18, buf)
                if g:
                    rr.parsed.update(g)
            except MalformedDNS:
                rr.parsed["signer"] = None
        elif rr.rtype == T_NSEC3 and rr.rdlength >= 5:
            salt_len = buf[rdoff + 4]
            rr.parsed = {
                "hash_algorithm": buf[rdoff],
                "flags": buf[rdoff + 1],
                "iterations": _u16(buf, rdoff + 2),
                "salt_length": salt_len,
                "opt_out": bool(buf[rdoff + 1] & 0x01),
            }
        elif rr.rtype == T_NS:
            target, _ = parse_name(buf, rdoff, ptr_sink=ptr_sink)
            rr.parsed = {"target": target}
        elif rr.rtype in (T_CNAME, T_DNAME, T_PTR):
            # PTR matters as much as CNAME here: in DNS-SD the PTR
            # rdata IS the service instance name, so without decoding
            # it the mDNS census can see that a service type exists
            # but never which device is advertising it.
            target, _ = parse_name(buf, rdoff, ptr_sink=ptr_sink)
            rr.parsed = {"target": target}
        elif rr.rtype == T_SRV and rr.rdlength >= 7:
            rr.parsed = {
                "priority": _u16(buf, rdoff),
                "weight": _u16(buf, rdoff + 2),
                "port": _u16(buf, rdoff + 4),
                "target": parse_name(buf, rdoff + 6)[0],
            }
        elif rr.rtype == T_NSEC and rr.rdlength >= 1:
            # RFC 4034 s4.1.1: next-domain is NOT compressible.
            nxt, after = parse_name(buf, rdoff)
            rr.parsed = {"next": nxt, "bitmap_len": rr.rdlength - (after - rdoff)}
        elif rr.rtype in (T_SVCB, T_HTTPS) and rr.rdlength >= 3:
            prio = _u16(buf, rdoff)
            target, _ = parse_name(buf, rdoff + 2)
            rr.parsed = {"priority": prio, "target": target,
                         "alias_mode": prio == 0, "service_mode": prio != 0}
        elif rr.rtype == T_OPT:
            opts, p, end = [], rdoff, rdoff + rr.rdlength
            while p + 4 <= end:
                ocode = _u16(buf, p)
                olen = _u16(buf, p + 2)
                if p + 4 + olen > end:
                    opts.append(("truncated", ocode))
                    break
                opts.append((ocode, olen))
                p += 4 + olen
            rr.parsed = {"options": opts}
        elif rr.rtype in (T_RRSIG, T_SIG) and rr.rtype == T_SIG and rr.rdlength >= 18:
            # SIG(24) shares RRSIG's layout. Decoded separately only so
            # the existing RRSIG branch above keeps its exact shape.
            rr.parsed = _parse_sig_like(buf, rdoff, rr, ptr_sink)
        elif rr.rtype == T_TSIG:
            rr.parsed = _parse_tsig(buf, rdoff, rr)
        elif rr.rtype == T_TKEY:
            rr.parsed = _parse_tkey(buf, rdoff, rr)
        elif rr.rtype == T_SOA:
            mname, o2 = parse_name(buf, rdoff)
            rname, _ = parse_name(buf, o2)
            rr.parsed = {"mname": mname, "rname": rname}
    except MalformedDNS as e:
        rr.parsed = {"rdata_error": str(e)}


def dnskey_key_tag(rdata):
    """
    RFC 4034 Appendix B key-tag computation. This is a CHECKSUM RULE,
    which per LESSON A is precisely the kind of thing a hand-rolled
    implementation and its hand-rolled test can agree on while both
    being wrong -- so xcheck.py verifies it against an independent
    implementation (dnspython) rather than against our own fixtures.

    Algorithm 1 (RSA/MD5) uses a completely different rule and is
    handled separately; it is deprecated but still appears in the wild.
    """
    if len(rdata) < 4:
        return None
    algorithm = rdata[3]
    if algorithm == 1:
        if len(rdata) < 7:
            return None
        return (rdata[-3] << 8) | rdata[-2]
    total = 0
    for i, b in enumerate(rdata):
        total += b if (i & 1) else (b << 8)
    total += (total >> 16) & 0xFFFF
    return total & 0xFFFF


def parse_dns(payload):
    """
    Total function: always returns a DNSMessage. On a structural
    failure it returns one with .malformed set and whatever sections
    were readable before the failure -- partial data is still useful
    to the posture detectors, and the malformation itself is DNSD-007.
    """
    msg = DNSMessage()
    if len(payload) < 12:
        msg.malformed = True
        msg.malformed_reason = "shorter than a DNS header"
        msg.pointer_anomaly = None
        msg.txid = None
        msg.qr = msg.opcode = msg.rcode = None
        msg.flags = 0
        msg.aa = msg.tc = msg.rd = msg.ra = msg.ad = msg.cd = False
        return msg

    msg.txid = int.from_bytes(payload[0:2], "big")
    flags = int.from_bytes(payload[2:4], "big")
    msg.flags = flags
    msg.qr = bool(flags & 0x8000)
    msg.opcode = (flags >> 11) & 0x0F
    msg.aa = bool(flags & 0x0400)
    msg.tc = bool(flags & 0x0200)
    msg.rd = bool(flags & 0x0100)
    msg.ra = bool(flags & 0x0080)
    msg.ad = bool(flags & 0x0020)
    msg.cd = bool(flags & 0x0010)
    msg.rcode = flags & 0x000F

    qd, an, ns, ar = (int.from_bytes(payload[i:i + 2], "big") for i in (4, 6, 8, 10))
    msg.counts = (qd, an, ns, ar)
    off = 12
    ptr_sink, rdata_spans = [], []
    msg.pointer_targets = ptr_sink
    msg.rdata_spans = rdata_spans
    try:
        for _ in range(qd):
            name, off = parse_name(payload, off, ptr_sink=ptr_sink)
            qtype = _u16(payload, off)
            qclass = _u16(payload, off + 2)
            off += 4
            msg.questions.append({"name": name, "qtype": qtype, "qclass": qclass})
        for count, section, bucket in ((an, "answer", msg.answers),
                                       (ns, "authority", msg.authority),
                                       (ar, "additional", msg.additional)):
            for _ in range(count):
                rr, off = parse_rr(payload, off, section,
                                   ptr_sink=ptr_sink, rdata_spans=rdata_spans)
                bucket.append(rr)
    except PointerAnomaly as e:
        msg.malformed = True
        msg.malformed_reason = str(e)
        msg.pointer_anomaly = str(e)
    except MalformedDNS as e:
        msg.malformed = True
        msg.malformed_reason = str(e)

    # A pointer that resolves INTO a resource record's RDATA is the
    # CVE-2026-81642 shape. It is not caught by the strictly-backward
    # rule, because a pointer into an EARLIER record's rdata points
    # backwards quite legally as far as that rule is concerned.
    if msg.pointer_anomaly is None:
        for ptr in ptr_sink:
            for start, end, rtype in rdata_spans:
                if start <= ptr < end:
                    msg.pointer_anomaly = (
                        f"compression pointer {ptr} resolves into the RDATA of a "
                        f"type-{rtype} record (bytes {start}..{end})")
                    break
            if msg.pointer_anomaly:
                break
    return msg


# ---------------------------------------------------------------------
# mDNS helpers (RFC 6762 / RFC 6763 DNS-SD)
# ---------------------------------------------------------------------

def mdns_class(raw_class):
    """Strip the QU / cache-flush bit before comparing to a class."""
    return raw_class & MDNS_CLASS_MASK


def mdns_unicast_requested(raw_qclass):
    """RFC 6762 s5.4 QU bit: the querier asked for a unicast reply.
    A unicast mDNS response is therefore NOT inherently a violation --
    only an OFF-LINK one is. Without this distinction the scope
    detector would fire on ordinary QU exchanges."""
    return bool(raw_qclass & MDNS_UNICAST_BIT)


def mdns_cache_flush(raw_rclass):
    return bool(raw_rclass & MDNS_CACHE_FLUSH_BIT)


def is_mdns_group(addr):
    return addr == MDNS_V4_GROUP or addr == MDNS_V6_GROUP


def service_type_of(name):
    """
    Extract the DNS-SD service type from a name, per RFC 6763 s4.1.

    Handles both shapes that appear on the wire:
      <service>.<proto>.local.                      (a PTR query/answer)
      <instance>.<service>.<proto>.local.           (an SRV/TXT owner)

    Returns a lowercase "_svc._proto" string, or None if the name is
    not service-shaped. Matching on this rather than on the full
    instance name is what keeps the census keyed to the SERVICE while
    the instance stays available separately.
    """
    labels = [l.lower() for l in name.lower_labels()] if hasattr(name, "lower_labels") else []
    if len(labels) < 2:
        return None
    for i in range(len(labels) - 1):
        a, b = labels[i], labels[i + 1]
        if a.startswith(b"_") and b in (b"_tcp", b"_udp"):
            return (a + b"." + b).decode("ascii", "replace")
    return None


def instance_of(name):
    """
    The instance label preceding a service type, if any.

    Reads the ORIGINAL labels, not the lowercased ones: DNS-SD
    instance names are UTF-8 human-readable strings ("Living Room
    Lamp") and are case-PRESERVING even though matching is
    case-insensitive. Folding them to lowercase for display would
    quietly mangle every device name in the census.
    """
    orig = getattr(name, "labels", [])
    for i in range(1, len(orig) - 1):
        if orig[i].lower().startswith(b"_") and orig[i + 1].lower() in (b"_tcp", b"_udp"):
            return orig[i - 1].decode("utf-8", "replace")
    return None


# =====================================================================
# TSIG / TKEY / SIG rdata decoding
#
# These three are decoded TOGETHER because they share one property that
# shapes the whole DDNS tier: each carries internal length fields that
# a receiver must trust before it has validated anything. Every CVE in
# this group is a receiver believing one of those lengths. So the
# decoders below are written as VALIDATORS first and accessors second:
# they never raise, and they record WHY a structure is impossible
# rather than silently returning partial fields that a detector would
# then read as if they were real.
# =====================================================================

def uncompressed_name_length(name):
    """Wire length this name WOULD occupy with no compression: one
    length byte per label plus the label bytes plus the root null.

    This is the quantity Windows' Name_PacketNameToCountNameEx reports
    and SIGRed abuses -- it is NOT the number of bytes the name took up
    on the wire, and the gap between the two is the whole attack."""
    if name is None:
        return 1
    if not name.labels:
        return 1
    return sum(len(l) + 1 for l in name.labels) + 1


def _sigred_geometry(rr, signer, signer_off, after_off):
    """Reconstruct the allocation arithmetic Windows DNS performs for a
    SIG or RRSIG record (CVE-2020-1350).

    sigred_alloc is computed with PYTHON ints, deliberately -- the
    vulnerability IS the 16-bit truncation, so computing it in 16 bits
    here would reproduce the bug instead of detecting it."""
    wire = after_off - signer_off
    sig_len = rr.rdlength - 18 - wire
    if sig_len < 0:
        sig_len = 0
    unc = uncompressed_name_length(signer)
    alloc = unc + SIGRED_ALLOC_OVERHEAD + sig_len
    return {
        "signer_wire_bytes": wire,
        "signer_uncompressed_len": unc,
        "signature_len": sig_len,
        "sigred_alloc": alloc,
        "sigred_wraps": alloc >= SIGRED_ALLOC_WRAP,
        # A name that cost fewer wire bytes than its uncompressed length
        # was reached through a compression pointer. Legitimate inside
        # SIG(24); forbidden inside RRSIG by RFC 4034 s3.1.7, and the
        # lever that lets 2 wire bytes contribute up to 255.
        "signer_compressed": wire < unc,
    }


def _sigred_geometry_overflow(rr, exc, signer_off, buf):
    """Geometry for a signer name that never terminated inside 255.

    The wire cost is recovered from the pointer itself rather than from
    a parse that did not finish: a two-byte pointer costs two bytes, and
    anything else here means the name was being read inline and the
    overflow is a malformed packet rather than the SIGRed lever.

    The uncompressed length is reported as AT LEAST what was reached
    before the cap. Windows applies no 255 cap in this path, so the real
    figure is larger; using the floor keeps the arithmetic a lower
    bound, and a lower bound that already wraps is proof enough.
    """
    ln = buf[signer_off] if signer_off < len(buf) else 0
    wire = 2 if (ln & 0xC0) == 0xC0 else None
    if wire is None:
        return None
    sig_len = rr.rdlength - 18 - wire
    if sig_len < 0:
        sig_len = 0
    unc = max(exc.accumulated, MAX_NAME_LEN + 1)
    alloc = unc + SIGRED_ALLOC_OVERHEAD + sig_len
    return {
        "signer_wire_bytes": wire,
        "signer_uncompressed_len": unc,
        "signer_uncompressed_is_floor": True,
        "signature_len": sig_len,
        "sigred_alloc": alloc,
        "sigred_wraps": alloc >= SIGRED_ALLOC_WRAP,
        "signer_compressed": True,
        "signer_overflow": str(exc),
    }


def _parse_sig_like(buf, rdoff, rr, ptr_sink=None):
    """SIG(24): identical layout to RRSIG(46)."""
    out = {
        "type_covered": _u16(buf, rdoff),
        "algorithm": buf[rdoff + 2],
        "labels": buf[rdoff + 3],
        "original_ttl": _u32(buf, rdoff + 4),
        "expiration": _u32(buf, rdoff + 8),
        "inception": _u32(buf, rdoff + 12),
        "key_tag": _u16(buf, rdoff + 16),
        "obsolete_sig_type": True,
    }
    try:
        signer, after = parse_name(buf, rdoff + 18, ptr_sink=ptr_sink)
        out["signer"] = signer
        out.update(_sigred_geometry(rr, signer, rdoff + 18, after))
    except NameTooLong as e:
        out["signer"] = None
        out["rdata_error"] = str(e)
        g = _sigred_geometry_overflow(rr, e, rdoff + 18, buf)
        if g:
            out.update(g)
    except MalformedDNS as e:
        out["signer"] = None
        out["rdata_error"] = str(e)
    return out


def _parse_tsig(buf, rdoff, rr):
    """
    RFC 8945 s4.2 TSIG rdata:
      algorithm name | time signed (48) | fudge (16) | MAC size (16)
      | MAC | original ID (16) | error (16) | other len (16) | other data

    Returns a dict that ALWAYS carries 'struct_error' (None when the
    record is internally consistent). CVE-2020-8622 is a receiver
    asserting while verifying a TSIG it could not fully read, so the
    structural verdict is the finding -- not a side note.
    """
    end = rdoff + rr.rdlength
    out = {"struct_error": None, "algorithm": None, "mac_size": None,
           "error": None, "error_name": None, "mac_truncated": False,
           "mac_empty": False, "gss": False}
    try:
        algo, p = parse_name(buf, rdoff)
    except MalformedDNS as e:
        out["struct_error"] = f"algorithm name unparseable: {e}"
        return out
    out["algorithm"] = algo.text().lower()
    out["gss"] = out["algorithm"] in TSIG_GSS_ALGOS

    if p + 10 > end:
        out["struct_error"] = (
            f"rdata ends after the algorithm name: {end - p} bytes left, "
            f"10 needed for time-signed/fudge/MAC-size")
        return out
    out["time_signed"] = int.from_bytes(buf[p:p + 6], "big")
    out["fudge"] = _u16(buf, p + 6)
    mac_size = _u16(buf, p + 8)
    out["mac_size"] = mac_size
    mac_end = p + 10 + mac_size
    if mac_end + 6 > end:
        out["struct_error"] = (
            f"MAC size {mac_size} plus the 6 trailing bytes overruns the "
            f"rdata by {mac_end + 6 - end} bytes")
        return out
    out["original_id"] = _u16(buf, mac_end)
    err = _u16(buf, mac_end + 2)
    out["error"] = err
    out["error_name"] = TSIG_FAILURE_CODES.get(err)
    other_len = _u16(buf, mac_end + 4)
    out["other_len"] = other_len
    tail = mac_end + 6 + other_len
    if tail > end:
        out["struct_error"] = (
            f"other-data length {other_len} overruns the rdata by {tail - end} bytes")
        return out
    if tail < end:
        out["struct_error"] = (
            f"{end - tail} trailing bytes after other-data; TSIG rdata must end exactly")
        return out

    # MAC truncation. RFC 8945 s5.2 permits truncation but never below
    # half the digest length and never below 80 bits. gss-tsig is
    # excluded: its MAC is a variable-length GSS checksum, so applying
    # a digest-length rule to it would fire on every AD exchange.
    full = TSIG_DIGEST_LEN.get(out["algorithm"])
    if mac_size == 0:
        out["mac_empty"] = True
    elif full is not None and not out["gss"]:
        floor = max(10, full // 2)
        if mac_size < floor:
            out["mac_truncated"] = True
            out["mac_floor"] = floor
            out["mac_full"] = full
    return out


def _der_len(buf, i, end):
    """Read one DER length. Returns ((length, next_index), None) or
    (None, reason). Rejects indefinite and non-minimal encodings, both
    of which are illegal in DER and both of which appear in malformed
    SPNEGO tokens."""
    if i >= end:
        return None, "length byte missing"
    b = buf[i]
    i += 1
    if b < 0x80:
        return (b, i), None
    n = b & 0x7F
    if n == 0:
        return None, "indefinite-length encoding is illegal in DER"
    if n > 4:
        return None, f"length encoded in {n} bytes"
    if i + n > end:
        return None, "long-form length field is itself truncated"
    v = int.from_bytes(buf[i:i + n], "big")
    i += n
    if v < 0x80:
        return None, f"non-minimal long-form length ({v} in {n} bytes)"
    return (v, i), None


def _der_scan(buf, i, end, depth=0):
    """
    Bounded DER structural walk. Returns None when sound, else a reason.

    This is the CVE-2020-8625 / CVE-2021-25216 check. The BIND SPNEGO
    decoder trusted a DER length field and copied that many bytes, so
    the wire-visible precondition is a TLV whose declared length
    exceeds what the token actually contains. Nothing here interprets
    SPNEGO SEMANTICS -- only whether its lengths are self-consistent,
    which is the one question that can be answered from the bytes.
    """
    if depth > 12:
        return "DER nesting deeper than 12 levels"
    seen = 0
    while i < end:
        seen += 1
        if seen > 256:
            return "more than 256 TLVs in one SPNEGO token"
        tag = buf[i]
        i += 1
        r, err = _der_len(buf, i, end)
        if err:
            return err
        length, i = r
        if i + length > end:
            return (f"DER tag 0x{tag:02x} claims {length} bytes but only "
                    f"{end - i} remain in the token")
        if tag & 0x20:          # constructed -> descend
            sub = _der_scan(buf, i, i + length, depth + 1)
            if sub:
                return sub
        i += length
    return None


def spnego_struct_error(token):
    """Structural verdict on a GSS/SPNEGO token from TKEY key data."""
    if len(token) < 2:
        return "token shorter than one DER TLV"
    if token[0] != DER_APPLICATION_0:
        # Continuation tokens are legitimately not APPLICATION 0, so
        # this is not an error on its own -- scan what is there.
        return _der_scan(token, 0, len(token))
    r, err = _der_len(token, 1, len(token))
    if err:
        return f"outer GSS token: {err}"
    length, body = r
    if body + length > len(token):
        return (f"outer GSS token claims {length} bytes but only "
                f"{len(token) - body} follow")
    if not token[body:body + len(SPNEGO_OID)] == SPNEGO_OID:
        # Not SPNEGO (could be raw Kerberos). Still walk it.
        return _der_scan(token, body, body + length, 1)
    return _der_scan(token, body + len(SPNEGO_OID), body + length, 1)


def _parse_tkey(buf, rdoff, rr):
    """
    RFC 2930 s2 TKEY rdata:
      algorithm name | inception (32) | expiration (32) | mode (16)
      | error (16) | key size (16) | key data | other size (16) | other data
    """
    end = rdoff + rr.rdlength
    out = {"struct_error": None, "algorithm": None, "mode": None,
           "key_size": None, "spnego_error": None, "gssapi": False}
    try:
        algo, p = parse_name(buf, rdoff)
    except MalformedDNS as e:
        out["struct_error"] = f"algorithm name unparseable: {e}"
        return out
    out["algorithm"] = algo.text().lower()
    if p + 14 > end:
        out["struct_error"] = (
            f"rdata ends after the algorithm name: {end - p} bytes left, 14 needed")
        return out
    out["inception"] = _u32(buf, p)
    out["expiration"] = _u32(buf, p + 4)
    out["mode"] = _u16(buf, p + 8)
    out["error"] = _u16(buf, p + 10)
    key_size = _u16(buf, p + 12)
    out["key_size"] = key_size
    key_start = p + 14
    key_end = key_start + key_size
    if key_end + 2 > end:
        out["struct_error"] = (
            f"key size {key_size} plus the other-size field overruns the "
            f"rdata by {key_end + 2 - end} bytes")
        return out
    other_size = _u16(buf, key_end)
    out["other_size"] = other_size
    if key_end + 2 + other_size > end:
        out["struct_error"] = (
            f"other-size {other_size} overruns the rdata by "
            f"{key_end + 2 + other_size - end} bytes")
        return out
    out["gssapi"] = out["mode"] == TKEY_MODE_GSSAPI
    if out["gssapi"] and key_size:
        out["spnego_error"] = spnego_struct_error(buf[key_start:key_end])
    return out
