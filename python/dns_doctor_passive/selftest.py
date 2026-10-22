#!/usr/bin/env python3
"""
Tier 1 self-test: fabricate frames, push them through the REAL
Engine.handle_frame(), assert on finding codes.

Every fixture is built with scapy's PER-TYPE DNSSEC record classes
(DNSRRDNSKEY/DNSRRRSIG/DNSRRNSEC3) and then RE-DISSECTED before use.
That is not ceremony -- a naive DNSRR(type="DNSKEY") builds bytes that
scapy itself re-dissects as Raw, so a fixture built that way would
validate the parser against garbage while looking perfectly fine
(the LESSON AD shape, caught during this build).

Every structural scenario runs over BOTH IPv4 and IPv6 to satisfy the
dual-stack mandate at the tier level, not just in the parser.
"""
import unittest

from scapy.all import Ether, IP, IPv6, UDP, raw
from scapy.layers.dns import (DNS, DNSQR, DNSRR, DNSRRDNSKEY, DNSRRRSIG,
                              DNSRRNSEC3, DNSRRSOA, DNSRRNSEC, DNSRROPT, EDNS0TLV)
from scapy.all import Ether, UDP

import parse
from state import Config
from engine import Engine

V4 = IP(src="192.0.2.10", dst="192.0.2.20")
V6 = IPv6(src="2001:db8::10", dst="2001:db8::20")


def frame(dns, l3=None, sport=53, dport=33333):
    """Serialize, then RE-PARSE through scapy so the bytes under test
    are the bytes a dissector agrees are well-formed."""
    l3 = V4 if l3 is None else l3
    return raw(Ether() / l3 / UDP(sport=sport, dport=dport) / dns)


def dnskey(tag_seed, algorithm=8, keybytes=None):
    return DNSRRDNSKEY(rrname="example.com.", flags=257, protocol=3,
                       algorithm=algorithm,
                       publickey=keybytes or bytes([tag_seed % 256]) * 64)


def rrsig(covered="A", algorithm=8, keytag=1234):
    return DNSRRRSIG(rrname="example.com.", typecovered=covered, algorithm=algorithm,
                     labels=2, originalttl=3600, expiration=1800000000,
                     inception=1700000000, keytag=keytag,
                     signersname="example.com.", signature=b"\x11" * 64)


def codes(findings):
    return sorted(f["code"] for f in findings)


class DualStackMixin:
    """Runs a scenario on both stacks and asserts identical verdicts.
    The prime directive is that parity is TESTED, not assumed."""

    def assert_both_stacks(self, dns, expect_code, sport=53, dport=33333):
        got = {}
        for label, l3 in (("IPv4", V4), ("IPv6", V6)):
            eng = Engine(Config())
            out = eng.handle_frame(frame(dns, l3, sport, dport))
            got[label] = codes(out)
            self.assertIn(expect_code, got[label],
                          f"{label}: expected {expect_code}, got {got[label]}")
        self.assertEqual(got["IPv4"], got["IPv6"],
                         f"dual-stack divergence: {got}")
        return got["IPv4"]


class TestKeyTrap(unittest.TestCase, DualStackMixin):
    def test_colliding_key_tags_fire_dnsd001(self):
        # Two DISTINCT keys that genuinely share a key tag. SEARCHED
        # for, never asserted: a fabricated "collision" that isn't one
        # would make this test pass for the wrong reason.
        #
        # The key material must be SPREAD, not a counter. RFC 4034's
        # key tag is a weighted byte sum, so keys differing by an
        # incrementing integer produce strictly INCREASING tags and can
        # never collide -- the first version of this fixture searched
        # 4000 such keys and found nothing, which looked like a
        # detector bug and was a fixture bug (LESSON K). Hashed key
        # material spreads across the 16-bit space and collides at the
        # birthday bound, a few hundred samples in.
        import hashlib
        by_tag = {}
        pair = None
        for i in range(6000):
            key = hashlib.sha256(i.to_bytes(4, "big")).digest() * 2
            rd = b"\x01\x01\x03\x08" + key
            tag = parse.dnskey_key_tag(rd)
            if tag in by_tag and by_tag[tag] != key:
                pair = (by_tag[tag], key)
                break
            by_tag[tag] = key
        self.assertIsNotNone(pair, "no key-tag collision found in search space")
        self.assertNotEqual(pair[0], pair[1], "collision pair must be DISTINCT keys")
        t1 = parse.dnskey_key_tag(b"\x01\x01\x03\x08" + pair[0])
        t2 = parse.dnskey_key_tag(b"\x01\x01\x03\x08" + pair[1])
        self.assertEqual(t1, t2, "searched pair must actually share a tag")
        k1 = DNSRRDNSKEY(rrname="example.com.", flags=257, protocol=3, algorithm=8,
                         publickey=pair[0])
        k2 = DNSRRDNSKEY(rrname="example.com.", flags=257, protocol=3, algorithm=8,
                         publickey=pair[1])
        dns = DNS(qr=1, qd=DNSQR(qname="example.com.", qtype="DNSKEY"),
                  an=k1 / k2, ancount=2)
        self.assert_both_stacks(dns, "DNSD-001")

    def test_identical_duplicate_key_is_not_a_collision(self):
        """A key repeated twice shares its tag with itself. That is a
        duplicate record, not a collision, and must not fire."""
        k = dnskey(7)
        dns = DNS(qr=1, qd=DNSQR(qname="example.com.", qtype="DNSKEY"),
                  an=k / dnskey(7), ancount=2)
        eng = Engine(Config())
        self.assertNotIn("DNSD-001", codes(eng.handle_frame(frame(dns))))

    def test_rrsig_burst_fires_dnsd002(self):
        sigs = rrsig()
        for i in range(9):
            sigs = sigs / rrsig(keytag=1000 + i)
        dns = DNS(qr=1, qd=DNSQR(qname="example.com.", qtype="A"), an=sigs, ancount=10)
        self.assert_both_stacks(dns, "DNSD-002")

    def test_rrsigs_over_different_rrsets_do_not_fire(self):
        """Rollovers legitimately produce several RRSIGs across
        DIFFERENT RRsets; only many over ONE RRset is the signature."""
        chain = rrsig(covered="A")
        for t in ("AAAA", "MX", "TXT", "NS", "SOA", "PTR", "SRV", "CNAME"):
            chain = chain / rrsig(covered=t)
        dns = DNS(qr=1, qd=DNSQR(qname="example.com.", qtype="A"), an=chain, ancount=9)
        eng = Engine(Config())
        self.assertNotIn("DNSD-002", codes(eng.handle_frame(frame(dns))))

    def test_crypto_product_fires_dnsd003(self):
        chain = dnskey(1, keybytes=b"\x01" * 64)
        for i in range(2, 9):
            chain = chain / dnskey(i, keybytes=bytes([i]) * 64)
        for i in range(9):
            chain = chain / rrsig(keytag=2000 + i)
        dns = DNS(qr=1, qd=DNSQR(qname="example.com.", qtype="DNSKEY"),
                  an=chain, ancount=17)
        self.assert_both_stacks(dns, "DNSD-003")


def _rdata(rr):
    """Extract a built RR's rdata exactly as it appears on the wire."""
    b = raw(DNS(qr=1, an=rr, ancount=1))
    m = parse.parse_dns(b)
    return bytes(m.answers[0].rdata)


class TestNsec3AndAlgo(unittest.TestCase, DualStackMixin):
    def test_nsec3_iterations_fire_dnsd010(self):
        n = DNSRRNSEC3(rrname="example.com.", hashalg=1, flags=0, iterations=150,
                       saltlength=4, salt=b"\xaa\xbb\xcc\xdd", hashlength=20,
                       nexthashedownername=b"\x01" * 20)
        dns = DNS(qr=1, rcode=3, qd=DNSQR(qname="nx.example.com.", qtype="A"),
                  ns=n, nscount=1)
        self.assert_both_stacks(dns, "DNSD-010")

    def test_zero_iterations_is_compliant_and_silent(self):
        n = DNSRRNSEC3(rrname="example.com.", hashalg=1, flags=0, iterations=0,
                       saltlength=0, salt=b"", hashlength=20,
                       nexthashedownername=b"\x01" * 20)
        dns = DNS(qr=1, rcode=3, qd=DNSQR(qname="nx.example.com.", qtype="A"),
                  ns=n, nscount=1)
        eng = Engine(Config())
        self.assertNotIn("DNSD-010", codes(eng.handle_frame(frame(dns))))

    def test_unsupported_algorithm_fires_dnsd011(self):
        dns = DNS(qr=1, ad=0, rcode=0, qd=DNSQR(qname="example.com.", qtype="A"),
                  an=rrsig(algorithm=12), ancount=1)   # 12 = GOST, deprecated
        self.assert_both_stacks(dns, "DNSD-011")

    def test_ad_set_means_validator_authenticated_so_silent(self):
        dns = DNS(qr=1, ad=1, rcode=0, qd=DNSQR(qname="example.com.", qtype="A"),
                  an=rrsig(algorithm=12), ancount=1)
        eng = Engine(Config())
        self.assertNotIn("DNSD-011", codes(eng.handle_frame(frame(dns))))

    def test_servfail_means_it_failed_loudly_so_silent(self):
        dns = DNS(qr=1, ad=0, rcode=2, qd=DNSQR(qname="example.com.", qtype="A"),
                  an=rrsig(algorithm=12), ancount=1)
        eng = Engine(Config())
        self.assertNotIn("DNSD-011", codes(eng.handle_frame(frame(dns))))

    def test_supported_algorithm_is_silent(self):
        dns = DNS(qr=1, ad=0, rcode=0, qd=DNSQR(qname="example.com.", qtype="A"),
                  an=rrsig(algorithm=13), ancount=1)   # ECDSA P-256
        eng = Engine(Config())
        self.assertNotIn("DNSD-011", codes(eng.handle_frame(frame(dns))))


class TestNewCveCodes(unittest.TestCase, DualStackMixin):
    """
    The 11 codes added from the Sept 2026 CVE register. Every one runs
    over BOTH stacks and asserts identical verdicts -- the register
    claims dual-stack parity "holds by construction" because these are
    record-layer checks, and this is where that claim is tested rather
    than trusted.
    """

    def test_dnskey_malformed_dnsd009(self):
        k = DNSRRDNSKEY(rrname="example.com.", flags=257, protocol=4,
                        algorithm=8, publickey=b"\x01" * 64)
        dns = DNS(qr=1, qd=DNSQR(qname="example.com.", qtype="DNSKEY"), an=k, ancount=1)
        self.assert_both_stacks(dns, "DNSD-009")

    def test_wellformed_dnskey_is_silent(self):
        k = DNSRRDNSKEY(rrname="example.com.", flags=257, protocol=3,
                        algorithm=8, publickey=b"\x01" * 64)
        dns = DNS(qr=1, qd=DNSQR(qname="example.com.", qtype="DNSKEY"), an=k, ancount=1)
        eng = Engine(Config())
        self.assertNotIn("DNSD-009", codes(eng.handle_frame(frame(dns))))

    def test_rrsig_label_mismatch_dnsd040(self):
        sig = DNSRRRSIG(rrname="www.example.com.", typecovered="A", algorithm=8, labels=9,
                        originalttl=3600, expiration=1800000000, inception=1700000000,
                        keytag=1, signersname="example.com.", signature=b"\x11" * 32)
        dns = DNS(qr=1, qd=DNSQR(qname="www.example.com.", qtype="A"), an=sig, ancount=1)
        self.assert_both_stacks(dns, "DNSD-040")

    def test_wildcard_rrsig_labels_are_silent(self):
        """labels < owner count is how wildcard expansion is signalled.
        Firing here would alert on every wildcard zone on the internet."""
        sig = DNSRRRSIG(rrname="a.b.example.com.", typecovered="A", algorithm=8, labels=2,
                        originalttl=3600, expiration=1800000000, inception=1700000000,
                        keytag=1, signersname="example.com.", signature=b"\x11" * 32)
        dns = DNS(qr=1, qd=DNSQR(qname="a.b.example.com.", qtype="A"), an=sig, ancount=1)
        eng = Engine(Config())
        self.assertNotIn("DNSD-040", codes(eng.handle_frame(frame(dns))))

    def test_nsec_out_of_zone_dnsd041(self):
        n = DNSRRNSEC(rrname="a.example.com.", nextname="evil.attacker.net.")
        dns = DNS(qr=1, rcode=3, qd=DNSQR(qname="example.com.", qtype="A"), ns=n, nscount=1)
        self.assert_both_stacks(dns, "DNSD-041")

    def test_nsec_apex_wrap_is_silent(self):
        n = DNSRRNSEC(rrname="z.example.com.", nextname="example.com.")
        dns = DNS(qr=1, rcode=3, qd=DNSQR(qname="example.com.", qtype="A"), ns=n, nscount=1)
        eng = Engine(Config())
        self.assertNotIn("DNSD-041", codes(eng.handle_frame(frame(dns))))

    def test_nsec3_apex_impersonation_dnsd042(self):
        n = DNSRRNSEC3(rrname="HASH.attacker.net.", hashalg=1, flags=0, iterations=0,
                       saltlength=0, salt=b"", hashlength=20,
                       nexthashedownername=b"\x02" * 20)
        dns = DNS(qr=1, rcode=3, qd=DNSQR(qname="example.com.", qtype="A"), ns=n, nscount=1)
        self.assert_both_stacks(dns, "DNSD-042")

    def test_edns_option_duplication_dnsd051(self):
        opt = DNSRROPT(rclass=4096, rdata=[EDNS0TLV(optcode=3, optdata=b"abcd"),
                                           EDNS0TLV(optcode=3, optdata=b"efgh")])
        dns = DNS(qr=1, qd=DNSQR(qname="example.com.", qtype="A"), ar=opt, arcount=1)
        self.assert_both_stacks(dns, "DNSD-051")

    def test_distinct_edns_options_are_silent(self):
        opt = DNSRROPT(rclass=4096, rdata=[EDNS0TLV(optcode=3, optdata=b"abcd"),
                                           EDNS0TLV(optcode=12, optdata=b"\x00" * 8)])
        dns = DNS(qr=1, qd=DNSQR(qname="example.com.", qtype="A"), ar=opt, arcount=1)
        eng = Engine(Config())
        self.assertNotIn("DNSD-051", codes(eng.handle_frame(frame(dns))))

    def test_duplicate_soa_flood_dnsd052(self):
        chain = DNSRRSOA(rrname="example.com.", mname="ns.example.com.",
                         rname="hostmaster.example.com.", serial=1)
        for _ in range(11):
            chain = chain / DNSRRSOA(rrname="example.com.", mname="ns.example.com.",
                                     rname="hostmaster.example.com.", serial=1)
        dns = DNS(qr=1, rcode=3, qd=DNSQR(qname="example.com.", qtype="SOA"),
                  an=chain, ancount=12)
        self.assert_both_stacks(dns, "DNSD-052")

    def test_round_robin_a_records_are_silent(self):
        chain = DNSRR(rrname="example.com.", type="A", ttl=60, rdata="192.0.2.1")
        for _ in range(19):
            chain = chain / DNSRR(rrname="example.com.", type="A", ttl=60, rdata="192.0.2.1")
        dns = DNS(qr=1, qd=DNSQR(qname="example.com.", qtype="A"), an=chain, ancount=20)
        eng = Engine(Config())
        self.assertNotIn("DNSD-052", codes(eng.handle_frame(frame(dns))))

    def test_tkey_query_dnsd053(self):
        dns = DNS(qr=0, qd=DNSQR(qname="example.com.", qtype=249))
        for l3 in (V4, V6):
            eng = Engine(Config())
            out = codes(eng.handle_frame(frame(dns, l3, sport=40000, dport=53)))
            self.assertIn("DNSD-053", out)

    def test_pointer_anomaly_is_not_merely_malformed(self):
        """DNSD-008 must be SEPARATE from DNSD-007: one is a
        memory-safety primitive, the other is network noise."""
        payload = b"\xab\xcd\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00" + b"\xc0\x0c"
        for l3 in (V4, V6):
            eng = Engine(Config())
            f = raw(Ether() / l3 / UDP(sport=53, dport=33333)) + payload
            out = codes(eng.handle_frame(f))
            self.assertIn("DNSD-008", out)


class TestMdnsTier(unittest.TestCase):
    """
    The mDNS tier, over both stacks. Matter is IPv6-first, so the v6
    path carries most of the real signal and is tested first-class
    rather than as an afterthought.
    """

    @staticmethod
    def _frame(l3, records, qr=True, sport=5353, dport=5353):
        an = None
        for rr in records:
            an = rr if an is None else an / rr
        dns = DNS(qr=1 if qr else 0, an=an, ancount=len(records))
        return raw(Ether() / l3 / UDP(sport=sport, dport=dport) / dns)

    @staticmethod
    def _ptr(service, instance="Hall Light"):
        return DNSRR(rrname=f"{service}.local.", type="PTR", ttl=4500,
                     rdata=f"{instance}.{service}.local.")

    def _v4(self, ttl=255):
        return IP(src="192.168.1.50", dst="224.0.0.251", ttl=ttl)

    def _v6(self, hlim=255):
        p = IPv6(src="2001:db8:1::50", dst="ff02::fb")
        p.hlim = hlim
        return p

    def test_matter_census_both_stacks(self):
        for label, l3 in (("IPv4", self._v4()), ("IPv6", self._v6())):
            eng = Engine(Config())
            got = codes(eng.handle_frame(self._frame(l3, [self._ptr("_matter._tcp")])))
            self.assertIn("DNSD-070", got, f"{label}: {got}")

    def test_thread_border_router_census(self):
        eng = Engine(Config())
        got = codes(eng.handle_frame(
            self._frame(self._v6(), [self._ptr("_meshcop._udp", "Border Router")])))
        self.assertIn("DNSD-073", got, got)

    def test_commissionable_and_commissioner(self):
        for svc, code in (("_matterc._udp", "DNSD-071"), ("_matterd._udp", "DNSD-072")):
            eng = Engine(Config())
            got = codes(eng.handle_frame(self._frame(self._v4(), [self._ptr(svc)])))
            self.assertIn(code, got, f"{svc}: {got}")

    def test_census_reports_once_per_instance(self):
        eng = Engine(Config())
        f = self._frame(self._v4(), [self._ptr("_matter._tcp", "Lamp A")])
        self.assertIn("DNSD-070", codes(eng.handle_frame(f)))
        self.assertNotIn("DNSD-070", codes(eng.handle_frame(f)),
                         "re-announcement must be suppressed")

    def test_ttl_violation_both_stacks(self):
        for label, l3 in (("IPv4 TTL", self._v4(ttl=64)), ("IPv6 hop limit", self._v6(hlim=64))):
            eng = Engine(Config())
            got = codes(eng.handle_frame(self._frame(l3, [self._ptr("_matter._tcp")])))
            self.assertIn("DNSD-074", got, f"{label}: {got}")

    def test_compliant_ttl_is_silent(self):
        for l3 in (self._v4(), self._v6()):
            eng = Engine(Config())
            got = codes(eng.handle_frame(self._frame(l3, [self._ptr("_matter._tcp")])))
            self.assertNotIn("DNSD-074", got, got)

    def test_off_link_unicast_reflector(self):
        cfg = Config(mdns_local_prefixes=("192.168.1.0/24",))
        eng = Engine(cfg)
        l3 = IP(src="192.168.1.50", dst="203.0.113.77", ttl=255)
        got = codes(eng.handle_frame(self._frame(l3, [self._ptr("_matter._tcp")])))
        self.assertIn("DNSD-076", got, got)

    def test_on_link_unicast_is_a_legitimate_qu_reply(self):
        cfg = Config(mdns_local_prefixes=("192.168.1.0/24",))
        eng = Engine(cfg)
        l3 = IP(src="192.168.1.50", dst="192.168.1.77", ttl=255)
        got = codes(eng.handle_frame(self._frame(l3, [self._ptr("_matter._tcp")])))
        self.assertNotIn("DNSD-076", got, got)

    def test_mdns_never_triggers_unicast_dns_codes(self):
        """Port routing. Every mDNS name ends in .local, so without
        the split the bailiwick detector alone would fire on nearly
        every announcement on the network."""
        from findings import FINDINGS as _F
        dns_codes = {c for c, m in _F.items() if m["klass"] != "mdns"}
        eng = Engine(Config(mdns_local_prefixes=("192.168.1.0/24",)))
        got = set(codes(eng.handle_frame(
            self._frame(self._v4(), [self._ptr("_matter._tcp"),
                                     self._ptr("_meshcop._udp", "BR")]))))
        self.assertFalse(got & dns_codes, f"leaked unicast-DNS codes: {got & dns_codes}")


class TestMalformed(unittest.TestCase):
    def test_truncated_message_fires_dnsd007(self):
        eng = Engine(Config())
        f = raw(Ether() / V4 / UDP(sport=53, dport=33333)) + b"\x12\x34\x81\x80\x00\x01"
        self.assertIn("DNSD-007", codes(eng.handle_frame(f)))

    def test_pointer_loop_is_caught_not_hung(self):
        """A self-referential compression pointer must be reported as
        malformed, not spin the detection thread forever."""
        payload = (b"\xab\xcd\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00" + b"\xc0\x0c")
        f = raw(Ether() / V4 / UDP(sport=53, dport=33333)) + payload
        eng = Engine(Config())
        out = eng.handle_frame(f)
        self.assertIn("DNSD-007", codes(out))

    def test_wellformed_response_does_not_fire_dnsd007(self):
        dns = DNS(qr=1, qd=DNSQR(qname="example.com.", qtype="A"),
                  an=DNSRR(rrname="example.com.", type="A", ttl=300, rdata="192.0.2.1"),
                  ancount=1)
        eng = Engine(Config())
        self.assertNotIn("DNSD-007", codes(eng.handle_frame(frame(dns))))


class TestNotDns(unittest.TestCase):
    def test_non_dns_frame_is_ignored(self):
        eng = Engine(Config())
        f = raw(Ether() / V4 / UDP(sport=1234, dport=4321) / b"hello")
        out = eng.handle_frame(f)
        # port-53 filtering is the BPF's job; the engine still parses
        # whatever reaches it, but must not crash or invent findings.
        self.assertIsInstance(out, list)

    def test_arp_frame_is_ignored(self):
        eng = Engine(Config())
        self.assertEqual(eng.handle_frame(raw(Ether(type=0x0806) / (b"\x00" * 28))), [])



# ======================================================================
# DDNS / rDNS tiers
# ======================================================================

def ddns_frame(payload, l3=None, sport=33333, dport=53):
    l3 = V4 if l3 is None else l3
    return raw(Ether() / l3 / UDP(sport=sport, dport=dport) / payload)


def update_wire(zone="example.com.", adds=(("host1", "A", "192.0.2.10"),),
                keyname=None, prereq_only=False):
    """UPDATE built by dnspython, an INDEPENDENT implementation.

    The detectors read a hand-rolled parser; if the fixtures came from
    a hand-rolled serializer too, a shared misreading of RFC 2136's
    section semantics would be invisible here (LESSON A).
    """
    import base64
    import dns.update, dns.tsigkeyring, dns.name
    kw = {}
    if keyname:
        kw = {"keyring": dns.tsigkeyring.from_text(
                  {keyname: base64.b64encode(b"0" * 32).decode()}),
              "keyname": keyname,
              "keyalgorithm": dns.name.from_text("hmac-sha256.")}
    u = dns.update.Update(zone, **kw)
    if prereq_only:
        u.present("host9")
        return u.to_wire()
    for n, t, v in adds:
        u.add(n, 300, t, v)
    return u.to_wire()


def update_response(request_wire, rcode=0, tsig=None):
    import struct
    txid = int.from_bytes(request_wire[0:2], "big")
    flags = 0x8000 | (5 << 11) | rcode
    hdr = struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 1 if tsig else 0)
    off = 12
    while request_wire[off] != 0:
        off += 1 + request_wire[off]
    zone_sec = request_wire[12:off + 1] + request_wire[off + 1:off + 5]
    return hdr + zone_sec + (tsig or b"")


def tsig_bytes(mac_size=32, mac=None, err=0, algo=b"\x0bhmac-sha256\x00"):
    import struct
    mac = mac if mac is not None else b"\x22" * 32
    rd = (algo + (0).to_bytes(6, "big") + struct.pack("!HH", 300, mac_size) + mac
          + struct.pack("!HHH", 0x1234, err, 0))
    return b"\x01k\x00" + struct.pack("!HHIH", parse.T_TSIG, 255, 0, len(rd)) + rd


# Matched client/server L3 pairs per family, so a response is keyed on
# the same conversation as its request.
PAIRS = (
    ("IPv4", IP(src="10.0.0.5", dst="10.0.0.1"), IP(src="10.0.0.1", dst="10.0.0.5")),
    ("IPv6", IPv6(src="fd00::5", dst="fd00::1"), IPv6(src="fd00::1", dst="fd00::5")),
)


class TestDdnsTier(unittest.TestCase):
    """Every DDNS scenario on BOTH stacks, with identical verdicts
    asserted -- the prime directive is that parity is tested, not
    assumed."""

    def _exchange(self, cfg, req, cli, srv, rcode=0, tsig=None, now=1.0):
        eng = Engine(cfg)
        first = eng.handle_frame(ddns_frame(req, cli, 33333, 53), now=now)
        second = eng.handle_frame(
            ddns_frame(update_response(req, rcode, tsig), srv, 53, 33333), now=now + 0.01)
        return eng, codes(first), codes(second)

    def test_unsigned_update_accepted_both_stacks(self):
        got = {}
        for label, cli, srv in PAIRS:
            _, c1, c2 = self._exchange(Config(), update_wire(), cli, srv)
            self.assertEqual(c1, [], f"{label}: the request alone must report nothing")
            self.assertIn("DNSD-080", c2, f"{label}: got {c2}")
            got[label] = c2
        self.assertEqual(got["IPv4"], got["IPv6"], f"dual-stack divergence: {got}")

    def test_rejected_update_is_silent_both_stacks(self):
        for label, cli, srv in PAIRS:
            for rcode in (5, 9, 6, 8):
                _, _, c2 = self._exchange(Config(), update_wire(), cli, srv, rcode=rcode)
                self.assertEqual(c2, [], f"{label}: rcode {rcode} must be silent, got {c2}")

    def test_prereq_only_update_is_silent_both_stacks(self):
        """An UPDATE with an empty update section mutates nothing, so a
        NOERROR says only that the prerequisite held. RFC 4703 DHCP
        clients send this on every renewal."""
        for label, cli, srv in PAIRS:
            _, _, c2 = self._exchange(Config(), update_wire(prereq_only=True), cli, srv)
            self.assertEqual(c2, [], f"{label}: got {c2}")

    def test_tsig_bypass_both_stacks(self):
        got = {}
        for label, cli, srv in PAIRS:
            _, _, c2 = self._exchange(Config(), update_wire(keyname="k."), cli, srv,
                                      rcode=0, tsig=tsig_bytes(err=16))
            self.assertIn("DNSD-081", c2, f"{label}: got {c2}")
            self.assertNotIn("DNSD-080", c2,
                             f"{label}: a signed update is never an unsigned one")
            got[label] = c2
        self.assertEqual(got["IPv4"], got["IPv6"], f"dual-stack divergence: {got}")

    def test_notauth_with_badsig_is_correct_behaviour(self):
        for label, cli, srv in PAIRS:
            _, _, c2 = self._exchange(Config(), update_wire(keyname="k."), cli, srv,
                                      rcode=9, tsig=tsig_bytes(err=16))
            self.assertEqual(c2, [], f"{label}: got {c2}")

    def test_clean_signed_update_is_silent(self):
        for label, cli, srv in PAIRS:
            _, _, c2 = self._exchange(Config(), update_wire(keyname="k."), cli, srv,
                                      rcode=0, tsig=tsig_bytes(err=0))
            self.assertEqual(c2, [], f"{label}: got {c2}")

    def test_unexpected_source_needs_config(self):
        out_cidr = {"IPv4": IP(src="203.0.113.9", dst="10.0.0.1"),
                    "IPv6": IPv6(src="2001:db8:bad::9", dst="fd00::1")}
        allow = ("10.0.0.0/24", "fd00::/64")
        for label, cli, _srv in PAIRS:
            eng = Engine(Config(ddns_allowed_updater_prefixes=allow))
            got = codes(eng.handle_frame(ddns_frame(update_wire(), out_cidr[label]), now=1.0))
            self.assertIn("DNSD-082", got, f"{label}: got {got}")
            eng = Engine(Config(ddns_allowed_updater_prefixes=allow))
            self.assertEqual(
                codes(eng.handle_frame(ddns_frame(update_wire(), cli), now=1.0)), [],
                f"{label}: an in-allowlist source must be silent")
            eng = Engine(Config())
            self.assertEqual(
                codes(eng.handle_frame(ddns_frame(update_wire(), out_cidr[label]), now=1.0)), [],
                f"{label}: unconfigured means silent, never 'everything is unexpected'")


class TestRdnsTier(unittest.TestCase):

    @staticmethod
    def _q(name, qtype="PTR"):
        import dns.message
        return dns.message.make_query(name, qtype).to_wire()

    INT = ("10.0.0.0/8", "fd00::/8")
    ULA = ("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0."
           "0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa.")

    def test_private_leak_both_families_and_both_transports(self):
        cases = (
            ("v4 private over v4", "1.0.0.10.in-addr.arpa.",
             IP(src="10.0.0.5", dst="8.8.8.8")),
            ("v6 ULA over v4", self.ULA, IP(src="10.0.0.5", dst="9.9.9.9")),
            ("v4 private over v6", "1.0.0.10.in-addr.arpa.",
             IPv6(src="fd00::5", dst="2001:4860:4860::8888")),
            ("v6 ULA over v6", self.ULA, IPv6(src="fd00::5", dst="2001:4860:4860::8888")),
        )
        for label, name, l3 in cases:
            eng = Engine(Config(rdns_internal_prefixes=self.INT))
            got = codes(eng.handle_frame(ddns_frame(self._q(name), l3), now=1.0))
            self.assertIn("DNSD-090", got, f"{label}: got {got}")

    def test_internal_destination_is_ordinary_business(self):
        for l3 in (IP(src="10.0.0.5", dst="10.0.0.1"), IPv6(src="fd00::5", dst="fd00::1")):
            eng = Engine(Config(rdns_internal_prefixes=self.INT))
            self.assertEqual(
                codes(eng.handle_frame(ddns_frame(self._q("1.0.0.10.in-addr.arpa."), l3),
                                       now=1.0)), [])

    def test_doc_range_is_not_private(self):
        """RFC 5737 203.0.113/24 is documentation space, not private
        addressing -- Python's ipaddress disagrees, and that
        disagreement is what let a mutation survive the mDNS suite."""
        eng = Engine(Config(rdns_internal_prefixes=self.INT))
        self.assertEqual(
            codes(eng.handle_frame(ddns_frame(self._q("5.113.0.203.in-addr.arpa."),
                                              IP(src="10.0.0.5", dst="8.8.8.8")), now=1.0)), [])

    def test_unconfigured_is_silent(self):
        eng = Engine(Config())
        self.assertEqual(
            codes(eng.handle_frame(ddns_frame(self._q("1.0.0.10.in-addr.arpa."),
                                              IP(src="10.0.0.5", dst="8.8.8.8")), now=1.0)), [])

    def test_ip6_walk_both_transports(self):
        prefix = "20010db800000000"
        names = [".".join(reversed(prefix + f"{i:016x}")) + ".ip6.arpa." for i in range(80)]
        got = {}
        for label, l3 in (("IPv4", IP(src="198.51.100.9", dst="10.0.0.1")),
                          ("IPv6", IPv6(src="2001:db8::9", dst="fd00::1"))):
            eng = Engine(Config())
            out = []
            for i, nm in enumerate(names):
                out += eng.handle_frame(ddns_frame(self._q(nm), l3, sport=40000 + i * 7),
                                        now=1.0 + i * 0.1)
            got[label] = codes(out)
            self.assertIn("DNSD-091", got[label], f"{label}: got {got[label]}")
            self.assertEqual(got[label].count("DNSD-091"), 1,
                             f"{label}: once per window, not once per query")
        self.assertEqual(got["IPv4"], got["IPv6"], f"dual-stack divergence: {got}")

    def test_scattered_lookups_do_not_fire(self):
        """The mail-server shape: many distinct ip6.arpa names with no
        shared delegation. Count and distinctness alone would fire."""
        import random
        random.seed(3)
        eng = Engine(Config())
        out = []
        for i in range(200):
            full = "".join(random.choice("0123456789abcdef") for _ in range(32))
            nm = ".".join(reversed(full)) + ".ip6.arpa."
            out += eng.handle_frame(
                ddns_frame(self._q(nm), IP(src="198.51.100.9", dst="10.0.0.1"),
                           sport=40000 + i * 7), now=1.0 + i * 0.1)
        self.assertEqual(codes(out), [], f"got {codes(out)}")


class TestSigredAndTsig(unittest.TestCase):

    @staticmethod
    def _sigred(rtype=parse.T_RRSIG, sig_len=65260):
        import struct
        hdr = struct.pack("!HHHHHH", 0x5151, 0x8180, 1, 1, 0, 0)
        question = b"\x00" + struct.pack("!HH", 1, 1)
        owner = b"\xc0\x0c"
        sig_fixed = struct.pack("!HBBIIIH", 1, 8, 2, 3600, 1800000000, 1700000000, 0x003f)
        rdata = sig_fixed + struct.pack("!H", 0xC000 | 46) + b"\x3f" * sig_len
        rr = owner + struct.pack("!HHIH", rtype, 1, 3600, len(rdata)) + rdata
        return hdr + question + rr

    def _tcp(self, payload, l3, sport=53, dport=33333):
        from scapy.all import TCP
        return raw(Ether() / l3 / TCP(sport=sport, dport=dport)
                   / (len(payload).to_bytes(2, "big") + payload))

    def test_sigred_both_types_both_stacks(self):
        for rtype, label in ((parse.T_RRSIG, "RRSIG"), (parse.T_SIG, "SIG")):
            got = {}
            for fam, l3 in (("IPv4", IP(src="10.0.0.1", dst="10.0.0.5")),
                            ("IPv6", IPv6(src="fd00::1", dst="fd00::5"))):
                eng = Engine(Config())
                out = eng.handle_frame(self._tcp(self._sigred(rtype), l3), now=1.0)
                got[fam] = codes(out)
                self.assertIn("DNSD-044", got[fam], f"{label}/{fam}: got {got[fam]}")
            self.assertEqual(got["IPv4"], got["IPv6"],
                             f"{label}: dual-stack divergence {got}")

    def test_near_miss_is_silent(self):
        eng = Engine(Config())
        out = eng.handle_frame(self._tcp(self._sigred(sig_len=60000),
                                         IP(src="10.0.0.1", dst="10.0.0.5")), now=1.0)
        self.assertNotIn("DNSD-044", codes(out))

    def test_tsig_structure_both_stacks(self):
        import struct
        hdr = struct.pack("!HHHHHH", 0x4242, 0x8000, 1, 0, 0, 1)
        body = b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
        bad = hdr + body + tsig_bytes(mac_size=200, mac=b"\x11" * 32)
        good = hdr + body + tsig_bytes()
        got = {}
        for fam, l3 in (("IPv4", IP(src="10.0.0.1", dst="10.0.0.5")),
                        ("IPv6", IPv6(src="fd00::1", dst="fd00::5"))):
            eng = Engine(Config())
            got[fam] = codes(eng.handle_frame(ddns_frame(bad, l3, 53, 33333), now=1.0))
            self.assertIn("DNSD-054", got[fam], f"{fam}: got {got[fam]}")
            eng = Engine(Config())
            self.assertEqual(codes(eng.handle_frame(ddns_frame(good, l3, 53, 33333), now=1.0)),
                             [], f"{fam}: a well-formed TSIG must be silent")
        self.assertEqual(got["IPv4"], got["IPv6"], f"dual-stack divergence: {got}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
