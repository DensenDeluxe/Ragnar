"""
DNS Doctor mDNS tier (RFC 6762 multicast DNS / RFC 6763 DNS-SD).

TWO LEGS, kept separate because they answer different questions:

  CENSUS (DNSD-070..073) -- what Matter and Thread infrastructure
  exists on this LAN. Informational, never an alarm. This exists
  because Ragnar can see Zigbee, Z-Wave, LoRaWAN, Wi-Fi HaLow,
  MeshCore, Meshtastic, BLE and Classic, but had no way to know
  Matter existed at all. Matter's operational traffic on UDP 5540 is
  encrypted per session, so mDNS discovery is the only cleartext
  plane that names it -- and it works over Wi-Fi and Ethernet without
  any 802.15.4 radio, including devices sitting behind a Thread
  border router.

  SCOPE (DNSD-074..076) -- the RFC 6762 transport rules, which is the
  CERT VU#550620 family: responders that answer off-link become
  amplification reflectors and leak their whole service inventory.

WHAT THIS TIER DELIBERATELY DOES NOT DO: judge whether an mDNS answer
is legitimate. smbwatch already owns LLMNR/NBT-NS/mDNS name poisoning
(Responder/Inveigh). Both modules see the same packets; only smbwatch
reports spoofing. This one judges scope and census only, so there is
no double report and no disagreement between two detectors about the
same frame.

WHY THE AVAHI CVEs ARE ABSENT: the remote crafted-packet bugs
(CVE-2008-5081 source-port-0 assertion, CVE-2010-2244 checksum crash,
CVE-2011-1002 empty-packet loop) are all 2006-2011 and score ~5.0 on
CVSS v2, under the 6.5 floor. CVE-2008-5081 has a Metasploit module
and high EPSS but is not in CISA KEV, so no exception applies. The
2023 and 2025 Avahi CVEs are local D-Bus resource exhaustion -- not
on the wire at all, so not passively detectable by construction.
"""
import ipaddress

import netscope

import parse
from findings import finding

LAYER = "mdns"

# DNS-SD service types the census reports, mapped to their code.
CENSUS_SERVICES = {
    "_matter._tcp":  ("DNSD-070", "Matter operational node"),
    "_matterc._udp": ("DNSD-071", "Matter commissionable device (setup mode)"),
    "_matterd._udp": ("DNSD-072", "Matter commissioner (controller or hub)"),
    "_meshcop._udp": ("DNSD-073", "Thread border router"),
}


def _addr_text(raw):
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return raw.hex()


# Both predicates now live in netscope.py, shared with the DDNS and
# rDNS tiers. Re-exported under their original names so this tier's
# existing call sites and tests keep working unchanged -- one
# implementation, three callers.
_in_any_prefix = netscope.in_any_prefix
parse_local_prefixes = netscope.parse_prefixes


# ======================================================================
# CENSUS
# ======================================================================

def census_records(msg):
    """
    Every (service_type, instance) pair this message advertises.

    Reads the ANSWER and ADDITIONAL sections only. Questions are
    excluded on purpose: a QUERY for _matter._tcp proves someone is
    LOOKING for Matter, not that Matter is present -- and any host
    running a Matter controller app browses for it on every network it
    joins, including ones with no Matter at all. Counting queries
    would put a Matter census line on every LAN a phone touches.
    """
    out = []
    for rr in msg.answers + msg.additional:
        if rr.rtype not in (parse.T_PTR, parse.T_SRV, parse.T_TXT):
            continue
        # ONE census entry per record, never one per matching name.
        # For a PTR the service type is the OWNER and the instance is
        # in the rdata target; for SRV/TXT it is the other way round.
        # Both names on a PTR therefore carry the same service type,
        # and looping over them emitted the service twice -- once
        # with an instance and once without, so the same device
        # appeared in the census as two entries, one anonymous.
        # Prefer whichever candidate actually yields an instance.
        svc = inst = None
        for candidate in (rr.parsed.get("target"), rr.name):
            if candidate is None:
                continue
            cand_svc = parse.service_type_of(candidate)
            if cand_svc not in CENSUS_SERVICES:
                continue
            cand_inst = parse.instance_of(candidate)
            if svc is None:
                svc, inst = cand_svc, cand_inst
            if cand_inst is not None:
                svc, inst = cand_svc, cand_inst
                break
        if svc is not None:
            out.append((svc, inst))
    return out


def detect_census(msg, cfg, census_table, src_raw, now):
    """
    Emit one finding per (service, instance) first sighting.

    mDNS hosts re-announce on a schedule and on every topology change,
    so a per-packet census would emit continuously. The table is
    bounded and the suppression is the point, not an optimisation.
    """
    out = []
    for svc, inst in census_records(msg):
        code, label = CENSUS_SERVICES[svc]
        key = (svc, inst or "")
        if not census_table.first_sighting(key, now):
            continue
        who = f"'{inst}'" if inst else "an unnamed instance"
        out.append(finding(
            code, "local.",
            f"{label} seen on this LAN: {who} advertising {svc}",
            {"service_type": svc, "instance": inst,
             "source": _addr_text(src_raw),
             "note": "census only -- presence, not a vulnerability"},
        ))
    return out


# ======================================================================
# SCOPE (RFC 6762 transport rules / CERT VU#550620)
# ======================================================================

def detect_ttl_violation(msg, cfg, ttl, src_raw, dst_raw):
    """
    RFC 6762 s11: mDNS MUST be sent with IP TTL / IPv6 hop limit 255,
    and a receiver SHOULD check it. Anything else crossed a router or
    was not generated as link-local traffic.

    This is the CONFIG-FREE leg. It needs no knowledge of the site's
    addressing, which matters because the two stronger scope checks
    below cannot run without it.
    """
    if ttl is None or ttl == parse.MDNS_REQUIRED_TTL:
        return []
    return [finding(
        "DNSD-074", "local.",
        f"mDNS packet from {_addr_text(src_raw)} arrived with TTL/hop-limit {ttl}, "
        f"not the 255 RFC 6762 s11 requires -- it crossed a router or was not "
        f"generated as link-local traffic",
        {"ttl": ttl, "required": parse.MDNS_REQUIRED_TTL,
         "source": _addr_text(src_raw), "destination": _addr_text(dst_raw),
         "is_response": bool(msg.qr)},
    )]


def detect_off_link_source(msg, cfg, src_raw, dst_raw, local_nets):
    """
    An mDNS packet whose SOURCE is outside the site's own prefixes.

    Requires operator-supplied prefixes and returns nothing without
    them. That is deliberate rather than lazy: the obvious config-free
    shortcut is "a public/global source address means off-link", and
    that is WRONG on exactly the networks this has to run on. A
    carrier-neutral colo or an ISP backbone uses public addressing on
    the LAN, so the shortcut would fire on every ordinary mDNS packet
    in the building. An undecidable check must stay silent.
    """
    inside = _in_any_prefix(src_raw, local_nets)
    if inside is not False:
        return []
    return [finding(
        "DNSD-075", "local.",
        f"mDNS packet sourced from {_addr_text(src_raw)}, outside the configured local "
        f"prefixes -- mDNS is link-local by definition, so this service is reachable "
        f"beyond its intended scope",
        {"source": _addr_text(src_raw), "destination": _addr_text(dst_raw),
         "local_prefixes": [str(n) for n in local_nets],
         "is_response": bool(msg.qr)},
    )]


def detect_off_link_unicast_response(msg, cfg, src_raw, dst_raw, local_nets):
    """
    CERT VU#550620, and the CVE cluster that instantiates it
    (CVE-2015-2809 Synology/Avahi, CVE-2017-6520 Bose,
    CVE-2015-1892 IBM ISAM).

    A responder that answers a unicast query from off-link is an open
    reflector: amplification fuel, and a full disclosure of every
    service it advertises.

    THE FALSE-POSITIVE CONTROL: a unicast mDNS response is NOT by
    itself a violation. RFC 6762 s5.4 defines the QU bit precisely so
    a querier can request one, and on-link QU exchanges are ordinary.
    What makes it a violation is the DESTINATION being off-link, so
    that -- not unicast-ness -- is the test.
    """
    if not msg.qr:
        return []
    if parse.is_mdns_group(dst_raw):
        return []                       # ordinary multicast response
    inside = _in_any_prefix(dst_raw, local_nets)
    if inside is not False:
        return []                       # on-link unicast (QU) or undecidable
    services = sorted({s for s, _ in census_records(msg)})
    return [finding(
        "DNSD-076", "local.",
        f"mDNS responder {_addr_text(src_raw)} answered to off-link unicast destination "
        f"{_addr_text(dst_raw)} -- an open reflector (CERT VU#550620): amplification "
        f"fuel and an inventory leak",
        {"source": _addr_text(src_raw), "destination": _addr_text(dst_raw),
         "answer_records": len(msg.answers),
         "services_disclosed": services,
         "local_prefixes": [str(n) for n in local_nets]},
    )]


def handle_mdns(msg, cfg, census_table, src_raw, dst_raw, ttl, local_nets, now):
    """Whole tier for one mDNS packet."""
    out = []
    out += detect_ttl_violation(msg, cfg, ttl, src_raw, dst_raw)
    out += detect_off_link_source(msg, cfg, src_raw, dst_raw, local_nets)
    out += detect_off_link_unicast_response(msg, cfg, src_raw, dst_raw, local_nets)
    out += detect_census(msg, cfg, census_table, src_raw, now)
    return out
