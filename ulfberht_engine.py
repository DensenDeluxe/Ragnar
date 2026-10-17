#!/usr/bin/env python3
"""
Ulfberht Engagement engine -- coordinated security workflows.

This is the professional/educational differentiator of the Ragnar OS Ulfberht
edition: not a drawer of tools, but **playbooks** that chain the phases of a real
engagement -- discovery -> diagnostics -> assessment -> reporting -- under one
scope, into one methodology-aligned report (NIST SP 800-115 / PTES).

It is EXCLUSIVE to the official Ulfberht image: every entry point checks the
build-time edition marker via ragnar_edition. On the standard image, or on a
stock Kali box that merely ran install_ragnar.sh, the engine refuses to run and
the UI never shows it.

Safety model:
  * Scope is entered once and every step is confined to it.
  * Discovery + diagnostics are passive/safe and always allowed.
  * The assessment phase is active and runs ONLY when the caller passes
    enable_active=True (wired to Ragnar's existing enable_attacks opt-in).
  * Everything runs in a background thread with per-tool timeouts.

In-memory run registry (ephemeral; a run does not survive a service restart),
which is the right scope for v1.
"""
from __future__ import annotations

import html
import re
import shutil
import subprocess
import threading
import time
import uuid
import xml.etree.ElementTree as ET

try:
    import ragnar_edition
except Exception:  # pragma: no cover - defensive
    ragnar_edition = None

# ── Methodology ─────────────────────────────────────────────────────────────
# Phases map to NIST SP 800-115 ("Technical Guide to Information Security
# Testing and Assessment"). Kept explicit so reports and teaching line up.
PHASES = ("discovery", "diagnostics", "assessment", "reporting")
PHASE_META = {
    "discovery":   {"name": "Discovery",   "nist": "NIST SP 800-115 §4 (Target Identification)", "active": False},
    "diagnostics": {"name": "Diagnostics", "nist": "NIST SP 800-115 §4 (Vulnerability / posture analysis)", "active": False},
    "assessment":  {"name": "Assessment",  "nist": "NIST SP 800-115 §5 (Target Vulnerability Validation)", "active": True},
    "reporting":   {"name": "Reporting",   "nist": "NIST SP 800-115 §8 (Post-Testing / Reporting)", "active": False},
}

PLAYBOOKS = {
    "scoped-network-assessment": {
        "id": "scoped-network-assessment",
        "name": "Scoped Network Assessment",
        "description": ("Sweep a scope for live hosts and services, derive a "
                        "security posture from what is exposed, optionally "
                        "validate findings, and produce one engagement report."),
        "phases": list(PHASES),
    },
}

# Cleartext / high-risk services we flag in the diagnostics posture pass.
# (service-name or port) -> (severity, title, reference)
_RISK_SERVICES = {
    "telnet":   ("high",   "Cleartext remote administration (Telnet)", "CWE-319 / MITRE T1021"),
    "ftp":      ("medium", "Cleartext file transfer (FTP)", "CWE-319"),
    "http":     ("low",    "Unencrypted web service (HTTP)", "CWE-319"),
    "rlogin":   ("high",   "Legacy r-service (rlogin)", "CWE-319"),
    "rsh":      ("high",   "Legacy r-service (rsh)", "CWE-319"),
    "vnc":      ("medium", "Remote desktop exposed (VNC)", "MITRE T1021.005"),
    "microsoft-ds": ("medium", "SMB exposed to the scope", "MITRE T1021.002"),
    "netbios-ssn":  ("medium", "NetBIOS/SMB exposed", "MITRE T1021.002"),
    "snmp":     ("medium", "SNMP exposed (often default community)", "CWE-1188"),
    "ms-sql-s": ("medium", "Database service exposed (MSSQL)", "MITRE T1210"),
    "mysql":    ("low",    "Database service exposed (MySQL)", "MITRE T1210"),
    "rdp":      ("medium", "Remote Desktop exposed (RDP)", "MITRE T1021.001"),
}
_RISK_PORTS = {23: "telnet", 21: "ftp", 513: "rlogin", 514: "rsh",
               5900: "vnc", 445: "microsoft-ds", 139: "netbios-ssn",
               161: "snmp", 1433: "ms-sql-s", 3306: "mysql", 3389: "rdp"}

_SCOPE_RE = re.compile(r"^[0-9a-zA-Z\.\:/\-\s]{1,200}$")

_runs = {}
_lock = threading.Lock()


def is_enabled():
    """True only on the genuine Ulfberht image."""
    try:
        return bool(ragnar_edition and ragnar_edition.detect().get("is_ulfberht"))
    except Exception:
        return False


def list_playbooks():
    return list(PLAYBOOKS.values())


def _valid_scope(scope):
    return bool(scope) and bool(_SCOPE_RE.match(scope.strip()))


def start_run(playbook_id, scope, enable_active=False):
    """Kick off an engagement run in a background thread. Returns (run_id, err)."""
    if not is_enabled():
        return None, "Ulfberht engine is available only on the Ragnar OS Ulfberht image."
    if playbook_id not in PLAYBOOKS:
        return None, "Unknown playbook."
    scope = (scope or "").strip()
    if not _valid_scope(scope):
        return None, "Invalid or empty scope."
    run_id = uuid.uuid4().hex[:12]
    run = {
        "id": run_id,
        "playbook": playbook_id,
        "playbook_name": PLAYBOOKS[playbook_id]["name"],
        "scope": scope,
        "enable_active": bool(enable_active),
        "status": "running",
        "phase": None,
        "phases_done": [],
        "started": time.time(),
        "finished": None,
        "hosts": [],
        "findings": [],
        "log": [],
        "report_md": "",
    }
    with _lock:
        _runs[run_id] = run
    t = threading.Thread(target=_execute, args=(run,), daemon=True)
    t.start()
    return run_id, None


def get_run(run_id):
    with _lock:
        run = _runs.get(run_id)
        return dict(run) if run else None


def list_runs():
    with _lock:
        return [
            {k: r[k] for k in ("id", "playbook_name", "scope", "status",
                               "phase", "started", "finished")}
            for r in sorted(_runs.values(), key=lambda x: x["started"], reverse=True)
        ]


def get_report(run_id):
    run = get_run(run_id)
    return run["report_md"] if run else None


# ── Execution ───────────────────────────────────────────────────────────────
def _log(run, msg):
    with _lock:
        _runs[run["id"]]["log"].append(f"{time.strftime('%H:%M:%S')}  {msg}")


def _set(run, **kw):
    with _lock:
        _runs[run["id"]].update(kw)


def _finding(run, severity, title, host, detail, ref=""):
    with _lock:
        _runs[run["id"]]["findings"].append({
            "severity": severity, "title": title, "host": host,
            "detail": detail, "ref": ref,
        })


def _execute(run):
    rid = run["id"]
    try:
        hosts = _phase_discovery(run)
        _phase_diagnostics(run, hosts)
        _phase_assessment(run, hosts)
        _phase_reporting(run)
        _set(run, status="completed", phase=None, finished=time.time())
    except Exception as e:  # never leave a run wedged in "running"
        _log(run, f"ERROR: {e}")
        _set(run, status="failed", finished=time.time())


def _mark_phase(run, phase):
    _set(run, phase=phase)
    _log(run, f"── {PHASE_META[phase]['name']} ({PHASE_META[phase]['nist']})")


def _phase_discovery(run):
    _mark_phase(run, "discovery")
    scope = run["scope"]
    hosts = []
    nmap = shutil.which("nmap")
    if not nmap:
        _log(run, "nmap not found; discovery skipped.")
        return hosts
    # Host + service discovery, XML out for robust parsing. Top 100 ports keeps
    # it quick; -T4 timing; version detection.
    _log(run, f"nmap -sV --top-ports 100 over {scope}")
    try:
        proc = subprocess.run(
            [nmap, "-sV", "--top-ports", "100", "-T4", "-oX", "-", scope],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=1800,
        )
        hosts = _parse_nmap_xml(proc.stdout.decode("utf-8", "replace"))
    except subprocess.TimeoutExpired:
        _log(run, "nmap timed out (1800s).")
    except Exception as e:
        _log(run, f"nmap failed: {e}")
    _set(run, hosts=hosts, phases_done=run["phases_done"] + ["discovery"])
    _log(run, f"{len(hosts)} live host(s), {sum(len(h['ports']) for h in hosts)} open port(s).")
    return hosts


def _parse_nmap_xml(xml_text):
    hosts = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return hosts
    for h in root.findall("host"):
        state = h.find("status")
        if state is not None and state.get("state") != "up":
            continue
        addr = ""
        for a in h.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                addr = a.get("addr"); break
        hn = h.find("hostnames/hostname")
        name = hn.get("name") if hn is not None else ""
        ports = []
        for p in h.findall("ports/port"):
            st = p.find("state")
            if st is None or st.get("state") != "open":
                continue
            svc = p.find("service")
            ports.append({
                "port": int(p.get("portid")),
                "proto": p.get("protocol"),
                "service": (svc.get("name") if svc is not None else "") or "",
                "product": (svc.get("product") if svc is not None else "") or "",
                "version": (svc.get("version") if svc is not None else "") or "",
            })
        if addr:
            hosts.append({"ip": addr, "name": name, "ports": ports})
    return hosts


def _phase_diagnostics(run, hosts):
    _mark_phase(run, "diagnostics")
    # Passive posture analysis from what discovery exposed. This is the safe
    # middle phase that also *aims* the assessment phase.
    for h in hosts:
        for p in h["ports"]:
            key = p["service"] or _RISK_PORTS.get(p["port"], "")
            risk = _RISK_SERVICES.get(key)
            if risk:
                sev, title, ref = risk
                banner = " ".join(x for x in (p["product"], p["version"]) if x)
                detail = f"{p['port']}/{p['proto']} {key}" + (f" — {banner}" if banner else "")
                _finding(run, sev, title, h["ip"], detail, ref)
    _set(run, phases_done=run["phases_done"] + ["diagnostics"])
    n = len(run_findings(run))
    _log(run, f"Posture analysis produced {n} finding(s).")


def run_findings(run):
    with _lock:
        return list(_runs[run["id"]]["findings"])


def _phase_assessment(run, hosts):
    _mark_phase(run, "assessment")
    if not run["enable_active"]:
        _log(run, "Assessment skipped — active testing not enabled (enable_attacks off).")
        _set(run, phases_done=run["phases_done"] + ["assessment"])
        return
    # Best-effort active validation against web services, using nuclei when it is
    # present. Confined to hosts/ports already found in scope.
    nuclei = shutil.which("nuclei")
    web = [(h["ip"], p["port"]) for h in hosts for p in h["ports"]
           if p["service"] in ("http", "https") or p["port"] in (80, 443, 8080, 8443)]
    if not web:
        _log(run, "No web services found to validate.")
    elif not nuclei:
        _log(run, "nuclei not installed; assessment of web services skipped.")
    else:
        for ip, port in web[:25]:
            scheme = "https" if port in (443, 8443) else "http"
            target = f"{scheme}://{ip}:{port}"
            _log(run, f"nuclei -silent {target}")
            try:
                proc = subprocess.run(
                    [nuclei, "-u", target, "-silent", "-nc"],
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=600,
                )
                for line in proc.stdout.decode("utf-8", "replace").splitlines():
                    line = line.strip()
                    if line:
                        _finding(run, "medium", "Nuclei match", ip, line, "nuclei")
            except Exception as e:
                _log(run, f"nuclei failed on {target}: {e}")
    _set(run, phases_done=run["phases_done"] + ["assessment"])


def _sev_rank(s):
    return {"high": 0, "medium": 1, "low": 2, "info": 3}.get(s, 4)


def _phase_reporting(run):
    _mark_phase(run, "reporting")
    # mark the phase done before rendering so the report reflects itself
    _set(run, phases_done=get_run(run["id"])["phases_done"] + ["reporting"])
    run = get_run(run["id"])  # snapshot with all findings + phases
    findings = sorted(run["findings"], key=lambda f: _sev_rank(f["severity"]))
    lines = []
    A = lines.append
    A(f"# Engagement Report — {run['playbook_name']}")
    A("")
    A(f"- **Scope:** `{run['scope']}`")
    A(f"- **Started:** {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(run['started']))}")
    A(f"- **Methodology:** NIST SP 800-115 (Discovery → Diagnostics → Assessment → Reporting)")
    A(f"- **Active validation:** {'enabled' if run['enable_active'] else 'not run (passive engagement)'}")
    A("")
    A("## Summary")
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    A(f"- Hosts live: **{len(run['hosts'])}**")
    A(f"- Findings: **{len(findings)}** "
      f"(high {counts.get('high',0)}, medium {counts.get('medium',0)}, low {counts.get('low',0)})")
    A("")
    A("## Hosts & services")
    if run["hosts"]:
        A("| Host | Port | Service | Product/Version |")
        A("|------|------|---------|-----------------|")
        for h in run["hosts"]:
            for p in h["ports"]:
                pv = " ".join(x for x in (p["product"], p["version"]) if x)
                A(f"| {h['ip']}{(' ('+h['name']+')') if h['name'] else ''} | "
                  f"{p['port']}/{p['proto']} | {p['service']} | {pv} |")
    else:
        A("_No live hosts found in scope._")
    A("")
    A("## Findings")
    if findings:
        for f in findings:
            A(f"### [{f['severity'].upper()}] {f['title']} — {f['host']}")
            A(f"- {f['detail']}")
            if f["ref"]:
                A(f"- Reference: {f['ref']}")
            A("")
    else:
        A("_No posture findings. Scope looks clean for the checks run._")
    A("")
    A("## Phases executed")
    for ph in PHASES:
        done = "✓" if ph in run["phases_done"] else "—"
        A(f"- {done} **{PHASE_META[ph]['name']}** — {PHASE_META[ph]['nist']}")
    A("")
    A("---")
    A("_Ragnar OS Ulfberht — for authorized security testing only._")
    _set(run, report_md="\n".join(lines))


if __name__ == "__main__":
    import json
    import os
    os.environ.setdefault("RAGNAR_EDITION", "ulfberht")  # dev test
    if ragnar_edition:
        ragnar_edition._cache = None
    rid, err = start_run("scoped-network-assessment",
                         os.environ.get("ULF_SCOPE", "127.0.0.1"),
                         enable_active=False)
    if err:
        print("error:", err); raise SystemExit(1)
    while True:
        r = get_run(rid)
        if r["status"] != "running":
            break
        time.sleep(2)
    print(json.dumps({"status": r["status"], "findings": r["findings"],
                      "hosts": r["hosts"]}, indent=2))
    print("\n----- REPORT -----\n")
    print(get_report(rid))
