#!/usr/bin/env python3
"""
Ragnar edition / base-OS detection -- the "hidden switch".

Ragnar runs on several Debian-family bases. The standard Ragnar OS image is
built on Raspberry Pi OS Lite. The "Ulfberht" edition is built on top of a
security-focused Debian derivative whose Raspberry Pi kernel ships Nexmon
(onboard Wi-Fi monitor mode + frame injection) and a large offensive toolset.

When Ragnar detects that base it unlocks extra, additive capabilities and
surfaces the tools that are already installed so they are one tap away in the
web UI. On a plain Raspberry Pi OS / Debian box this module reports
edition="standard" and the UI shows nothing new -- the switch stays hidden.

Pure standard library, no side effects, never raises, safe to import anywhere.
"""
from __future__ import annotations

import glob
import json
import os
import shutil
import subprocess

# os-release IDs we treat as the security-distro base that powers the
# "Ulfberht" edition. A set so a later point release (still ID=kali) keeps
# working without a code change.
_SECURITY_BASE_IDS = {"kali"}

EDITION_ULFBERHT = "ulfberht"
EDITION_STANDARD = "standard"

EDITION_NAMES = {
    EDITION_ULFBERHT: "Ragnar OS Ulfberht",
    EDITION_STANDARD: "Ragnar OS",
}

# Offensive / analysis tools worth surfacing when present: (binary, label,
# category). Detection is by presence on PATH only -- we never run them here.
# Metasploit is detected via msfconsole. Curated, not exhaustive.
_TOOL_CATALOG = (
    ("nmap", "Nmap", "recon"),
    ("masscan", "Masscan", "recon"),
    ("aircrack-ng", "Aircrack-ng", "wifi"),
    ("airodump-ng", "Airodump-ng", "wifi"),
    ("wifite", "Wifite", "wifi"),
    ("kismet", "Kismet", "wifi"),
    ("reaver", "Reaver", "wifi"),
    ("bully", "Bully", "wifi"),
    ("hcxdumptool", "hcxdumptool", "wifi"),
    ("hashcat", "Hashcat", "cracking"),
    ("john", "John the Ripper", "cracking"),
    ("hydra", "Hydra", "cracking"),
    ("bettercap", "Bettercap", "mitm"),
    ("ettercap", "Ettercap", "mitm"),
    ("responder", "Responder", "mitm"),
    ("mitm6", "mitm6", "mitm"),
    ("tshark", "TShark", "capture"),
    ("tcpdump", "tcpdump", "capture"),
    ("sqlmap", "sqlmap", "web"),
    ("nikto", "Nikto", "web"),
    ("nuclei", "Nuclei", "web"),
    ("ffuf", "ffuf", "web"),
    ("gobuster", "Gobuster", "web"),
    ("wpscan", "WPScan", "web"),
    ("msfconsole", "Metasploit", "exploit"),
    ("setoolkit", "SET", "exploit"),
    ("enum4linux", "enum4linux", "smb"),
    ("crackmapexec", "CrackMapExec", "smb"),
    ("netexec", "NetExec", "smb"),
)

# Nexmon packages (onboard-Wi-Fi monitor/injection support on the security base).
_NEXMON_PACKAGES = ("brcmfmac-nexmon-dkms", "firmware-nexmon")

_cache = None


def _read_os_release():
    data = {}
    try:
        with open("/etc/os-release", "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                data[key] = val.strip().strip('"').strip("'")
    except OSError:
        pass
    return data


def _dpkg_installed(pkg):
    dpkg = shutil.which("dpkg-query") or shutil.which("dpkg")
    if not dpkg:
        return False
    try:
        res = subprocess.run(
            [dpkg, "-s", pkg],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5,
        )
        return res.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _detect_tools():
    found = []
    for binary, label, category in _TOOL_CATALOG:
        path = shutil.which(binary)
        if path:
            found.append({"bin": binary, "name": label,
                          "category": category, "path": path})
    return found


def _detect_nexmon():
    pkgs = [p for p in _NEXMON_PACKAGES if _dpkg_installed(p)]
    # Nexmon-patched brcmfmac firmware lands in /lib/firmware/brcm; the exact
    # file depends on the Pi's wireless chip, so glob rather than hardcode.
    fw = bool(glob.glob("/lib/firmware/brcm/*nexmon*")
              or glob.glob("/usr/lib/firmware/brcm/*nexmon*"))
    return {
        "available": bool(pkgs) or fw,
        "packages": pkgs,
        "firmware_present": fw,
    }


def detect(refresh=False):
    """Return a dict describing the running base/edition. Cached; never raises."""
    global _cache
    if _cache is not None and not refresh:
        return _cache

    osr = _read_os_release()
    base_id = (osr.get("ID") or "unknown").lower()
    id_like = (osr.get("ID_LIKE") or "").lower()
    pretty = osr.get("PRETTY_NAME") or base_id

    is_security = base_id in _SECURITY_BASE_IDS
    edition = EDITION_ULFBERHT if is_security else EDITION_STANDARD

    result = {
        "edition": edition,
        "edition_name": EDITION_NAMES[edition],
        "is_security_distro": is_security,
        "base_id": base_id,
        "base_id_like": id_like,
        "base_pretty": pretty,
        "base_version": osr.get("VERSION") or osr.get("VERSION_ID") or "",
        "nexmon": {"available": False, "packages": [], "firmware_present": False},
        "tools": [],
        "tool_count": 0,
    }
    if is_security:
        try:
            result["nexmon"] = _detect_nexmon()
        except Exception:
            pass
        try:
            result["tools"] = _detect_tools()
            result["tool_count"] = len(result["tools"])
        except Exception:
            pass

    _cache = result
    return result


if __name__ == "__main__":
    print(json.dumps(detect(), indent=2))
