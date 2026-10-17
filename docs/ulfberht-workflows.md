# Ulfberht Engagements — coordinated security workflows

The **Engagements** engine is what makes [Ragnar OS Ulfberht](ragnar-os-ulfberht.md)
a professional tool rather than a Kali spin with extra packages. Instead of a
drawer of tools, it runs **playbooks** that chain the phases of a real
engagement — **discovery → diagnostics → assessment → reporting** — over one
scope, into one methodology-aligned report.

It is **exclusive to the official Ulfberht image**: the engine and its UI only
appear when the build-time edition marker (`/etc/ragnar-edition`) is present.
On the standard image, or on a stock Kali box running Ragnar, the Engagements
tab and the engine are hidden and the API refuses to run. For authorized
security testing only.

## Methodology

Phases map to **NIST SP 800-115** (and align with PTES), so an engagement
follows a defensible standard and the output is something a professional hands
to a client — and something a student can be graded on.

| Phase | NIST SP 800-115 | Safety | What it does |
|-------|-----------------|--------|--------------|
| **Discovery** | §4 Target identification | passive | `nmap` host + service sweep of the scope (XML-parsed). |
| **Diagnostics** | §4 Vulnerability/posture analysis | passive | Derives a security posture from what's exposed (cleartext protocols, legacy r-services, exposed SMB/RDP/DB/SNMP…), each mapped to a CWE / MITRE ATT&CK reference. This safe phase also *aims* the active phase. |
| **Assessment** | §5 Target vulnerability validation | **active (gated)** | Validates findings against discovered services (e.g. `nuclei` on web services). Runs **only** when the operator opts in **and** Ragnar's `enable_attacks` flag is on. |
| **Reporting** | §8 Post-testing / reporting | passive | One report: scope, methodology, host/service table, findings by severity with references, phases executed. Viewable in-tab and downloadable as Markdown. |

## Safety model

- **Scope is entered once and every step is confined to it.** No phase targets
  anything outside the scope you give.
- **Passive by default.** Discovery and diagnostics are non-intrusive and always
  allowed. The **assessment** phase is the only active one and is double-gated:
  the operator must tick "enable active assessment" *and* the server's
  `enable_attacks` setting must be on, or the phase is skipped and the report
  says so.
- Everything runs in a background thread with per-tool timeouts.

## Using it

1. Boot the Ulfberht image; open the web UI (`:8000`). The **⚔️ Engagements** tab
   appears (it won't on a non-Ulfberht box). The detected offensive toolset also
   shows as the **Arsenal** panel on the Pentest tab.
2. Pick a playbook, enter a **scope** (IP / CIDR / host), optionally enable the
   active phase, and **Run engagement**.
3. Watch the phases progress and findings stream in; when it completes, **view**
   or **download** the engagement report.

### Playbooks

- **Scoped Network Assessment** — the flagship: sweep → posture → (optional)
  validation → report. More playbooks (web-app, Wi-Fi, AD/SMB) build on the same
  engine.

## Roadmap

- More playbooks (web-app via ZAP/nuclei, Wi-Fi via the Nexmon onboard radio,
  AD/SMB via netexec/enum4linux).
- Persisted engagement history + PDF export + SIEM push of findings (reusing
  Ragnar's existing SIEM egress).
- Deeper feed-forward from the passive watcher/guard layer into the diagnostics
  phase.

See also: [Ragnar OS Ulfberht](ragnar-os-ulfberht.md).
