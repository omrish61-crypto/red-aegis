"""Arsenal — the tool knowledge base of the co-pilot.

Every tool the co-pilot may recommend is registered here. Each entry:

- name        : canonical tool name (registry key)
- phase       : INTECTED task-tree phase the tool advances
                (recon | initial_access | c2 | privesc | lateral | evasion)
- host        : WHERE the tool lives / how availability is determined:
                  kali          -> live-probed via `wsl -d kali-linux command -v`
                  license       -> commercial license required (static status)
                  deprecated    -> unmaintained (static status)
                  windows-host  -> runs on WINDOWS TARGETS, not the Kali host
                  api           -> service API key required (static status)
                  docker        -> runs via Docker (static status)
                  install       -> install path known, NOT yet installed (missing)
                  gui           -> interactive/manual tool, evidence pasted in
- probe       : binary name used for the live `command -v` check (kali only)
- purpose     : one-line description
- template    : canonical invocation ("" where not applicable)
- guardrail   : operational/ethical constraint (printed by `intected arsenal --tool`)
- risk        : authorization category REQUIRED to recommend/run this tool
                (None | phishing | c2 | evasion | credential) — ENFORCED by
                scope.check_command(..., authorizations=...)
- license     : licensing note
- extractor   : parsing module that turns this tool's output into facts
                (None = no validated extractor — findings are NOT producible
                 until real output is captured and a parser is validated)

Availability honesty contract (project rule): the catalog's `host` assignments
are grounded in LIVE `command -v` probes on the Kali WSL2 host (2026-08-10);
`status_override` marks tools that are installed but NON-FUNCTIONAL on this
host (verified quirk — never trust a green flag).
"""

import subprocess

from .scope import RISK_CATEGORIES as RISK_TO_TOOLS  # single source of truth

PHASES = {"recon", "initial_access", "c2", "privesc", "lateral", "evasion"}

# --- entries ---------------------------------------------------------------

ARSENAL = [
    # ---- 1. Reconnaissance & Asset Discovery ------------------------------
    {"name": "amass", "phase": "recon", "host": "kali", "probe": "amass",
     "purpose": "subdomain enumeration (active + passive OSINT)",
     "template": "amass enum -passive -d <domain> -o out.json",
     "guardrail": "scope-clean domains only; passive default",
     "risk": None, "license": "Apache-2.0", "extractor": None},
    {"name": "sublist3r", "phase": "recon", "host": "kali", "probe": "sublist3r",
     "purpose": "subdomain enumeration via OSINT search engines",
     "template": "sublist3r -d <domain> -o out.txt",
     "guardrail": "OSINT only; apt package (verified 2026-08-10)",
     "risk": None, "license": "GPL-3.0", "extractor": None},
    {"name": "nmap", "phase": "recon", "host": "kali", "probe": "nmap",
     "purpose": "port/service/version discovery + NSE vuln scripts",
     "template": "nmap -sV -p- -oX out.xml <target>",
     "guardrail": "recon-only default; -sS works as root in WSL2 (control-tested)",
     "risk": None, "license": "NPSL", "extractor": "nmap"},
    {"name": "masscan", "phase": "recon", "host": "kali", "probe": "masscan",
     "purpose": "high-speed port scanning (nmap-compatible -oX)",
     "template": "masscan <subnet> -p 1-65535 --rate 1000 --wait 0 -oX out.xml",
     "guardrail": "BROKEN on Kali-WSL2: adapter binds (libpcap 1.10.6) but TX stays 0.00-kpps, scan 'completes' found=0 with EMPTY -oX; cannot scan loopback (lo has no MAC) — use nmap -sS on this host",
     "risk": None, "license": "AGPL-3.0", "extractor": "masscan",
     "status_override": "broken"},
    {"name": "shodan", "phase": "recon", "host": "api", "probe": "",
     "purpose": "search engine for internet-connected devices (passive)",
     "template": "shodan host <ip>",
     "guardrail": "requires SHODAN_API_KEY (not in env); passive — no target contact",
     "risk": None, "license": "commercial API (free tier)", "extractor": None},
    {"name": "censys", "phase": "recon", "host": "api", "probe": "",
     "purpose": "search engine for exposed services (passive)",
     "template": "censys search 'services.port=443'",
     "guardrail": "requires CENSYS_API_ID/SECRET (not in env)",
     "risk": None, "license": "commercial API (free tier)", "extractor": None},
    {"name": "eyewitness", "phase": "recon", "host": "kali", "probe": "eyewitness",
     "purpose": "automated web screenshots across asset ranges",
     "template": "eyewitness --web -f urls.txt -d ./report",
     "guardrail": "screenshots = human artifact, no parseable findings",
     "risk": None, "license": "BSD-3-Clause", "extractor": None},
    {"name": "aquatone", "phase": "recon", "host": "deprecated", "probe": "",
     "purpose": "web screenshot tool (unmaintained since 2021)",
     "template": "cat hosts.txt | aquatone -out ./shots",
     "guardrail": "DEPRECATED — prefer EyeWitness",
     "risk": None, "license": "MIT", "extractor": None},
    {"name": "theharvester", "phase": "recon", "host": "kali", "probe": "theharvester",
     "purpose": "OSINT email/host harvesting",
     "template": "theharvester -d <domain> -b all",
     "guardrail": "OSINT only — passive",
     "risk": None, "license": "GPL-2.0", "extractor": None},
    {"name": "gobuster", "phase": "recon", "host": "kali", "probe": "gobuster",
     "purpose": "directory/DNS brute force",
     "template": "gobuster dir -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/common.txt",
     "guardrail": "SPA targets emit false 200s — verify wildcard first",
     "risk": None, "license": "Apache-2.0", "extractor": "gobuster"},
    {"name": "ffuf", "phase": "recon", "host": "kali", "probe": "ffuf",
     "purpose": "fast web fuzzer (dirs, params, vhosts)",
     "template": "ffuf -u http://<target>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -o out.json",
     "guardrail": "SPA wildcard false-positives — size-filter",
     "risk": None, "license": "MIT", "extractor": "ffuf"},
    {"name": "nuclei", "phase": "recon", "host": "kali", "probe": "nuclei",
     "purpose": "template-based vulnerability scanner",
     "template": "nuclei -u http://<target> -jsonl -o out.jsonl",
     "guardrail": "Docker image also available; rate-limit (-rl) for labs",
     "risk": None, "license": "MIT", "extractor": "nuclei"},
    {"name": "zap", "phase": "recon", "host": "docker", "probe": "",
     "purpose": "OWASP ZAP active/passive web scanning",
     "template": "zap-baseline.py -t http://<target> -J zap.json",
     "guardrail": "Docker (zaproxy/zap-stable); rate-limit (-m/-D) for labs",
     "risk": None, "license": "Apache-2.0", "extractor": "zap"},
    {"name": "burp", "phase": "recon", "host": "gui", "probe": "",
     "purpose": "interactive web proxy (community/free)",
     "template": "",
     "guardrail": "manual tool — paste XML sitemap as evidence",
     "risk": None, "license": "commercial (free community)", "extractor": "burp"},
    {"name": "nikto", "phase": "recon", "host": "kali", "probe": "nikto",
     "purpose": "web server scanner (known issues/banners)",
     "template": "nikto -h http://<target>",
     "guardrail": "noisy — lab/authorized targets only",
     "risk": None, "license": "GPL-2.0", "extractor": "nikto"},
    # ---- 2. Initial Access & Weaponization ---------------------------------
    {"name": "gophish", "phase": "initial_access", "host": "kali", "probe": "gophish",
     "purpose": "phishing campaign framework (email + tracking)",
     "template": "./gophish serve",
     "guardrail": "PHISHING — needs mission authorization 'phishing' + written auth; never real users without it",
     "risk": "phishing", "license": "MIT", "extractor": None},
    {"name": "evilginx2", "phase": "initial_access", "host": "kali", "probe": "evilginx2",
     "purpose": "MitM reverse proxy for MFA session-cookie hijack",
     "template": "evilginx2 -p phishlet.conf",
     "guardrail": "PHISHING — needs mission authorization 'phishing'; NEVER against real users without written auth",
     "risk": "phishing", "license": "BSD-3-Clause", "extractor": None},
    {"name": "donut", "phase": "initial_access", "host": "kali", "probe": "donut",
     "purpose": "in-memory shellcode generation (VBS/JS/EXE/DLL)",
     "template": "donut -f payload.exe -o payload.bin",
     "guardrail": "in-memory payload gen — gated 'evasion'; authorized missions only",
     "risk": "evasion", "license": "BSD-2-Clause", "extractor": None},
    {"name": "msfvenom", "phase": "initial_access", "host": "kali", "probe": "msfvenom",
     "purpose": "Metasploit payload generator/encoder",
     "template": "msfvenom -p linux/x64/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 -f elf -o shell.elf",
     "guardrail": "lab/localhost listeners only",
     "risk": None, "license": "BSD-3-Clause", "extractor": None},
    {"name": "sqlmap", "phase": "initial_access", "host": "kali", "probe": "sqlmap",
     "purpose": "SQL injection detection/exploitation",
     "template": "sqlmap -u http://<target>/x?id=1 --batch",
     "guardrail": "destructive flags need aggressive:true; fresh session cookie",
     "risk": None, "license": "GPL-2.0", "extractor": "sqlmap"},
    # ---- 3. C2 frameworks ---------------------------------------------------
    {"name": "sliver", "phase": "c2", "host": "kali", "probe": "sliver-server",
     "purpose": "open-source cross-platform C2 (mTLS/WireGuard/HTTP)",
     "template": "sliver-server",
     "guardrail": "C2 — gated 'c2'; authorized red-team missions only",
     "risk": "c2", "license": "GPL-3.0", "extractor": None},
    {"name": "havoc", "phase": "c2", "host": "install", "probe": "",
     "purpose": "modern OSS post-exploitation C2 (Demon agent)",
     "template": "./Havoc server",
     "guardrail": "C2 — gated 'c2'; authorized red-team missions only",
     "risk": "c2", "license": "GPL-3.0", "extractor": None},
    {"name": "mythic", "phase": "c2", "host": "docker", "probe": "",
     "purpose": "multi-agent C2 framework (Docker, plug-and-play agents)",
     "template": "docker compose up -d",
     "guardrail": "C2 — gated 'c2'; Docker compose deploy; authorized missions only",
     "risk": "c2", "license": "Apache-2.0", "extractor": None},
    {"name": "cobalt-strike", "phase": "c2", "host": "license", "probe": "",
     "purpose": "commercial C2 framework (Beacon)",
     "template": "",
     "guardrail": "COMMERCIAL license required — use Sliver/Havoc/Mythic as OSS alternatives; gated 'c2'",
     "risk": "c2", "license": "commercial (per-seat)", "extractor": None},
    # ---- 4. Privilege Escalation & Credential Access ------------------------
    {"name": "mimikatz", "phase": "privesc", "host": "kali", "probe": "mimikatz",
     "purpose": "LSASS credential extraction (plaintext/hashes/PINs)",
     "template": "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" \"exit\"",
     "guardrail": "CREDENTIAL extraction — gated 'credential'; Windows post-exploitation on authorized hosts only",
     "risk": "credential", "license": "BSD-3-Clause (variants)", "extractor": None},
    {"name": "rubeus", "phase": "privesc", "host": "kali", "probe": "rubeus",
     "purpose": "Kerberos abuse (Kerberoast/AS-REP/PtT)",
     "template": "Rubeus.exe kerberoast /outfile:hashes.txt",
     "guardrail": "CREDENTIAL — gated 'credential'; AD lab/authorized domains only",
     "risk": "credential", "license": "BSD-3-Clause", "extractor": None},
    {"name": "linpeas", "phase": "privesc", "host": "kali", "probe": "linpeas",
     "purpose": "automated Linux privilege-escalation enumeration",
     "template": "curl -L <raw-linpeas-url> | sh",
     "guardrail": "read-only enumeration — run ON the target",
     "risk": None, "license": "GPL-2.0", "extractor": None},
    {"name": "winpeas", "phase": "privesc", "host": "kali", "probe": "winpeas",
     "purpose": "automated Windows privilege-escalation enumeration",
     "template": "winPEASx64.exe",
     "guardrail": "read-only enumeration — run ON the target",
     "risk": None, "license": "GPL-2.0", "extractor": None},
    {"name": "bloodhound", "phase": "privesc", "host": "kali", "probe": "bloodhound-python",
     "purpose": "AD relationship graph analysis (Neo4j + UI)",
     "template": "bloodhound --no-sandbox",
     "guardrail": "read-only AD graph analysis; needs Neo4j",
     "risk": None, "license": "Apache-2.0", "extractor": None},
    {"name": "sharphound", "phase": "privesc", "host": "kali", "probe": "sharphound",
     "purpose": "AD graph data collector (feeds BloodHound)",
     "template": "SharpHound.exe -c All",
     "guardrail": "read-only LDAP/AD queries",
     "risk": None, "license": "Apache-2.0", "extractor": None},
    # ---- 5. Lateral Movement & Persistence ----------------------------------
    {"name": "impacket", "phase": "lateral", "host": "kali", "probe": "impacket-secretsdump",
     "purpose": "Python network protocol suite (psexec/wmiexec/secretsdump)",
     "template": "impacket-psexec <user>@<target> cmd.exe",
     "guardrail": "standard lab lateral movement; secretsdump is gated 'credential'",
     "risk": None, "license": "Apache-2.0", "extractor": None},
    {"name": "netexec", "phase": "lateral", "host": "kali", "probe": "netexec",
     "purpose": "network exec/enum (CrackMapExec successor)",
     "template": "netexec smb <target> -u user -p pass -j",
     "guardrail": "credential spraying is an ACTIVE auth attack — scope+aggressive gates apply",
     "risk": None, "license": "BSD-2-Clause", "extractor": None},
    {"name": "responder", "phase": "lateral", "host": "kali", "probe": "responder",
     "purpose": "LLMNR/NBT-NS/MDNS poisoning for NTLM hash capture",
     "template": "responder -I eth0 -wv",
     "guardrail": "ACTIVE network poisoning — lab/authorized networks only",
     "risk": None, "license": "GPL-3.0", "extractor": None},
    {"name": "certipy", "phase": "lateral", "host": "kali", "probe": "certipy",
     "purpose": "AD CS enumeration and abuse",
     "template": "certipy find -u user@<domain> -p pass -vulnerable",
     "guardrail": "CREDENTIAL — gated 'credential'; AD lab/authorized domains only",
     "risk": "credential", "license": "MIT", "extractor": None},
    {"name": "chisel", "phase": "lateral", "host": "kali", "probe": "chisel",
     "purpose": "fast TCP/HTTP tunnel for segmented networks",
     "template": "./chisel server -p 8080 --reverse",
     "guardrail": "tunnel endpoints remain scope-gated",
     "risk": None, "license": "MIT", "extractor": None},
    {"name": "ligolo-ng", "phase": "lateral", "host": "kali", "probe": "ligolo-proxy",
     "purpose": "tunneling proxy with agent/proxy split",
     "template": "ligolo-ng_proxy -selfcert",
     "guardrail": "tunnel endpoints remain scope-gated",
     "risk": None, "license": "MIT", "extractor": None},
    # ---- 6. Defense Evasion & EDR Bypass ------------------------------------
    {"name": "syswhispers", "phase": "evasion", "host": "windows-host", "probe": "",
     "purpose": "direct syscall stub generation (EDR API-hook bypass)",
     "template": "python3 syswhispers.py --preset all -o syscalls",
     "guardrail": "EDR evasion — gated 'evasion'; defensive-tooling research context only",
     "risk": "evasion", "license": "MIT", "extractor": None},
    {"name": "pe-bearer", "phase": "evasion", "host": "windows-host", "probe": "",
     "purpose": "class of custom loaders stripping EDR hooks (unhooking)",
     "template": "",
     "guardrail": "EDR evasion class (not a single package) — gated 'evasion'; defensive research only; evaluate per-repo",
     "risk": "evasion", "license": "varies", "extractor": None},
]


# --- live availability probe (no green-flag assumptions) --------------------

_PROBE_CACHE: dict[str, str] | None = None

_KALI_WSL = ["wsl", "-d", "kali-linux", "-e", "bash", "-c"]


def _probe_kali(names: list[str]) -> dict[str, bool]:
    """Batch `command -v` over the Kali WSL2 host; one subprocess call.

    Parses `ok <name>` / `miss <name>` lines; a name with no line is a miss.
    Returns {name: bool}. Never raises — probe failures degrade to miss.
    """
    script = "for t in %s; do command -v \"$t\" >/dev/null 2>&1 && echo \"ok $t\" || echo \"miss $t\"; done" % " ".join(names)
    try:
        res = subprocess.run(_KALI_WSL + [script], capture_output=True,
                             text=True, timeout=60)
    except (subprocess.SubprocessError, OSError):
        return {n: False for n in names}
    found: dict[str, bool] = {}
    for line in (res.stdout or "").splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[1] in names:
            found[parts[1]] = parts[0] == "ok"
    return {n: found.get(n, False) for n in names}


def probe_arsenal(force: bool = False) -> dict[str, str]:
    """Probe every catalog tool -> status string.

    status values: ok | missing | broken | license | deprecated | windows-host |
                   api | docker | install | gui
    `force=True` re-probes the Kali host; otherwise the per-process result is
    cached (the reasoning digest calls this every turn).
    """
    global _PROBE_CACHE
    if _PROBE_CACHE is not None and not force:
        return dict(_PROBE_CACHE)
    kali_names = [e["probe"] for e in ARSENAL if e["host"] == "kali"]
    found = _probe_kali(kali_names) if kali_names else {}
    probe: dict[str, str] = {}
    for e in ARSENAL:
        if e["host"] == "kali":
            status = "ok" if found.get(e["probe"]) else "missing"
            if status == "ok" and e.get("status_override"):
                status = e["status_override"]  # e.g. masscan -> broken
        else:
            status = e["host"]  # static status for non-kali hosts
        probe[e["name"]] = status
    if not force:
        _PROBE_CACHE = dict(probe)
    return probe


def arsenal_summary(probe: dict[str, str] | None = None) -> str:
    """Compact per-phase list of only the tools verified usable (status 'ok')."""
    if probe is None:
        probe = probe_arsenal()
    by_phase: dict[str, list[str]] = {}
    for e in ARSENAL:
        if probe.get(e["name"]) == "ok":
            by_phase.setdefault(e["phase"], []).append(e["name"])
    lines = []
    for phase in sorted(PHASES):
        tools = by_phase.get(phase)
        if tools:
            lines.append(f"{phase}: {', '.join(sorted(tools))}")
    return " | ".join(lines) if lines else "(no verified tools)"


def format_arsenal_table(probe: dict[str, str]) -> str:
    """Human table of the whole catalog with live statuses."""
    rows = []
    for phase in sorted(PHASES):
        rows.append(f"\n[{phase}]")
        for e in ARSENAL:
            if e["phase"] != phase:
                continue
            st = probe.get(e["name"], "?")
            rows.append(f"  {e['name']:<16} {st:<12} {e['purpose']}")
    return "\n".join(rows)


def get(name: str) -> dict | None:
    """Return the arsenal entry for a tool name (None if unknown)."""
    for e in ARSENAL:
        if e["name"] == name:
            return e
    return None


def requires_authorization(name: str) -> str | None:
    """Risk category gating this tool, or None if ungated (scope enforces)."""
    for risk, tools in RISK_TO_TOOLS.items():
        if name in tools:
            return risk
    return None


def blocked_categories(authorizations: set[str]) -> list[str]:
    """Risk categories NOT authorized for a mission (deny-by-default)."""
    return sorted(set(RISK_TO_TOOLS) - set(authorizations or set()))
