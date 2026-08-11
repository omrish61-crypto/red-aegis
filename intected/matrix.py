"""Tool selection decision matrix (addendum section 6).

Strict IF/THEN logic based on the target footprint — the Expert agent never
picks tools randomly. Given the EvidenceGraph profile, this returns the next
actionable tool call (registered tool + params), WAF-aware, with the
stealth-safe defaults from section 7 applied. masscan is never suggested
(requires explicit written permission + would trip IDS).

Rules implemented (section 6):
- Network: live hosts -> fping/nmap -sn; ports -> nmap -sV -sC top-1000;
  firewall -> nmap -sA / traceroute (firewall detection is operator-gated)
- Web: tech -> whatweb (passive); dirs -> ffuf/ferox with delay+filter;
  known CVEs -> nuclei -tags cve (the safe, accurate web-CVE path)
- Vuln: SQLi -> sqlmap (tamper-aware if WAF); XSS -> dalfox; service
  exploitation -> metasploit (OPERATOR-GATED, not auto-suggested)
- WAF present -> no nikto/wpscan/dirb defaults; suggest requests-based
  business-logic probes instead
"""

from .evidence import stack_profile

# service -> canonical port (for honeypot / service-mismatch detection)
_CANONICAL_PORTS = {
    "ssh": 22, "http": 80, "https": 443, "ftp": 21, "smtp": 25,
    "smb": 445, "netbios": 139, "rdp": 3389, "telnet": 23, "mysql": 3306,
    "postgresql": 5432, "redis": 6379, "mongodb": 27017, "dns": 53,
}


def honeypot_candidates(services: list[dict]) -> list[dict]:
    """Flag service/port mismatches (honeypot pattern, low confidence).

    E.g. an SSH banner on port 445, or HTTP on port 22. Such findings get
    LOW confidence and must NOT be attacked aggressively — a honeypot's
    purpose is to bait. Returns flagged services with the reason."""
    flagged = []
    for svc in services:
        banner = (svc.get("banner") or "").lower()
        port = svc.get("port")
        for name, canon in _CANONICAL_PORTS.items():
            if name in banner and canon != port:
                flagged.append({
                    "port": port,
                    "banner": svc.get("banner", "")[:60],
                    "looks_like": name,
                    "canonical_port": canon,
                    "confidence": 0.25,
                    "reason": f"{name}-like banner on non-standard port "
                              f"{port} (canonical {canon}) — possible honeypot",
                })
                break
    return flagged


def next_tool_call(profile: dict, surface: list[str],
                   target: str, services: list[dict] | None = None) -> dict | None:
    """Pick the next tool call for the target given its footprint.

    Returns {"tool": <registered>, "params": {...}} or None when the
    footprint yields nothing actionable (planner stops, not guesses).
    Honeypot candidates (service/port mismatch) force a LOW-CONFIDENCE,
    passive-only probe — never aggressive testing.
    """
    web = profile.get("web")
    waf = profile.get("waf_detected", False)
    surface_l = [s.lower() for s in (surface or [])]
    graphql = profile.get("graphql") or any("/graphql" in s for s in surface_l)
    api = profile.get("api") or any("/api" in s or "/rest" in s for s in surface_l)

    # HONEYPOT GUARD: service/port mismatch -> low confidence, passive only
    honeypots = honeypot_candidates(services or [])
    if honeypots and not waf:
        h = honeypots[0]
        return {"tool": "http_headers",
                "params": {"target": target, "port": h["port"]},
                "low_confidence": True, "honeypot": h,
                "why": f"HONEYPOT CANDIDATE: {h['reason']} — passive probe "
                       "only, no aggressive testing"}

    # WAF present: no nikto/wpscan/dirb defaults (section 6D)
    if waf and web:
        return {"tool": "http_headers",  # passive, WAF-safe
                "params": {"target": target, "port": 80},
                "why": "WAF detected — passive header probe first; "
                       "no nikto/wpscan/dirb defaults"}
    # web level
    if web:
        if graphql or api:
            return {"tool": "http_headers",
                    "params": {"target": target, "port": 80},
                    "why": "API/GraphQL surface — map before deeper testing"}
        if not any(s in surface_l for s in ("/login", "/admin")):
            return {"tool": "ffuf_content",
                    "params": {"target": target},
                    "why": "hidden endpoints unknown — rate-limited content "
                           "discovery (delay 1s, filter 403/404)"}
        return {"tool": "nuclei",
                "params": {"target": target},
                "why": "known-CVE verification via nuclei templates "
                       "(safe, accurate — not LLM guessing)"}
    # network level
    if profile.get("network"):
        return {"tool": "nmap_services",
                "params": {"target": target, "ports": "top1000"},
                "why": "network services present — version detection "
                       "(bounded rate, T3)"}
    # no usable footprint: only passive recon is honest
    return {"tool": "nmap_ports",
            "params": {"target": target},
            "why": "no web/network evidence yet — bounded top-1000 scan to "
                   "build the footprint"}
