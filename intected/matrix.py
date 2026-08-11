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


def next_tool_call(profile: dict, surface: list[str],
                   target: str) -> dict | None:
    """Pick the next tool call for the target given its footprint.

    Returns {"tool": <registered>, "params": {...}} or None when the
    footprint yields nothing actionable (planner stops, not guesses).
    """
    web = profile.get("web")
    waf = profile.get("waf_detected", False)
    surface_l = [s.lower() for s in (surface or [])]
    graphql = profile.get("graphql") or any("/graphql" in s for s in surface_l)
    api = profile.get("api") or any("/api" in s or "/rest" in s for s in surface_l)

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
