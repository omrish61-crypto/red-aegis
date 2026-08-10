"""Attack-Plan Engine — evidence-based dynamic testing plan (methodology 11).

THE RULE (methodology 15): every finding must lead to a test hypothesis, and
every test must be based on a previous finding. This engine consumes the
EvidenceGraph and produces a RANKED attack plan: branch selection (Web/API vs
Network), then priorities (Auth/AuthZ → JWT → API authz → GraphQL → Injection
→ Client-side → Infra) — exactly the decision tree in the methodology.

Each plan item carries: rank, area, hypothesis (why we test this NOW), the
facts it is based on (fact ids), and concrete test commands per target.
"""

from .evidence import EvidenceGraph, stack_profile

# priority areas in the web/api branch (methodology 11 example)
WEB_BRANCH = [
    ("Authentication / Authorization",
     "Recon shows an auth surface — verify identity controls before anything else."),
    ("JWT implementation",
     "Token-based auth detected — test algorithm confusion, none-alg, expiry, and signing."),
    ("REST API authorization",
     "API endpoints exposed — test broken object-level and function-level authorization."),
    ("GraphQL authorization / introspection",
     "GraphQL endpoint present — introspection, field-level authz, and query depth."),
    ("Injection points",
     "Input-bearing endpoints known — test SQLi, NoSQLi, SSTI, and command injection."),
    ("Client-side issues",
     "UI/JS surface mapped — test XSS, CSRF, open redirects, and CORS misconfig."),
    ("Infrastructure hardening",
     "Versions/banners identified — correlate known CVEs and missing security headers."),
]

NETWORK_BRANCH = [
    ("Service enumeration",
     "Network ports exposed — enumerate the full service set first."),
    ("Version identification",
     "Banners present — pin exact versions for vulnerability correlation."),
    ("Known-vulnerability correlation",
     "Versions known — match against known CVEs/exploits (never blind Metasploit)."),
    ("Configuration weaknesses",
     "Service behaviors observed — test default creds, weak configs, and exposure."),
    ("Authentication controls",
     "Auth services present — test credential handling and access controls."),
    ("Manual validation",
     "Hypotheses formed — validate each finding manually before reporting."),
]

COMMAND_TEMPLATES = {
    "nmap_service": "nmap -Pn -sV -sC -p {port} {target} -oN /tmp/nmap_{port}_{target}.txt",
    "nmap_full": "nmap -Pn -p- --open {target} -oN /tmp/nmap_full_{target}.txt",
    "http_headers": "curl -skI https://{target}",
    "whatweb": "whatweb -a 3 {target}",
    "wafw00f": "wafw00f {target}",
    "ffuf": "ffuf -u http://{target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -ac -mc 200,204,301,302,307,401,403",
    "nuclei": "nuclei -u http://{target} -severity low,medium,high,critical",
    "graphql_introspect": "curl -sk -X POST http://{target}/graphql -H 'Content-Type: application/json' -d '{{\"query\":\"{{__schema{{types{{name}}}}}}\"}}'",
    "nikto": "nikto -h http://{target} -maxtime 120s",
    "sqlmap": "sqlmap -u http://{target} --batch --level 2",
}


def _cmd(key: str, target: str, **kw) -> str:
    try:
        return COMMAND_TEMPLATES[key].format(target=target, **kw)
    except KeyError:
        return COMMAND_TEMPLATES[key]


def _web_plan(graph: EvidenceGraph, profile: dict, target: str) -> list[dict]:
    plan = []
    for rank, (area, hypothesis) in enumerate(WEB_BRANCH, 1):
        item = {"rank": rank, "area": area, "hypothesis": hypothesis,
                "based_on": sorted(graph.facts), "commands": []}
        if area.startswith("Authentication") and profile["auth_surface"]:
            item["commands"] = [_cmd("nuclei", target),
                                _cmd("nikto", target)]
        elif area.startswith("JWT"):
            item["commands"] = []
        elif area.startswith("REST API") and profile["api"]:
            item["commands"] = [_cmd("ffuf", target)]
        elif area.startswith("GraphQL") and profile["graphql"]:
            item["commands"] = [_cmd("graphql_introspect", target)]
        elif area.startswith("Injection") and profile["web"]:
            item["commands"] = [_cmd("sqlmap", target)]
        elif area.startswith("Client-side") and profile["web"]:
            item["commands"] = [_cmd("http_headers", target)]
        elif area.startswith("Infrastructure"):
            item["commands"] = [_cmd("nmap_service", target, port=443)]
        # only include areas with evidence-backed relevance
        if item["commands"] or area.startswith("Infrastructure"):
            plan.append(item)
    return plan


def _network_plan(graph: EvidenceGraph, profile: dict, target: str) -> list[dict]:
    plan = []
    for rank, (area, hypothesis) in enumerate(NETWORK_BRANCH, 1):
        plan.append({
            "rank": rank, "area": area, "hypothesis": hypothesis,
            "based_on": sorted(graph.facts), "commands": [
                _cmd("nmap_service", target, port=s["port"])
                for s in graph.services if s["port"] not in (80, 443, 3000, 8001, 8080)
            ][:4],
        })
    return plan


def build_plan(graph: EvidenceGraph, target: str | None = None) -> dict:
    """Ranked attack plan for a target from its evidence graph (methodology 11)."""
    tgt = target or graph.asset
    profile = stack_profile(graph)
    if profile["network"] and not profile["web"]:
        branch = "network"
        plan = _network_plan(graph, profile, tgt)
    else:
        branch = "web_api"
        plan = _web_plan(graph, profile, tgt)
    return {
        "target": tgt,
        "branch": branch,
        "stack": profile,
        "plan": plan,
        "rule": "every finding leads to a test hypothesis; every test is "
                "based on a previous finding",
    }


def plan_for_mission(conn, mission_id: int, target: str | None = None) -> dict:
    """Evidence graph + ranked plan for a mission (CLI/dashboard entry point)."""
    from .evidence import build_evidence_graph
    graph = build_evidence_graph(conn, mission_id, target)
    return {"graph": graph.to_dict(), "plan": build_plan(graph, target)}
