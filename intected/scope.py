"""MissionScope — hard scoping gate (ethics, non-negotiable).

Every target and every command is validated against the mission's allowed hosts.
Violations raise ScopeViolation (a PermissionError) and are logged by the caller.

Rules (proven pitfalls from pentest-core embedded):
- Deny by default: a host not matching any allowed entry is refused.
- `aggressive` approval is STRICT boolean: only `aggressive is True` passes.
  The string "true" (or "yes"/"1") does NOT count as approval.
- Matches: exact IP, CIDR, exact hostname, or a subdomain of an allowed hostname.
"""

import ipaddress
import re

HOST_TOKEN_RE = re.compile(
    r"(?<![\w.-])(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3}|"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})(?![\w.-])"
)

# Destructive / aggressive markers -> require explicit aggressive=True
AGGRESSIVE_MARKERS = (
    "--aggressive", "--tamper", "--drop", "--delete", "--force",
    "rm -rf", "DROP TABLE", "DROP DATABASE", "format ", "mkfs",
)

# Risk categories -> tool names. Tools in these categories are REJECTED unless
# the mission declares the category in missions.authorizations_json
# (deny-by-default). arsenal.py re-exports this as RISK_TO_TOOLS — this dict is
# the single source of truth; the enforcement point is check_command().
RISK_CATEGORIES = {
    "phishing":   {"gophish", "evilginx2", "evilginx"},
    "c2":         {"sliver", "havoc", "mythic", "cobalt-strike", "cobaltstrike"},
    "evasion":    {"donut", "syswhispers", "pe-bearer", "unhooking"},
    "credential": {"mimikatz", "rubeus", "certipy", "secretsdump"},
}

_RISK_TOOL_RE = re.compile(
    r"\b(?:%s)\b" % "|".join(
        re.escape(t) for tools in RISK_CATEGORIES.values() for t in tools
    ),
    re.IGNORECASE,
)


def _gated_tool(cmd: str) -> tuple[str, str] | None:
    """Return (tool, risk_category) if the command invokes a gated tool."""
    for m in _RISK_TOOL_RE.finditer(cmd):
        tool = m.group(0).lower()
        for risk, tools in RISK_CATEGORIES.items():
            if tool in tools:
                return tool, risk
    return None


class ScopeViolation(PermissionError):
    """Raised when a target or command falls outside the mission's allowed scope."""


# File-like tokens that are NOT hosts (wordlists, scripts, outputs). A token
# ending in one of these is skipped by command validation. Includes payload
# artifact extensions (msfvenom/donut outputs like shell.elf must not be
# treated as hosts).
FILE_EXTENSIONS = {
    "txt", "lst", "dic", "json", "xml", "php", "html", "htm", "js", "css",
    "log", "csv", "yml", "yaml", "conf", "cfg", "ini", "md", "sh", "py", "rb",
    "pl", "exe", "bin", "gz", "zip", "tar", "pcap", "db", "sql", "bak", "old",
    "save", "out", "raw", "list", "words", "php3", "jsp", "asp", "aspx",
    "elf", "dll", "so", "bat", "cmd", "vbs", "ps1", "jar", "war", "app",
    "msi", "deb", "rpm", "ko", "c", "h", "asm", "o", "a",
}


def _normalize_host(host: str) -> str:
    """Strip scheme, userinfo, port, path from a host token."""
    h = host.strip().lower()
    h = re.sub(r"^[a-z][a-z0-9+.-]*://", "", h)      # scheme://
    h = re.sub(r"^[^@/]+@", "", h)                   # user:pass@
    h = re.sub(r":[0-9]+(/.*)?$", "", h)             # :port or :port/path
    h = h.split("/", 1)[0]                           # trailing path
    return h.rstrip(".")


def _looks_like_file(token: str) -> bool:
    norm = _normalize_host(token)
    if "." not in norm:
        return False
    return norm.rsplit(".", 1)[1] in FILE_EXTENSIONS


def _host_matches(host: str, allowed: str) -> bool:
    """True if `host` is allowed (exact / CIDR / subdomain)."""
    # 1. IP / CIDR comparison — must run on the RAW allowed token:
    #    _normalize_host would strip the "/24" off a CIDR entry.
    try:
        net = ipaddress.ip_network(allowed.strip(), strict=False)
    except ValueError:
        net = None
    if net is not None:
        try:
            return ipaddress.ip_address(_normalize_host(host)) in net
        except ValueError:
            return False
    # 2. Hostname: exact, or subdomain of an allowed hostname
    host = _normalize_host(host)
    allowed = _normalize_host(allowed)
    if not host or not allowed:
        return False
    if host == allowed:
        return True
    return host.endswith("." + allowed)


def check_target(target: str, allowed_hosts: list[str]) -> None:
    """Raise ScopeViolation unless target is within allowed_hosts."""
    if not allowed_hosts:
        raise ScopeViolation(f"mission has no allowed hosts — refusing target {target!r}")
    if not any(_host_matches(target, a) for a in allowed_hosts):
        raise ScopeViolation(
            f"target {target!r} is outside allowed scope {allowed_hosts}"
        )


_IP_LITERAL_RE = re.compile(r"^[0-9]{1,3}(?:\.[0-9]{1,3}){3}$")


def _is_ip_literal(token: str) -> bool:
    """True for bare IPv4-looking tokens (10.0.0.99) — never an option name."""
    return bool(_IP_LITERAL_RE.match(token))


def check_command(cmd: str, allowed_hosts: list[str], aggressive: bool = False,
                  authorizations=None) -> None:
    """Validate every host token in a command against scope.

    `aggressive` must be the STRICT boolean True to permit destructive markers.
    `authorizations` must be a set/list of risk categories the mission declares
    (phishing/c2/evasion/credential). A bare string or None NEVER counts —
    gated tools are denied by default.
    """
    # 1. Destructive marker gate
    lower = cmd.lower()
    if any(marker.lower() in lower for marker in AGGRESSIVE_MARKERS):
        if aggressive is not True:  # strict: string "true" fails
            raise ScopeViolation(
                "command contains destructive markers and aggressive=True "
                f"(strict boolean) was not passed: {cmd!r}"
            )
    # 1b. Risk-category gate: gated tools need explicit mission authorization
    if not isinstance(authorizations, (set, list, frozenset)):
        authorizations = set()  # None or a bare string -> deny by default
    gated = _gated_tool(cmd)
    if gated is not None:
        tool, risk = gated
        if risk not in authorizations:
            raise ScopeViolation(
                f"tool {tool!r} is gated under '{risk}' and the mission does "
                f"not authorize that category (authorized: "
                f"{sorted(authorizations) or 'none'})"
            )
    # 2. Host-token gate — every host-like token must be in scope.
    #    File-like tokens (wordlists, outputs) are excluded.
    for m in HOST_TOKEN_RE.finditer(cmd):
        token = m.group(0)
        if _looks_like_file(token):
            continue
        # key=value option assignments (nmap --script-args http-fetch.paths=/metrics)
        # are NOT hosts — but ONLY when the token is a bare option-name-shaped
        # token (letters, NOT an IP literal) AND not inside a URL (previous
        # char is not '/'). Control-review H1 (live-verified): `10.0.0.99=x`
        # and `curl --url=http://evil.com= ...` bypassed the gate — both are
        # checked again here.
        if cmd[m.end():m.end() + 1] == "=":
            prev = cmd[m.start() - 1] if m.start() > 0 else "/"
            if not _is_ip_literal(token) and prev not in "/.=:&":
                continue
        check_target(token, allowed_hosts)


def host_tokens(cmd: str) -> list[str]:
    """Extract host-like tokens from a command (used by tests and CLI display)."""
    return [t for t in HOST_TOKEN_RE.findall(cmd)]
