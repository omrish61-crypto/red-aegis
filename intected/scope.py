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


class ScopeViolation(PermissionError):
    """Raised when a target or command falls outside the mission's allowed scope."""


# File-like tokens that are NOT hosts (wordlists, scripts, outputs). A token
# ending in one of these is skipped by command validation.
FILE_EXTENSIONS = {
    "txt", "lst", "dic", "json", "xml", "php", "html", "htm", "js", "css",
    "log", "csv", "yml", "yaml", "conf", "cfg", "ini", "md", "sh", "py", "rb",
    "pl", "exe", "bin", "gz", "zip", "tar", "pcap", "db", "sql", "bak", "old",
    "save", "out", "raw", "list", "words", "php3", "jsp", "asp", "aspx",
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


def check_command(cmd: str, allowed_hosts: list[str], aggressive: bool = False) -> None:
    """Validate every host token in a command against scope.

    `aggressive` must be the STRICT boolean True to permit destructive markers.
    """
    # 1. Destructive marker gate
    lower = cmd.lower()
    if any(marker.lower() in lower for marker in AGGRESSIVE_MARKERS):
        if aggressive is not True:  # strict: string "true" fails
            raise ScopeViolation(
                "command contains destructive markers and aggressive=True "
                f"(strict boolean) was not passed: {cmd!r}"
            )
    # 2. Host-token gate — every host-like token must be in scope.
    #    File-like tokens (wordlists, outputs) are excluded.
    for token in HOST_TOKEN_RE.findall(cmd):
        if _looks_like_file(token):
            continue
        check_target(token, allowed_hosts)


def host_tokens(cmd: str) -> list[str]:
    """Extract host-like tokens from a command (used by tests and CLI display)."""
    return [t for t in HOST_TOKEN_RE.findall(cmd)]
