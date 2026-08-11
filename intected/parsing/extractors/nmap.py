"""nmap extractor — XML (-oX) and plain-text output.

XML facts: port (open ports), service, version (product+version), cpe,
note (NSE script findings, e.g. VULNERABLE blocks).
Text facts: parsed from the classic port table.
"""

import re
import xml.etree.ElementTree as ET

from .common import bounded, dedupe_facts, note

_TEXT_PORT_RE = re.compile(
    r"^(\d+)/(tcp|udp)[ \t]+(\w+)[ \t]+(\S+)?[ \t]*(.*)$", re.MULTILINE
)
_TEXT_TITLE_RE = re.compile(r"\|_?http-title:\s*(.+)$", re.MULTILINE)
# text-mode NSE script blocks: "|   vulners:" / "|_http-title:" etc.
_TEXT_SCRIPT_RE = re.compile(
    r"^\|\s*_?([a-z0-9_-]+):\s*(.*)$", re.MULTILINE)
# fingerprint-strings block: "| fingerprint-strings:" then consecutive
# "|" lines (probe responses) until the next non-| line.
_TEXT_FPRINT_RE = re.compile(
    r"\| fingerprint-strings:[^\n]*\n((?:\|.*(?:\n|$))*)", re.MULTILINE)
_SF_PORT_RE = re.compile(r"SF-Port(\d+)-TCP")

SCRIPT_VULN_MARKERS = ("VULNERABLE", "CVE-", "Exploit available", "State:")

# Known-application signatures matched against fingerprint-strings output
# (evidence-based: the RAW output must literally contain the app name).
_APP_SIGNATURES = (
    ("OWASP Juice Shop", {"service": "http", "product": "OWASP Juice Shop"}),
    ("Apache Tomcat", {"service": "http", "product": "Apache Tomcat"}),
    ("nginx", {"service": "http", "product": "nginx"}),
    ("Apache httpd", {"service": "http", "product": "Apache httpd"}),
    ("Microsoft-IIS", {"service": "http", "product": "Microsoft IIS"}),
)


def _decode_escapes(text: str) -> str:
    """Decode literal backslash-x escapes nmap emits in script output
    (e.g. http-title 'HTTP Status 404 \\xE2\\x80\\x93 Not Found').
    Consecutive backslash-x escape pairs are treated as UTF-8 bytes
    when valid."""
    if "\\x" not in text:
        return text
    parts = re.split(r"(\\x[0-9a-fA-F]{2})", text)
    out = []
    pending: list[int] = []
    for p in parts:
        m = re.fullmatch(r"\\x([0-9a-fA-F]{2})", p)
        if m:
            pending.append(int(m.group(1), 16))
            continue
        if p:  # non-empty separator: flush the pending byte run
            if pending:
                out.append(_decode_utf8(pending))
                pending = []
            out.append(p)
    if pending:
        out.append(_decode_utf8(pending))
    return "".join(out)


def _decode_utf8(bytes_vals: list[int]) -> str:
    try:
        return bytes(bytes_vals).decode("utf-8")
    except Exception:
        return "".join(chr(b) for b in bytes_vals)


def extract(text: str):
    text = text.strip()
    if not text:
        return [], []
    if text.lstrip().startswith("<"):
        return _extract_xml(text)
    return _extract_text(text)


def _extract_xml(text: str):
    facts = []
    warnings = []
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        return [], [f"nmap XML parse failed: {exc}"]
    for host in root.iter("host"):
        addr = None
        for a in host.iter("address"):
            addr = a.get("addr")
            break
        for port in host.iter("port"):
            pid, proto = port.get("portid"), port.get("protocol")
            state = None
            for st in port.iter("state"):
                state = st.get("state")
                break
            if state == "open":
                facts.append({"fact_type": "port",
                              "value": {"port": int(pid), "protocol": proto,
                                        "host": addr or ""}})
            service = None
            for svc in port.iter("service"):
                service = svc
                break
            if service is not None and state == "open":
                sname = service.get("name")
                product = service.get("product")
                version = service.get("version")
                extrainfo = service.get("extrainfo")
                if sname:
                    facts.append({"fact_type": "service",
                                  "value": {"port": int(pid), "service": sname,
                                            "host": addr or ""}})
                if product or version:
                    value = {"port": int(pid), "product": product or "", 
                             "version": version or ""}
                    if extrainfo:
                        value["extrainfo"] = extrainfo
                    facts.append({"fact_type": "version", "value": value})
                cpe = service.get("cpe")
                if cpe:
                    facts.append({"fact_type": "version",
                                  "value": {"port": int(pid), "cpe": cpe}})
            # NSE script output -> notes (fact even when the script failed —
            # honesty: a failed/failed-to-run script is a fact worth keeping)
            for script in port.iter("script"):
                sid = script.get("id") or ""
                output = script.get("output") or ""
                if not output:
                    continue
                vulnish = any(m in output for m in SCRIPT_VULN_MARKERS) or "vuln" in sid.lower()
                facts.append({"fact_type": "note",
                              "value": {"tool": "nmap-script", "script": sid,
                                        "vulnerable": vulnish,
                                        "output": bounded(output, 800)}})
    return dedupe_facts(facts), warnings


def _extract_text(text: str):
    facts = []
    warnings = []
    # CRLF normalization: \s-classes must never cross line boundaries
    text = text.replace("\r\n", "\n")
    for m in _TEXT_PORT_RE.finditer(text):
        port, proto, state = m.group(1), m.group(2), m.group(3)
        rest = (m.group(5) or "").strip()
        if state != "open":
            continue
        facts.append({"fact_type": "port",
                      "value": {"port": int(port), "protocol": proto}})
        if rest:
            # e.g. "Apache httpd 2.4.25 ((Debian))" or "ssl/http Apache..."
            product = rest.split(" ", 1)[0] if rest else ""
            facts.append({"fact_type": "version", "value": {"port": int(port),
                                                            "banner": bounded(rest)}})
    for m in _TEXT_TITLE_RE.finditer(text):
        facts.append({"fact_type": "note",
                      "value": {"tool": "nmap", "script": "http-title",
                                "title": bounded(_decode_escapes(m.group(1)))}})
    # generic NSE script blocks (vulners, ssl-cert, ...) -> notes. http-title
    # is handled above; continuation lines (cpe:/...) are skipped.
    seen_scripts: set[str] = set()
    for m in _TEXT_SCRIPT_RE.finditer(text):
        name, first = m.group(1), m.group(2)
        if name in ("http-title", "http-title ", "fingerprint-strings"):
            continue
        if "/" in name or name in seen_scripts:
            continue
        seen_scripts.add(name)
        # collect the block: following indented "|" lines up to 500 chars
        start = m.end()
        block = [first]
        for lm in re.finditer(r"^\|\s*(.*)$", text[start:start + 2500], re.MULTILINE):
            line = lm.group(1).strip()
            if not line:
                break
            block.append(line)
            if len("\n".join(block)) > 500:
                break
        content = bounded("\n".join(block))
        vulnish = any(marker in content for marker in SCRIPT_VULN_MARKERS)
        facts.append({"fact_type": "note",
                      "value": {"tool": "nmap-script", "script": name,
                                "vulnerable": vulnish,
                                "output": _decode_escapes(content)}})
    # fingerprint-strings: identify the app from the RAW probe responses —
    # evidence-based (the output literally contains the app name). This is
    # what turns nmap's "ppp?" into "OWASP Juice Shop" without guessing.
    for fm in _TEXT_FPRINT_RE.finditer(text):
        block = fm.group(1)
        port = _sf_port_for(text, fm.start())
        if port is None:
            continue
        for sig, meta in _APP_SIGNATURES:
            if sig.lower() in block.lower():
                facts.append({"fact_type": "version",
                              "value": {"port": port,
                                        "service": meta["service"],
                                        "product": meta["product"]}})
                break
    return dedupe_facts(facts), warnings


def _sf_port_for(text: str, pos: int) -> int | None:
    """Port from the first 'SF-PortNNNN-TCP' marker after position pos."""
    m = _SF_PORT_RE.search(text, pos)
    return int(m.group(1)) if m else None


# Public alias: shared with the masscan extractor (masscan -oX emits the nmap
# XML dialect — same <host>/<port>/<state> element tree). Defined after
# _extract_xml so module import resolves it.
extract_xml = _extract_xml
