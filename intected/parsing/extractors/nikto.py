"""Nikto extractor — stdout.

Sample lines:
  + Server: Apache/2.4.25 (Debian)
  + /login.php: Admin login page/section found.
  + Target IP: 10.0.0.5
  - ERROR: ...
  + /: HTTP method 'DELETE' may indicate a potential vulnerability
"""

import re

from .common import bounded, dedupe_facts, note

_SERVER_RE = re.compile(r"^\+\s*Server:\s*(.+)$", re.MULTILINE)
_FINDING_RE = re.compile(r"^\+\s*(\S+):\s*(.+)$", re.MULTILINE)
_TARGET_RE = re.compile(r"^\+\s*Target (?:IP|Hostname):\s*(.+)$", re.MULTILINE)
_ERROR_RE = re.compile(r"^-\s*(ERROR.*)$", re.MULTILINE)
_INFO_RE = re.compile(r"^-\s*(.+)$", re.MULTILINE)


def extract(text: str):
    facts = []
    warnings = []
    m = _SERVER_RE.search(text)
    if m:
        server = m.group(1).strip()
        facts.append({"fact_type": "version",
                      "value": {"product": "http-server", "banner": bounded(server)}})
    for m in _TARGET_RE.finditer(text):
        facts.append({"fact_type": "note",
                      "value": {"nikto_target": bounded(m.group(1))}})
    for m in _FINDING_RE.finditer(text):
        target = m.group(1)
        finding = m.group(2).strip()
        if target.lower() in ("server",) or finding.lower().startswith("target "):
            continue
        if target.startswith("/"):
            facts.append({"fact_type": "path", "value": {"path": bounded(target),
                                                         "nikto": bounded(finding, 400)}})
        else:
            facts.append({"fact_type": "note",
                          "value": {"nikto": bounded(f"{target}: {finding}", 400)}})
    for m in _ERROR_RE.finditer(text):
        warnings.append(f"nikto: {m.group(1)}")
    return dedupe_facts(facts), warnings
