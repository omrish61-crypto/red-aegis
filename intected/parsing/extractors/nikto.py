"""Nikto extractor — stdout.

Legacy format:
  + Server: Apache/2.4.25 (Debian)
  + /login.php: Admin login page/section found.
  + Target IP: 10.0.0.5
  - ERROR: ...

nikto 2.6.0 format (real capture 2026-08-10, DVWA):
  + [95] /: Cookie PHPSESSID created without the httponly flag. ...
  + [600050] Apache/2.4.25 appears to be outdated (current is at least 2.4.66).
  + ERROR: Host maximum execution time of 90 seconds reached
  -> [OSVDB-id] prefixes are stripped into nikto_osvdb; errors with either
     sign become warnings.
"""

import re

from .common import bounded, dedupe_facts

_SERVER_RE = re.compile(r"^\+\s*Server:\s*(.+)$", re.MULTILINE)
_OSVDB_RE = re.compile(r"^\+\s*\[(\d+)\]\s*(?:(.*?):\s*)?(.+)$", re.MULTILINE)
_FINDING_RE = re.compile(r"^\+\s*(\S+):\s*(.+)$", re.MULTILINE)
_TARGET_RE = re.compile(r"^\+\s*Target (?:IP|Hostname):\s*(.+)$", re.MULTILINE)
_ERROR_RE = re.compile(r"^[+-]\s*ERROR:\s*(.+)$", re.MULTILINE)
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
    for m in _OSVDB_RE.finditer(text):
        osvdb = m.group(1)
        target = (m.group(2) or "").strip()
        finding = m.group(3).strip()
        value = {"nikto_osvdb": osvdb, "finding": bounded(finding, 400)}
        if target.startswith("/"):
            value["path"] = bounded(target)
            facts.append({"fact_type": "path", "value": value})
        else:
            value["target"] = bounded(target or finding.split()[0])
            facts.append({"fact_type": "note", "value": value})
    for m in _FINDING_RE.finditer(text):
        target = m.group(1)
        finding = m.group(2).strip()
        # ERROR lines are handled by _ERROR_RE -> warnings only (avoid double count)
        if target.lower() in ("server", "error") or finding.lower().startswith("target "):
            continue
        if target.startswith("/"):
            facts.append({"fact_type": "path", "value": {"path": bounded(target),
                                                         "nikto": bounded(finding, 400)}})
        else:
            facts.append({"fact_type": "note",
                          "value": {"nikto": bounded(f"{target}: {finding}", 400)}})
    for m in _ERROR_RE.finditer(text):
        warnings.append(f"nikto: ERROR: {m.group(1)}")
    return dedupe_facts(facts), warnings
