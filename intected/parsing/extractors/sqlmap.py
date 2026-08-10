"""sqlmap extractor — stdout logs.

Key evidence patterns:
  [INFO] GET parameter 'id' appears to be '...' injectable
  [INFO] GET parameter 'id' is '...' injectable
  [INFO] testing if GET parameter 'id' is dynamic
  [WARNING] GET parameter 'id' does not appear to be dynamic
  Parameter: id (GET)        <- from the final summary
      Type: boolean-based blind
      Title: ...
      Payload: ...
  [INFO] the back-end DBMS is 'MySQL'
  [INFO] heuristics shows that GET parameter 'id' might be vulnerable to XSS
  web server operating system: ...
  web application technology: ...
"""

import re

from .common import bounded, dedupe_facts, note

_INJECT_RE = re.compile(
    r"(GET|POST|Cookie|User-Agent|Referer) parameter '([^']+)' (?:appears to be|is) "
    r"'([^']+)' injectable"
)
_DYNAMIC_RE = re.compile(r"parameter '([^']+)' does not appear to be dynamic")
_XSS_RE = re.compile(r"parameter '([^']+)' might be vulnerable to cross-site scripting")
_DBMS_RE = re.compile(
    r"back-end DBMS (?:is )?'?([A-Za-z0-9.]+)|back-end DBMS:\s*([A-Za-z0-9.]+)"
)
_TECH_RE = re.compile(r"^(web application technology|web server operating system):\s*(.+)$",
                      re.MULTILINE)
_PARAM_BLOCK_RE = re.compile(
    r"Parameter:\s*([^\s]+)\s*\((\w+)\)(?:\s*\((\w+)\))?"
)
_PAYLOAD_RE = re.compile(r"Payload:\s*(.+)$", re.MULTILINE)


def extract(text: str):
    facts = []
    warnings = []
    injectable_params = {}
    for m in _INJECT_RE.finditer(text):
        injectable_params[m.group(2)] = m.group(3)
    for name, kind in injectable_params.items():
        facts.append({"fact_type": "param",
                      "value": {"param": name, "injectable": True, "type": kind}})
    for m in _DYNAMIC_RE.finditer(text):
        facts.append({"fact_type": "param",
                      "value": {"param": m.group(1), "dynamic": False}})
    for m in _XSS_RE.finditer(text):
        facts.append({"fact_type": "note",
                      "value": {"param": m.group(1), "xss": True,
                                "text": "heuristic XSS indication"}})
    dbms = _DBMS_RE.search(text)
    if dbms:
        facts.append({"fact_type": "note",
                      "value": {"dbms": dbms.group(1) or dbms.group(2)}})
    for m in _TECH_RE.finditer(text):
        facts.append({"fact_type": "note",
                      "value": {m.group(1): bounded(m.group(2))}})
    # final summary block: Parameter / Type / Title / Payload
    for pm in _PARAM_BLOCK_RE.finditer(text):
        name = pm.group(1)
        if name not in injectable_params:
            facts.append({"fact_type": "param", "value": {"param": name}})
    payloads = _PAYLOAD_RE.findall(text)
    for p in payloads[:10]:
        facts.append({"fact_type": "note",
                      "value": {"payload": bounded(p, 500)}})
    # not-injectable honesty: keep the negative result as a note, don't hide it
    if "isn't injectable" in text or "not injectable" in text:
        facts.append({"fact_type": "note",
                      "value": {"text": "sqlmap: target not injectable"}})
    return dedupe_facts(facts), warnings
