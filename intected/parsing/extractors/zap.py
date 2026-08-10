"""ZAP baseline extractor — zap-baseline.txt style report.

Lines:  PASS|WARN|FAIL: <name> [<rule-id>]
Header: Total of N URLs
Footer: Alert Summary section with per-rule counts.
"""

import re

from .common import bounded, dedupe_facts, note

_ALERT_RE = re.compile(
    r"^\s*(PASS|WARN|FAIL):\s*(.+?)\s*\[(\d+)\]\s*$"
)
_SUMMARY_RE = re.compile(r"^([\d\s]+)\|(.+?)\|(.+?)\|(Low|Medium|High|Informational)?\s*$")


def extract(text: str):
    facts = []
    warnings = []
    total = None
    m_total = re.search(r"Total of (\d+) URLs", text)
    if m_total:
        total = int(m_total.group(1))
        facts.append({"fact_type": "note",
                      "value": {"zap_total_urls": total}})
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        m = _ALERT_RE.match(line)
        if m:
            level, name, rule_id = m.group(1), m.group(2).strip(), m.group(3)
            facts.append({"fact_type": "note",
                          "value": {"zap_rule": rule_id, "level": level,
                                    "name": bounded(name)}})
            continue
        m = _SUMMARY_RE.match(line)
        if m and m.group(3).strip():
            facts.append({"fact_type": "note",
                          "value": {"zap_summary": bounded(m.group(2).strip()),
                                    "count": m.group(1).strip()}})
    return dedupe_facts(facts), warnings
