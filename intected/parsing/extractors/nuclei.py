"""nuclei extractor — JSONL (-jsonl) output.

Each line: {"template-id":..., "info":{"name":..., "severity":...,
"classification":{"cve-id":..., "cvss-score":...}}, "host":..., "url":...,
"matched-at":..., "type":...}
Facts: cve (when cve-id present) else note, with severity + cvss.
"""

import json

from .common import bounded, dedupe_facts


def extract(text: str):
    facts = []
    warnings = []
    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            warnings.append(f"nuclei line {lineno} is not JSON — skipped")
            continue
        if not isinstance(rec, dict):
            continue
        info = rec.get("info") or {}
        classification = info.get("classification") or {}
        cve_id = classification.get("cve-id")
        severity = info.get("severity", "unknown")
        value = {
            "template_id": rec.get("template-id", ""),
            "name": bounded(info.get("name", "")),
            "severity": bounded(severity),
            "url": bounded(rec.get("matched-at") or rec.get("url", "")),
            "type": rec.get("type", ""),
        }
        if cve_id:
            value["cve"] = bounded(cve_id)
            if classification.get("cvss-score") is not None:
                value["cvss"] = classification["cvss-score"]
            facts.append({"fact_type": "cve", "value": value})
        else:
            value["tags"] = bounded(",".join(info.get("tags") or []))
            facts.append({"fact_type": "note", "value": value})
    return dedupe_facts(facts), warnings
