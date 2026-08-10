"""ffuf extractor — -json output (one JSON object per line).

Sample line:
  {"input":{"FUZZ":"admin"},"position":1,"status":301,"length":312,
   "words":18,"lines":6,"url":"http://host/FUZZ","redirectlocation":"http://host/admin/"}
"""

import json

from .common import dedupe_facts, path_fact


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
            warnings.append(f"ffuf line {lineno} is not JSON — skipped")
            continue
        if not isinstance(rec, dict):
            warnings.append(f"ffuf line {lineno} is not an object — skipped")
            continue
        url = rec.get("url")
        if not url:
            continue
        # substitute FUZZ placeholder with the actual input for a concrete path
        fuzz = rec.get("input") or {}
        concrete = url
        for k, v in fuzz.items():
            concrete = concrete.replace(k, str(v)) if isinstance(k, str) else concrete
        facts.append(path_fact(
            concrete,
            status=int(rec["status"]) if rec.get("status") is not None else None,
            size=int(rec["length"]) if rec.get("length") is not None else None,
            redirect=rec.get("redirectlocation"),
        ))
    return dedupe_facts(facts), warnings
