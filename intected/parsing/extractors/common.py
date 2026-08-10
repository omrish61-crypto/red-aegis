"""Shared helpers for extractors."""

MAX_VALUE_CHARS = 2000  # per-fact value truncation (protects LLM context)


def bounded(value, limit: int = MAX_VALUE_CHARS) -> str:
    s = str(value)
    return s if len(s) <= limit else s[:limit] + "…"


def dedupe_facts(facts: list[dict]) -> list[dict]:
    """Dedupe by (fact_type, canonical value) — keep first occurrence."""
    seen: set[tuple] = set()
    out = []
    for f in facts:
        key = (f["fact_type"], str(sorted(f["value"].items())))
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def note(text: str, confidence: float = 1.0) -> dict:
    return {"fact_type": "note", "value": {"text": bounded(text)}, "confidence": confidence}


def path_fact(url_or_path: str, status: int | None = None, size: int | None = None,
              redirect: str | None = None, confidence: float = 1.0) -> dict:
    value = {"path": bounded(url_or_path)}
    if status is not None:
        value["status"] = status
    if size is not None:
        value["size"] = size
    if redirect is not None:
        value["redirect"] = bounded(redirect)
    return {"fact_type": "path", "value": value, "confidence": confidence}
