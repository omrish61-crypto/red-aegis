"""WAF-bypass knowledge base (addendum section 8C) — honest lightweight RAG.

The spec calls for Pinecone/ChromaDB + LangChain document loaders + a weekly
web scrape. For a local single-user tool that is unjustified infrastructure
(the architecture review rejects it); this module provides the same SERVICE —
retrieval of WAF-bypass knowledge as context — with a local markdown KB and
token-overlap retrieval (no vector DB, no LangChain, no external services).

The KB lives at <state>/waf-kb/*.md. A maintenance command
(`intected waf-kb update`) pulls curated sources (docs URLs the operator
chooses) — the planner queries it BEFORE building WAF-aware payloads, so the
LLM never fabricates "latest bypass techniques" from memory.
"""

import os
import re

from . import config


def kb_dir() -> str:
    d = os.path.join(config.state_dir(), "waf-kb")
    os.makedirs(d, exist_ok=True)
    return d


def _docs() -> list[tuple[str, str]]:
    """(doc_name, text) pairs from the KB directory."""
    docs = []
    for name in sorted(os.listdir(kb_dir())):
        if name.endswith(".md"):
            with open(os.path.join(kb_dir(), name), encoding="utf-8",
                      errors="replace") as f:
                docs.append((name, f.read()))
    return docs


def _tokens(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9_-]{3,}", text.lower()))


def query(question: str, top_k: int = 3) -> list[dict]:
    """Retrieve KB passages relevant to the question (token-overlap scoring)."""
    q_tokens = _tokens(question)
    scored = []
    for name, text in _docs():
        t = _tokens(text)
        score = len(q_tokens & t) / max(len(q_tokens), 1)
        if score > 0:
            scored.append((score, name, text))
    scored.sort(key=lambda x: x[0], reverse=True)
    results = []
    for score, name, text in scored[:top_k]:
        # return the most relevant window (first 1200 chars)
        results.append({"doc": name, "score": round(score, 2),
                        "passage": text[:1200]})
    return results


def seed_example() -> str:
    """Write the starter KB doc (sources the operator can extend)."""
    path = os.path.join(kb_dir(), "cloudflare-basics.md")
    if os.path.exists(path):
        return path
    content = """# Cloudflare WAF — bypass basics (seeded 2026-08-11)

Source guidance: extend from PortSwigger / HackTricks / official Cloudflare
docs. The AI uses ONLY what is in this KB — never memory.

## Behavioral notes
- Cloudflare blocks by IP reputation, JA3 fingerprint, and rate.
- Direct-to-origin probing: if the origin IP is known (DNS history), test
  the origin host header against the edge.
- Rate limits: stay under ~10 req/s per IP; vary User-Agent.
- Common bypass vectors (validate each against the live target):
  - non-standard HTTP methods on edge-cached paths
  - path normalization differences (/api vs /api/)
  - JSON content-type switches for WAF-parsed body rules
  - oversized bodies / chunked encoding where parsing diverges
- sqlmap: use --random-agent and a delay >= 2s when a WAF is present.
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


def summary() -> dict:
    return {"docs": [n for n, _ in _docs()], "dir": kb_dir()}
