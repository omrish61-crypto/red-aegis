"""Configuration: LLM routing table with LIVE measured latencies (2026-08-10).

Routing rules:
- Interactive reasoning  -> deepseek-v4-flash via bridge :11435 (measured 0.9s)
- Light/offline tasks    -> local Ollama models via bridge :11435 (15-53s, async only)
- deepseek-r1:8b         -> Ollama DIRECT :11434. The bridge 400s on this name
                           (bridge routes any `deepseek-*` to the cloud provider).

Latencies measured with an 8-token completion on 2026-08-10:
  deepseek-v4-flash   0.9s   llama3.2:latest 17.3s   gemma3:4b 15.1s
  qwen2.5-coder:7b   25.7s   deepseek-r1:8b  52.6s (direct :11434)
"""

import os

# --- State directory -------------------------------------------------------
STATE_DIR = os.environ.get("INTECTED_STATE", os.path.expanduser("~/.intected"))
DB_PATH = os.path.join(STATE_DIR, "intected.db")
EVIDENCE_DIR = os.path.join(STATE_DIR, "evidence")


def state_dir() -> str:
    """Resolve the state dir at CALL time (env changes respected).

    STATE_DIR/DB_PATH above bind at import (fast paths); code that must honor
    a runtime INTECTED_STATE override (CLI commands, secrets vault) uses this.
    """
    return os.environ.get("INTECTED_STATE") or STATE_DIR


def db_path() -> str:
    return os.path.join(state_dir(), "intected.db")

BRIDGE_URL = os.environ.get(
    "REDAEGIS_BRIDGE_URL", "http://127.0.0.1:11435/v1"
)   # LiteLLM: deepseek-v4-* + local models (Docker default: http://bridge:4000/v1)
OLLAMA_URL = "http://127.0.0.1:11434/v1"   # direct Ollama (deepseek-r1:8b etc.)

# pentest-core production DB (P4 integration). Override per host with
# INTECTED_PENTEST_CORE_DB (e.g. a WSL path via \\wsl$ or a backup copy).
PENTEST_CORE_DB = os.environ.get(
    "INTECTED_PENTEST_CORE_DB",
    os.path.expanduser("~/.pentest-core/pentest.db"),
)

# Task-class -> route. `fallback` is used when the primary route fails/times out
# (local -> flash; flash has no fallback).
ROUTES = {
    "reasoning": {
        "model": "deepseek-v4-flash",
        "base_url": BRIDGE_URL,
        "async": False,
        # heavy thinking phase (4800-5200 chars measured) -> needs headroom
        "timeout": 300,
        "fallback": None,
        "latency_s": 0.9,
        # strict-JSON task: low temperature measurably improves schema
        # compliance (verified live 2026-08-10 — default temp drifted to
        # prose on complex digests; temp 0.0 returns schema-exact JSON).
        "temperature": 0.0,
    },
    "light": {
        "model": "llama3.2:latest",
        "base_url": BRIDGE_URL,
        "async": True,
        "timeout": 120,
        "fallback": "reasoning",
        "latency_s": 17.3,
    },
    "extract_small": {
        "model": "gemma3:4b",
        "base_url": BRIDGE_URL,
        "async": True,
        "timeout": 120,
        "fallback": "reasoning",
        "latency_s": 15.1,
    },
    "code": {
        "model": "qwen2.5-coder:7b",
        "base_url": BRIDGE_URL,
        "async": True,
        "timeout": 150,
        "fallback": "reasoning",
        "latency_s": 25.7,
    },
    # PITFALL FIX: bridge 400s on deepseek-r1:8b (name collision with cloud
    # deepseek-*). This route MUST point at direct Ollama, never the bridge.
    "deep_reasoning": {
        "model": "deepseek-r1:8b",
        "base_url": OLLAMA_URL,
        "async": True,
        "timeout": 300,
        "fallback": "reasoning",
        "latency_s": 52.6,
    },
    "embeddings": {
        "model": "nomic-embed-text",
        "base_url": OLLAMA_URL,
        "async": True,
        "timeout": 60,
        "fallback": "reasoning",
        "latency_s": None,  # not benchmarked; used from P3
    },
}

DEFAULT_ROUTE = "reasoning"


def route(task_class: str) -> dict:
    """Resolve a task class to its route config (raises KeyError if unknown)."""
    if task_class not in ROUTES:
        raise KeyError(f"unknown task class: {task_class!r} (known: {sorted(ROUTES)})")
    return dict(ROUTES[task_class])
