"""LLM router — latency-aware model routing with async job queue and fallback.

- Interactive task classes hit `deepseek-v4-flash` (bridge :11435, ~0.9s).
- Local classes (light / extract_small / code / deep_reasoning / embeddings) run
  ASYNC through a job queue (15-53s measured) and fall back to `reasoning`
  (flash) on timeout/HTTP error.
- PITFALL FIX: `deep_reasoning` (deepseek-r1:8b) is hard-routed to DIRECT Ollama
  :11434 — the bridge returns HTTP 400 for any `deepseek-*` model name.
"""

import json
import time
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor

from . import config

__all__ = ["Router", "LocalJobQueue", "chat", "router_check", "RouteError"]


class RouteError(RuntimeError):
    """Raised when a route and its fallback both fail."""


def _post_json(url: str, payload: dict, timeout: float) -> dict:
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def _extract_text(resp: dict) -> str:
    """Extract assistant text; for reasoning models fall back to reasoning_content."""
    try:
        msg = resp["choices"][0]["message"]
    except (KeyError, IndexError) as exc:
        raise RouteError(f"unexpected completion shape: {resp!r}") from exc
    content = msg.get("content") or ""
    if content.strip():
        return content
    return msg.get("reasoning_content") or ""


class Router:
    """Stateless router: resolve task class -> (url, model), call, fall back."""

    def __init__(self, routes: dict | None = None):
        self._routes = routes if routes is not None else config.ROUTES
        # Normalize: replace base_url placeholders with live config values
        self._routes = {
            cls: dict(r, base_url=r["base_url"])
            for cls, r in self._routes.items()
        }

    def resolve(self, task_class: str) -> dict:
        if task_class not in self._routes:
            raise KeyError(
                f"unknown task class {task_class!r}; known: {sorted(self._routes)}"
            )
        return dict(self._routes[task_class])

    def chat(self, task_class: str, messages: list[dict], max_tokens: int = 512,
             timeout: float | None = None, _post=None) -> str:
        """Call the route for task_class; on failure, walk the fallback chain."""
        route = self.resolve(task_class)
        post = _post or _post_json
        last_err: Exception | None = None
        while route is not None:
            url = f"{route['base_url'].rstrip('/')}/chat/completions"
            payload = {
                "model": route["model"],
                "messages": messages,
                "max_tokens": max_tokens,
                "stream": False,
            }
            try:
                resp = post(url, payload, timeout or route["timeout"])
                return _extract_text(resp)
            except (urllib.error.URLError, TimeoutError, RouteError, OSError) as exc:
                last_err = exc
                fb = route.get("fallback")
                if fb is None:
                    break
                route = self.resolve(fb)
        raise RouteError(
            f"route {task_class!r} and all fallbacks failed: {last_err}"
        ) from last_err


class LocalJobQueue:
    """Async queue for slow local models. Never blocks the interactive loop."""

    def __init__(self, router: Router | None = None, max_workers: int = 2):
        self._router = router or Router()
        self._pool = ThreadPoolExecutor(max_workers=max_workers)
        self._jobs: dict[str, dict] = {}

    def submit(self, task_class: str, messages: list[dict], max_tokens: int = 512,
               timeout: float | None = None) -> str:
        job_id = uuid.uuid4().hex[:12]
        self._jobs[job_id] = {"status": "queued", "result": None, "error": None,
                              "task_class": task_class, "started": None}
        self._pool.submit(self._run, job_id, task_class, messages, max_tokens, timeout)
        return job_id

    def _run(self, job_id, task_class, messages, max_tokens, timeout):
        self._jobs[job_id]["status"] = "running"
        self._jobs[job_id]["started"] = time.time()
        try:
            result = self._router.chat(task_class, messages, max_tokens, timeout)
            self._jobs[job_id]["result"] = result
            self._jobs[job_id]["status"] = "done"
        except Exception as exc:  # noqa: BLE001 — job must never kill the queue
            self._jobs[job_id]["error"] = str(exc)
            self._jobs[job_id]["status"] = "error"

    def poll(self, job_id: str) -> dict:
        job = self._jobs.get(job_id)
        if job is None:
            raise KeyError(f"unknown job {job_id!r}")
        out = dict(job)
        if out.get("started"):
            out["elapsed_s"] = round(time.time() - out["started"], 1)
        return out


def chat(task_class: str, messages: list[dict], max_tokens: int = 512,
         timeout: float | None = None) -> str:
    """Module-level convenience: one-off synchronous call through the router."""
    return Router().chat(task_class, messages, max_tokens, timeout)


def router_check() -> list[dict]:
    """Live latency probe of every route (G1 evidence tool).

    Returns [{"task_class", "model", "ok", "latency_s", "detail"}] — measured,
    never guessed.
    """
    router = Router()
    rows = []
    for task_class, route in config.ROUTES.items():
        probe = {"task_class": task_class, "model": route["model"], "ok": False,
                 "latency_s": None, "detail": ""}
        try:
            t0 = time.time()
            router.chat(task_class, [{"role": "user", "content": "Say OK"}],
                        max_tokens=8, timeout=min(route["timeout"], 90))
            probe["latency_s"] = round(time.time() - t0, 1)
            probe["ok"] = True
        except Exception as exc:  # noqa: BLE001 — report, don't raise
            probe["detail"] = f"{type(exc).__name__}: {exc}"
        rows.append(probe)
    return rows
