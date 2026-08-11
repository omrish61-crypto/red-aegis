"""Live CVE integration — NIST NVD API v2 (spec: never rely on LLM memory).

The planner's "Infrastructure hardening" / version-correlation steps query the
NVD at execution time for CPE strings extracted from scan evidence. Results
are cached in-memory (NVD rate limits: ~5 req/30s anonymous, 50 with key) so
repeated lookups don't hammer the API. Network failures are honest: the caller
sees 'nvd_unavailable' — no invented CVEs.

Only CPE strings that came from real tool output may be looked up (the
anti-hallucination rule: no version, no lookup).
"""

import json
import time
import urllib.parse
import urllib.request

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_cache: dict[str, dict] = {}
_last_call = 0.0
_MIN_INTERVAL = 7.0  # stay well under the anonymous 5/30s limit


def _throttle() -> None:
    global _last_call
    wait = _MIN_INTERVAL - (time.time() - _last_call)
    if wait > 0:
        time.sleep(wait)
    _last_call = time.time()


def lookup_cpe(cpe: str, api_key: str | None = None) -> dict:
    """Query NVD for CVEs matching a CPE string. Cached. Returns:
    {'cves': [{'id','severity','score','published','description'}...],
     'source': 'nvd'|'cache', 'count': N} or raises LookupError on failure.
    """
    if cpe in _cache:
        return {** _cache[cpe], "source": "cache"}
    _throttle()
    params = urllib.parse.urlencode({"cpeName": cpe, "resultsPerPage": 10})
    req = urllib.request.Request(f"{NVD_API}?{params}")
    if api_key:
        req.add_header("apiKey", api_key)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        raise LookupError(f"nvd_unavailable: {exc}") from exc
    cves = []
    for item in data.get("vulnerabilities", []):
        c = item.get("cve", {})
        metrics = (c.get("metrics", {}).get("cvssMetricV31") or
                   c.get("metrics", {}).get("cvssMetricV2") or [])
        severity = (metrics[0].get("baseSeverity")
                    if metrics else "unknown")
        score = (metrics[0].get("cvssData", {}).get("baseScore")
                 if metrics else None)
        cves.append({
            "id": c.get("id"),
            "severity": severity,
            "score": score,
            "published": (c.get("published") or "")[:10],
            "description": ((c.get("descriptions") or [{}])[0]
                            .get("value", "")[:160]),
        })
    result = {"cves": cves, "source": "nvd", "count": len(cves)}
    _cache[cpe] = result
    return result


def cpe_from_banner(banner: str) -> str | None:
    """Best-effort CPE 2.3 from a banner ("Apache httpd 2.4.7" ->
    cpe:2.3:a:apache:httpd:2.4.7:*:*:*:*:*:*:*). Uses the banner's OWN tokens —
    honest, no guessing beyond the string. Returns None when no
    product/version pair exists (then no NVD lookup happens at all)."""
    m = __import__("re").search(
        r"([A-Za-z][A-Za-z0-9_-]*)(?:\s+([A-Za-z0-9._-]+))?\s+"
        r"([0-9]+(?:\.[0-9]+){1,3})", banner)
    if not m:
        return None
    vendor, name, version = m.group(1).lower(), m.group(2), m.group(3)
    product = name.lower() if name else vendor
    # curated aliases for the NVD CPE dictionary (documented, not guessed)
    product = {"httpd": "http_server"}.get(product, product)
    return (f"cpe:2.3:a:{vendor}:{product}:{version}"
            f":*:*:*:*:*:*:*")
