"""
M3 — AI-Assisted Enrichment
=============================
This is the existing ai_analyzer/app.py logic, refactored from a
run-once script into importable functions so the dashboard can call it
per job instead of duplicating the integration.

Preserved exactly from the original:
- Same provider/SDK: google-genai, model "gemini-flash-lite-latest"
- Same prompt template (bank security analyst framing)
- Same output schema: cve_id, explanation, banking_context_risk,
  priority_tier, remediation
- Same "strip markdown fences before json.loads" parsing guard

CHANGED FROM THE ORIGINAL (perf + reliability fixes):
- Findings are now enriched concurrently (thread pool) instead of one
  at a time
- Every call is gated by a shared sliding-window rate limiter tuned to
  the free tier's actual 15-requests/minute cap, so concurrent workers
  can't collectively blow past it (this was the cause of most
  "AI Priority: Failed" rows — RESOURCE_EXHAUSTED isn't only the 500/day
  cap; there's a separate, much tighter 15/minute cap too)
- On a 429 that does still happen, the wait uses Gemini's own reported
  retryDelay when present instead of guessing with fixed backoff
- A 429 that's specifically the *daily* 500-request cap short-circuits
  the rest of the batch immediately (that one can't be waited out)
- Already-enriched (cve, package, version) combos are cached to disk
  across runs/jobs, so repeat scans of the same CVEs don't re-spend
  quota at all
- The flat 4s pacing delay after every call is now a small per-worker
  cushion on top of the rate limiter, not the primary throttle

PERFORMANCE NOTE:
The original loop called Gemini strictly one finding at a time and
slept 4s after every call regardless of outcome, plus 60s on every
rate-limit retry (up to 3 attempts). For ~50 findings that's several
minutes of pure sleep even with zero errors, and it snowballs fast
if the API throttles you at all. This version fans calls out across
a small thread pool (default 3 workers) with a short per-call delay
per worker and real exponential backoff on retries, which cuts a
~50-finding run from minutes to well under a minute in the common
case while still being polite to the API.

NOTE ON A PROJECT-BRIEF CONFLICT:
The project brief this dashboard was built against describes M3 as a
Claude API integration. The actual, working M3 code uses Google's
Gemini API instead (GEMINI_API_KEY / google-genai). There is no Claude
integration anywhere in the uploaded project. Per "preserve existing
functionality, don't duplicate the integration," this module keeps
Gemini rather than silently swapping providers. If you actually want
Claude, that's a deliberate follow-up change, not a silent one.

The API key is never hardcoded and never sent to the frontend — it is
loaded once from environment variables (.env) at process start, same
as the original script.
"""

import json
import os
import random
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from dotenv import load_dotenv

_client = None
_load_attempted = False
_client_lock = threading.Lock()

# Tunables for the concurrent enrichment pass.
# Lowered from 6 -> 3: worker *count* barely matters now that _RateLimiter
# below gates every call against the free tier's actual 15-requests/minute
# cap directly — see RPM_LIMIT. 3 just keeps a little concurrency for
# non-network work (JSON parsing, cache lookups) between gated calls.
DEFAULT_MAX_WORKERS = 3
MIN_CALL_INTERVAL = 0.5      # small extra per-worker cushion after its own call
MAX_RETRIES = 3              # unchanged from the original
BASE_BACKOFF = 5.0           # seconds — first retry wait, before jitter, when
                             # the API doesn't tell us how long to wait
MAX_BACKOFF = 65.0           # seconds — retry wait never exceeds this (the
                             # observed per-minute retryDelay maxes out
                             # under 60s, so this gives it headroom)
CALL_TIMEOUT_MS = 30_000     # per-request timeout, so a hung connection
                             # fails fast instead of stalling a worker forever

# Free tier for gemini-3.5-flash-lite: 15 requests per minute (this is
# separate from, and much tighter than, the 500/day cap — see
# _quota_scope()). A small safety margin keeps threads from all landing on
# the 15th slot at once and tipping over from clock-skew/timing alone.
RPM_LIMIT = 15
RPM_SAFETY_MARGIN = 2
EFFECTIVE_RPM_LIMIT = max(1, RPM_LIMIT - RPM_SAFETY_MARGIN)

# Regex for Gemini's own "retry in Ns" guidance, e.g. `'retryDelay': '48s'`
# or "Please retry in 48.592484937s.". Trusting the API's own number beats
# guessing with a fixed exponential backoff — it already told us exactly
# how long until the per-minute window clears.
_RETRY_DELAY_RE = re.compile(r"retry(?:Delay)?['\"]?\s*(?:in|[:=])\s*['\"]?(\d+(?:\.\d+)?)s")


class _RateLimiter:
    """Shared, thread-safe sliding-window limiter. Blocks callers until
    issuing another call would stay under `limit` calls per `window`
    seconds, no matter how many worker threads are trying to call at once.
    This is what actually prevents the 15/min free-tier cap from being hit
    in the first place — per-worker pacing (MIN_CALL_INTERVAL) can't do
    that because workers don't coordinate with each other."""

    def __init__(self, limit: int, window: float = 60.0):
        self.limit = limit
        self.window = window
        self._lock = threading.Lock()
        self._timestamps: list[float] = []

    def acquire(self) -> None:
        while True:
            with self._lock:
                now = time.monotonic()
                cutoff = now - self.window
                self._timestamps = [t for t in self._timestamps if t > cutoff]
                if len(self._timestamps) < self.limit:
                    self._timestamps.append(now)
                    return
                wait_for = self._timestamps[0] + self.window - now + 0.1
            time.sleep(max(wait_for, 0.1))


_rate_limiter = _RateLimiter(EFFECTIVE_RPM_LIMIT)

# Cross-run, cross-job cache. Findings are keyed by (cve, package, version),
# and the same CVEs show up over and over across scans of related projects
# (lodash/axios/minimist CVEs in particular). Without this, every re-scan
# re-spends quota re-explaining a CVE Gemini already explained yesterday.
# This is the main fix for "quota exhausted" in practice: it stops the tool
# from burning through the 500/day free-tier cap on repeat work.
_CACHE_PATH = Path(__file__).resolve().parent.parent / "data" / "ai_cache.json"
_cache_lock = threading.Lock()

# Once a call comes back as a *daily* quota exhaustion, every other finding
# in this run will fail the exact same way — the cap resets by day, not by
# waiting a few seconds. Retrying each of the remaining findings 3x with
# backoff just burns ~5-10 minutes proving that 46 more times. This flag,
# once set, makes the rest of the batch fail fast instead.
_daily_quota_exhausted = threading.Event()


class AIEnrichmentError(Exception):
    """Raised when the API key is missing or the client can't be built."""


def _parse_retry_delay(exc) -> float | None:
    """Pull the number of seconds Gemini told us to wait out of the error
    text, if present (e.g. the per-minute RPM 429 includes retryDelay/
    "Please retry in Ns"). None if not found."""
    match = _RETRY_DELAY_RE.search(str(exc))
    return float(match.group(1)) if match else None


def _quota_scope(exc) -> str | None:
    """Return 'day' if this 429 is the per-day free-tier cap, 'rate' if it's
    a short-lived per-minute/RPM throttle, or None if it's not a quota error
    at all. The two look identical at a glance (both RESOURCE_EXHAUSTED) but
    need very different handling: a 'day' error can't be fixed by retrying
    in this run at all; a 'rate' error usually clears within a minute."""
    text = str(exc)
    if "RESOURCE_EXHAUSTED" not in text and "429" not in text:
        return None
    if "PerDay" in text or "GenerateRequestsPerDayPerProjectPerModel" in text:
        return "day"
    if "RESOURCE_EXHAUSTED" in text:
        return "rate"
    return None


def _load_cache() -> dict:
    if not _CACHE_PATH.exists():
        return {}
    try:
        with open(_CACHE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _save_cache(cache: dict) -> None:
    _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(_CACHE_PATH, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2)


def _cache_key(vuln: dict) -> str:
    return f"{vuln.get('cve')}|{vuln.get('package')}|{vuln.get('version')}"


def _get_client():
    """Lazily build the Gemini client so a missing API key doesn't crash
    the whole app at import time — only when a scan actually runs.
    Lock-guarded since multiple worker threads may call this at once."""
    global _client, _load_attempted
    if _client is not None:
        return _client
    with _client_lock:
        if _client is not None:
            return _client
        if not _load_attempted:
            load_dotenv()
            _load_attempted = True

        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise AIEnrichmentError(
                "GEMINI_API_KEY is not set. Add it to a .env file in the "
                "project root (see .env.example) — never hardcode it."
            )

        from google import genai
        from google.genai import types
        # Without an explicit timeout, a stalled/blocked network call can hang
        # a worker thread forever — that's how a job gets stuck at
        # ai_progress {"done": 0, "total": N} indefinitely instead of failing
        # fast and moving on.
        _client = genai.Client(
            api_key=api_key,
            http_options=types.HttpOptions(timeout=CALL_TIMEOUT_MS),
        )
        return _client


def build_prompt(vuln: dict) -> str:
    """Unchanged from ai_analyzer/app.py."""
    cvss_display = vuln["cvss"] if vuln.get("cvss") is not None else "Not scored"
    return f"""You are a security analyst assistant for a bank.
Analyze this vulnerability and respond with ONLY a JSON object (no markdown, no extra text).

Vulnerability:
CVE ID: {vuln['cve']}
Package: {vuln['package']} version {vuln['version']}
Severity: {vuln['severity']} (CVSS {cvss_display})
Description: {vuln['description']}

Respond with exactly this JSON structure:
{{
  "cve_id": "{vuln['cve']}",
  "explanation": "plain-language explanation for a bank executive",
  "banking_context_risk": "how this affects a bank's systems or customer data",
  "priority_tier": "one of: Low, Medium, High, Critical. Base this strictly on CVSS: 0.0-3.9=Low, 4.0-6.9=Medium, 7.0-8.9=High, 9.0-10.0=Critical. If not scored, use your judgment.",
  "remediation": "specific steps to fix this"
}}"""


def call_gemini(prompt: str) -> str | None:
    """
    Same 3-attempt retry count as the original. Every attempt is gated by
    the shared _rate_limiter so concurrent workers can't collectively blow
    past the free tier's 15-requests/minute cap. If a 429 still slips
    through (e.g. another process shares the same API key), the wait uses
    Gemini's own reported retryDelay when present, falling back to
    exponential backoff with jitter otherwise.
    """
    from google.genai import errors

    if _daily_quota_exhausted.is_set():
        # Already confirmed the day's cap is spent earlier in this batch —
        # don't spend another 3-attempt retry cycle proving it again for
        # every remaining finding.
        return None

    client = _get_client()
    backoff = BASE_BACKOFF
    for attempt in range(MAX_RETRIES):
        _rate_limiter.acquire()  # blocks here, not inside the except branch,
                                 # so we never even fire the call that would
                                 # trip the per-minute cap
        try:
            response = client.models.generate_content(
                model="gemini-flash-lite-latest",
                contents=prompt,
            )
            return response.text.strip()
        except errors.ClientError as exc:
            # e.g. 401/403 (bad/rotated API key), 404 (bad model name),
            # 429 (quota/rate limit). Printed so it shows up in the
            # terminal running `python app.py` instead of silently
            # becoming "Pending"/"Failed" with zero explanation.
            print(f"[m3_enrich] Gemini call failed (attempt {attempt + 1}/{MAX_RETRIES}): {exc}")
            scope = _quota_scope(exc)
            if scope == "day":
                # The 500/day free-tier cap is gone for today. Retrying
                # within this run cannot succeed — stop immediately instead
                # of doing 2 more doomed attempts, and tell every other
                # in-flight/pending worker to stop trying too.
                _daily_quota_exhausted.set()
                break
            if attempt == MAX_RETRIES - 1:
                break
            if scope == "rate":
                # Trust Gemini's own retryDelay over our guess — it already
                # told us exactly when the per-minute window clears.
                wait = _parse_retry_delay(exc) or backoff
            else:
                wait = backoff
            time.sleep(min(wait, MAX_BACKOFF) + random.uniform(0, 1))
            backoff *= 2
        except Exception as exc:  # noqa: BLE001 — e.g. a connection timeout.
            # Anything else (timeouts, DNS failures, etc.) is caught here too
            # so a single stalled call can't hang or crash the whole worker
            # pool — it just counts as a failed item and the batch moves on.
            print(f"[m3_enrich] Gemini call errored (attempt {attempt + 1}/{MAX_RETRIES}): {exc}")
            if attempt == MAX_RETRIES - 1:
                break
            time.sleep(min(backoff, MAX_BACKOFF) + random.uniform(0, 1))
            backoff *= 2
    return None


def _enrich_one(vuln: dict, cache: dict) -> tuple[dict | None, bool, bool]:
    """Call Gemini for a single finding and parse its response, checking the
    on-disk cache first. Returns (parsed_result_or_None, ok, came_from_cache)."""
    key = _cache_key(vuln)
    cached = cache.get(key)
    if cached is not None:
        return cached, True, True

    raw_text = call_gemini(build_prompt(vuln))
    if raw_text is None:
        return None, False, False

    if raw_text.startswith("```"):
        raw_text = raw_text.strip("`").replace("json\n", "", 1)
    try:
        parsed = json.loads(raw_text)
        return parsed, True, False
    except json.JSONDecodeError:
        return None, False, False  # malformed response for this item — skip, keep going


def enrich_findings(
    findings: list,
    output_path: str | None = None,
    on_progress=None,
    max_workers: int = DEFAULT_MAX_WORKERS,
) -> list:
    """
    Enrich each clean finding with AI analysis. Calls now fan out across
    a small thread pool instead of running strictly one at a time — this
    is the main fix for the multi-minute enrichment stage: the original
    loop paid a fixed 4s sleep *per finding* plus up to 3x60s on any
    rate-limit retry, all serialized, which added up fast on real finding
    counts.

    Still writes partial results after every completed item if
    output_path is given (writes are lock-serialized across workers), so
    a crash never loses completed work — same crash-safety guarantee as
    before, just thread-safe now.

    on_progress(i, total, cve_id, ok: bool) is called after each item
    completes. Note: with concurrency, items can finish out of input
    order, so `i` here means "number completed so far", not the
    finding's position in `findings`.

    max_workers controls how many Gemini calls run in parallel. Default
    is 6 — a reasonable balance between speed and not hammering the API;
    tune down if you see more rate-limit errors, up if you have generous
    quota.
    """
    # Each call to enrich_findings() is a fresh batch as far as this process
    # knows — don't let a quota-exhaustion flag from a previous job earlier
    # in the same process lifetime (which may have been yesterday, if the
    # server's been up a while) permanently short-circuit new runs.
    _daily_quota_exhausted.clear()

    total = len(findings)
    results: list = []
    write_lock = threading.Lock()
    completed = 0
    cache_hits = 0

    with _cache_lock:
        cache = _load_cache()

    def _run(vuln):
        nonlocal completed, cache_hits
        result, ok, from_cache = _enrich_one(vuln, cache)
        if not from_cache:
            time.sleep(MIN_CALL_INTERVAL)  # light per-worker pacing, not a global stall

        with write_lock:
            completed += 1
            if from_cache:
                cache_hits += 1
            if ok:
                results.append(result)
                if not from_cache:
                    # Persist immediately (not just at the end) so a run that
                    # gets partway through before hitting the daily cap still
                    # banks every finding it *did* successfully enrich —
                    # those won't need to spend quota again next time.
                    cache[_cache_key(vuln)] = result
                    with _cache_lock:
                        _save_cache(cache)
            if output_path:
                with open(output_path, "w", encoding="utf-8") as f:
                    json.dump(results, f, indent=2)
            if on_progress:
                on_progress(completed, total, vuln.get("cve"), ok)

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(_run, vuln) for vuln in findings]
        for future in as_completed(futures):
            future.result()  # re-raise any unexpected exception from a worker

    if cache_hits:
        print(f"[m3_enrich] {cache_hits}/{total} findings served from cache (no API call spent).")
    if _daily_quota_exhausted.is_set():
        print(
            "[m3_enrich] Gemini free-tier daily quota (500 requests/day) is exhausted. "
            "Remaining findings were skipped rather than retried 3x each — they'll need "
            "either tomorrow's quota reset, billing enabled on the Google AI Studio "
            "project, or a re-run later (already-enriched findings are cached and won't "
            "re-spend quota)."
        )

    return results


def quota_exhausted_last_run() -> bool:
    """True if the most recent enrich_findings() call hit the Gemini
    free-tier daily cap. Lets callers (e.g. the dashboard) show a specific,
    actionable message instead of guessing "bad API key" for every failure."""
    return _daily_quota_exhausted.is_set()


def merge_enrichment(clean_findings_list: list, ai_results: list) -> list:
    """Join clean findings with their AI enrichment by cve_id/cve."""
    ai_by_cve = {r.get("cve_id"): r for r in ai_results}
    merged = []
    for f in clean_findings_list:
        ai = ai_by_cve.get(f.get("cve"))
        merged.append({**f, "ai": ai})
    return merged
