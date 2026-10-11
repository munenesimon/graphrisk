"""
Shared rules every connector check follows -- the lessons from running
Wazuh against a real laptop, written once so each adapter gets them by
default instead of being patched by hand:

1. Missing data is "unknown", never "good" or "bad".
   A check that has nothing to measure (no hosts, no users, a process list
   that can't show the antivirus) returns a SKIPPED result via
   ``no_data_result``. The registry leaves the control's health as it was
   instead of writing a made-up 100% or 0%. ``share_score`` returns None
   for an empty population so a check can't quietly score 1.0 on nothing.

2. Vulnerability load is graded by severity, and measured as progress.
   ``open_weight`` turns findings per severity into one number (a Critical
   counts 40 times a Low), and ``progress`` reports it the way the registry
   expects: control health becomes the share of the worst level seen that
   has since been fixed, so every patch moves the score.

3. Only applicable items count.
   Checks pass ``applicable`` populations (e.g. devices that actually
   report an encryption state) to ``share_score``; anything that can't be
   evaluated is reported in the detail line, not counted as a pass or fail.

4. Slow or busy vendor APIs are retried, not failed.
   ``request_with_retry`` retries timeouts, connection drops, 429 and 5xx
   with bounded back-off, and reads Retry-After / X-Rate-Limit-Reset
   correctly (seconds, HTTP date or epoch time).
"""
from __future__ import annotations

import logging
import time
from email.utils import parsedate_to_datetime
from typing import Callable, Mapping

import requests

from .models import CheckCategory, CheckResult, CheckStatus

logger = logging.getLogger(__name__)

# ── Severity-weighted vulnerability load ─────────────────────────────────────
# One Critical outweighs many Lows: fixing it should move the score more.
SEVERITY_WEIGHTS: dict[str, float] = {"critical": 10.0, "high": 4.0, "medium": 1.0, "low": 0.25}


def severity_weight(label) -> float:
    """Weight of one finding at this severity label (case-insensitive);
    unknown labels count as nothing rather than guessing."""
    return SEVERITY_WEIGHTS.get(str(label or "").strip().lower(), 0.0)


def open_weight(counts_by_severity: Mapping[str, int] | None) -> float:
    """Severity-weighted size of an open-finding load, e.g.
    {"Critical": 2, "Low": 4} -> 21.0."""
    total = 0.0
    for label, count in (counts_by_severity or {}).items():
        try:
            total += severity_weight(label) * max(int(count or 0), 0)
        except (TypeError, ValueError):
            continue
    return round(total, 2)


# A small load shouldn't read as 0% just because it's the first one seen:
# the baseline is at least this much per device (about two Criticals).
PROGRESS_FLOOR_PER_DEVICE = 20.0


def first_run_score(open_weight_value: float, devices: int) -> float:
    """The score before any history exists (the registry replaces it with
    progress against the worst level seen)."""
    baseline = max(float(open_weight_value or 0.0), PROGRESS_FLOOR_PER_DEVICE * max(int(devices or 0), 1))
    return round(1.0 - float(open_weight_value or 0.0) / baseline, 4) if baseline else 1.0


def graded_status(score: float) -> CheckStatus:
    return (CheckStatus.PASS if score >= 0.95 else
            CheckStatus.WARNING if score >= 0.80 else CheckStatus.FAIL)


def progress(open_weight_value: float, devices: int) -> dict:
    """The raw_data["progress"] block the registry turns into progress-based
    control health (see CheckRegistry._apply_progress)."""
    return {"open_weight": round(max(float(open_weight_value or 0.0), 0.0), 2),
            "devices": max(int(devices or 0), 1)}


# ── Scores over a population ─────────────────────────────────────────────────
def share_score(bad: int, applicable: int) -> float | None:
    """1 - bad/applicable, or None when nothing was applicable -- so the
    caller has to decide what "nothing to measure" means instead of the
    check silently scoring 100%."""
    if applicable is None or applicable <= 0:
        return None
    return round(max(0.0, 1.0 - max(bad, 0) / applicable), 4)


def no_data_result(*, check_id: str, check_name: str, category: CheckCategory, source: str,
                   tenant_id: str, control_title: str, reason: str,
                   discovered_assets: list[dict] | None = None,
                   raw_data: dict | None = None) -> CheckResult:
    """A check that ran fine but had nothing to measure. SKIPPED, so the
    registry keeps the control's current health rather than overwriting it
    with an invented score; the reason is shown on the connector card."""
    return CheckResult(
        check_id=check_id,
        check_name=check_name,
        category=category,
        source=source,
        tenant_id=tenant_id,
        status=CheckStatus.SKIPPED,
        score=0.0,
        detail=f"Nothing to measure yet: {reason}",
        control_title=control_title,
        discovered_assets=list(discovered_assets or []),
        raw_data=dict(raw_data or {}, no_data=True),
    )


# ── HTTP with retries ────────────────────────────────────────────────────────
RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})
DEFAULT_TIMEOUT = (10, 60)       # (connect, read) seconds
MAX_BACKOFF_SECONDS = 60.0


def backoff_seconds(response: requests.Response | None, attempt: int,
                    now: Callable[[], float] = time.time) -> float:
    """How long to wait before retrying. Honours Retry-After (seconds or an
    HTTP date) and Okta's X-Rate-Limit-Reset (an epoch timestamp, not a
    duration); otherwise exponential back-off. Always capped."""
    default = float(2 ** attempt)
    if response is None:
        return min(default, MAX_BACKOFF_SECONDS)
    headers = response.headers or {}
    wait = None
    retry_after = headers.get("Retry-After")
    if retry_after:
        try:
            wait = float(retry_after)
        except ValueError:
            try:
                wait = parsedate_to_datetime(retry_after).timestamp() - now()
            except (TypeError, ValueError):
                wait = None
    if wait is None and headers.get("X-Rate-Limit-Reset"):
        try:
            wait = float(headers["X-Rate-Limit-Reset"]) - now()
        except ValueError:
            wait = None
    if wait is None:
        wait = default
    return min(max(wait, 1.0), MAX_BACKOFF_SECONDS)


def request_with_retry(session: requests.Session, method: str, url: str, *,
                       retries: int = 3, timeout=DEFAULT_TIMEOUT,
                       sleep: Callable[[float], None] = time.sleep, **kwargs) -> requests.Response:
    """
    One HTTP request, retried on timeouts, dropped connections, 429 and 5xx.
    Returns the final response (the caller still calls raise_for_status), or
    raises the last network error once retries run out.
    """
    attempts = max(int(retries), 1)
    for attempt in range(attempts):
        last = attempt == attempts - 1
        try:
            r = session.request(method, url, timeout=timeout, **kwargs)
        except (requests.Timeout, requests.ConnectionError) as e:
            if last:
                raise
            wait = backoff_seconds(None, attempt)
            logger.warning(f"{method} {url} failed ({type(e).__name__}); retrying in {wait:.0f}s")
            sleep(wait)
            continue
        if r.status_code in RETRYABLE_STATUS and not last:
            wait = backoff_seconds(r, attempt)
            logger.warning(f"{method} {url} returned {r.status_code}; retrying in {wait:.0f}s")
            sleep(wait)
            continue
        return r
    raise RuntimeError(f"Request failed after {attempts} attempts: {url}")  # pragma: no cover
