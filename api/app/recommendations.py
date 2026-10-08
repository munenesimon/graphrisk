"""
Recommended actions for one device -- what to do, in what order, and why.

Nothing here is stored. The actions are worked out every time the asset page
is read, from what the connectors last reported about the device (its merged
profile), its vulnerable software, and the risks it is under. So any device
a connector discovers gets recommendations on that connector's next run,
with no setup, and they change as soon as the evidence does: patch WinRAR,
re-run Wazuh, and the WinRAR action is gone.

Each action says:

    priority   critical / high / medium / low
    category   patch, protection, health, configuration, risk
    title      the instruction, e.g. "Update or remove WinRAR 5.70"
    detail     why, from the evidence (CVE count, ransomware use, ...)
    steps      concrete next steps where the source gives them (e.g. Wazuh's
               own remediation text for a failed CIS check)
    source     which connector the evidence came from
    helps      the control this strengthens and the device's risks that
               control mitigates -- so an action is tied to the risk score

Only evidence-backed advice: if no connector reports on a section, nothing is
recommended from it (the page's "Not reported yet" card covers that gap).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, Mapping

from app.scoring import assess_risk, explain_risk

PRIORITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_CATEGORY_RANK = {"patch": 0, "protection": 1, "health": 2, "risk": 3, "configuration": 4}

# Which control each kind of action strengthens -- the default control titles
# the connectors write their checks to (see each adapter's
# DEFAULT_CONTROL_TITLES). Used to say which of the device's risks an action
# helps.
CATEGORY_CONTROL = {
    "patch": "Vulnerability & Patch Management",
    "protection": "Endpoint Detection & Response",
    "health": "Endpoint Detection & Response",
    "configuration": "Secure Configuration Baseline",
}

MAX_PATCH_ACTIONS = 10
MAX_STEPS = 5
# Connector data older than this is called out: the page reflects the last
# report, so patches or new findings since then aren't visible yet.
STALE_AFTER_HOURS = 24


def _fields(profile: Mapping, section: str) -> Mapping:
    return ((profile or {}).get(section) or {}).get("fields") or {}


def _source(profile: Mapping, section: str) -> str | None:
    sources = ((profile or {}).get(section) or {}).get("sources") or []
    names = [s.get("name") for s in sources if isinstance(s, Mapping) and s.get("name")]
    return ", ".join(names) or None


def _helps(category: str, risks: Iterable[Mapping]) -> dict | None:
    control = CATEGORY_CONTROL.get(category)
    if not control:
        return None
    helped = [r.get("title") for r in risks
              if any((c or {}).get("title") == control for c in r.get("controls") or [])]
    return {"control": control, "risks": helped}


def _patch_actions(fix_first: list, risks: list, source: str | None) -> list[dict]:
    out = []
    for pkg in (fix_first or [])[:MAX_PATCH_ACTIONS]:
        name = " ".join(x for x in (pkg.get("name"), pkg.get("version")) if x)
        count = pkg.get("cve_count") or len(pkg.get("cves") or [])
        sev = pkg.get("max_severity") or "Unknown"
        cvss = pkg.get("max_cvss") or 0
        cves = f"{count} CVE{'s' if count != 1 else ''}"
        # Severity is the scanner's rating; CVSS the base score -- they can
        # disagree, so name both rather than implying one from the other.
        rating = f"rated {sev}" + (f", highest CVSS {cvss:g}" if cvss else "")
        if pkg.get("ransomware"):
            priority = "critical"
            why = f"{cves}, including at least one known to be used in ransomware ({rating})."
        elif sev == "Critical" or cvss >= 9:
            priority = "high"
            why = f"{cves}, {rating}."
        elif sev == "High":
            priority = "medium"
            why = f"{cves}, {rating}."
        else:
            priority = "low"
            why = f"{cves}, {rating}."
        out.append({
            "priority": priority, "category": "patch",
            "title": f"Update or remove {name}",
            "detail": why,
            # How to patch is the same for every package; the page says it
            # once above the list instead of on every card.
            "steps": [],
            "source": source, "helps": _helps("patch", risks),
            "cves": [c.get("cve_id") for c in (pkg.get("cves") or [])][:MAX_STEPS],
        })
    return out


def _protection_actions(profile: Mapping, risks: list) -> list[dict]:
    f = _fields(profile, "protection")
    if not f:
        return []
    src = _source(profile, "protection")
    out = []
    status = f.get("status")
    if status == "Not detected":
        out.append({
            "priority": "critical", "category": "protection",
            "title": "No antivirus or EDR is running",
            "detail": "The device's running processes show no recognised antivirus or EDR engine.",
            "steps": ["Install or re-enable endpoint protection (e.g. turn Microsoft Defender Antivirus back on).",
                      "Re-run the connector to confirm it is detected as running."],
            "source": src, "helps": _helps("protection", risks),
        })
    elif status and status.startswith("Installed"):
        out.append({
            "priority": "high", "category": "protection",
            "title": f"Start {f.get('product') or 'the installed protection'}",
            "detail": "It is installed but wasn't seen running, so it isn't protecting the device.",
            "steps": ["Check the product's service is running and not disabled by policy.",
                      "Re-run the connector to confirm it is detected as running."],
            "source": src, "helps": _helps("protection", risks),
        })
    gaps = [g for g in f.get("policy_gaps") or [] if g]
    if gaps:
        out.append({
            "priority": "medium", "category": "protection",
            "title": f"Fix {len(gaps)} Microsoft Defender setting{'s' if len(gaps) != 1 else ''}",
            "detail": f.get("policy") or "Defender settings the CIS benchmark expects aren't enforced.",
            "steps": gaps[:MAX_STEPS],
            "source": src, "helps": _helps("protection", risks),
        })
    return out


def _health_actions(profile: Mapping, risks: list) -> list[dict]:
    f = _fields(profile, "health")
    status = str(f.get("status") or "").lower()
    if not status or status in ("online", "active", "healthy"):
        return []
    last = f.get("last_seen")
    return [{
        "priority": "high", "category": "health",
        "title": "Monitoring agent isn't reporting",
        "detail": f"Status: {f.get('status')}" + (f", last seen {last}." if last else ".")
                  + " Nothing on this device is being checked until it reports again.",
        "steps": ["Check the device is on and the agent service is running.",
                  "Check it can still reach the manager."],
        "source": _source(profile, "health"), "helps": _helps("health", risks),
    }]


def _parse_time(value) -> datetime | None:
    if not value:
        return None
    try:
        t = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def data_age_hours(profile: Mapping, now: datetime | None = None) -> float | None:
    """Hours since the newest connector report on this device, or None if
    nothing has reported."""
    newest = None
    for section in (profile or {}).values():
        for src in (section or {}).get("sources") or []:
            t = _parse_time((src or {}).get("collected_at"))
            if t and (newest is None or t > newest):
                newest = t
    if newest is None:
        return None
    now = now or datetime.now(timezone.utc)
    return max((now - newest).total_seconds() / 3600, 0.0)


def _stale_actions(profile: Mapping, now: datetime | None) -> list[dict]:
    age = data_age_hours(profile, now)
    if age is None or age < STALE_AFTER_HOURS:
        return []
    names = sorted({(src or {}).get("name") for sec in (profile or {}).values()
                    for src in (sec or {}).get("sources") or [] if (src or {}).get("name")})
    age_text = f"{round(age)} hours" if age < 48 else f"{round(age / 24)} days"
    return [{
        "priority": "medium", "category": "health",
        "title": f"Re-run {', '.join(names) or 'the connector'}: this device's data is {age_text} old",
        "detail": ("Everything on this page reflects the last report. Updates installed or new "
                   "findings since then won't show until the connector runs again."),
        "steps": [],
        "source": ", ".join(names) or None, "helps": None,
    }]


def _configuration_actions(profile: Mapping, risks: list) -> list[dict]:
    out = []
    src = _source(profile, "configuration")
    for b in _fields(profile, "configuration").get("benchmarks") or []:
        if not isinstance(b, Mapping) or not b.get("failed"):
            continue
        checks = [c for c in b.get("failed_checks") or [] if isinstance(c, Mapping) and c.get("title")]
        steps = [c["title"] + (f" — {c['remediation']}" if c.get("remediation") else "") for c in checks[:MAX_STEPS]]
        total = (b.get("passed") or 0) + (b.get("failed") or 0)
        out.append({
            "priority": "medium", "category": "configuration",
            "title": f"Fix failed {b.get('name') or 'benchmark'} checks",
            "detail": f"{b.get('failed')} of {total} checks fail" + (f" (score {b.get('score')}%)." if b.get("score") is not None else ".")
                      + (" Start with these:" if steps else ""),
            "steps": steps,
            "source": src, "helps": _helps("configuration", risks),
        })
    return out


def _risk_actions(risks: list) -> list[dict]:
    out = []
    for r in risks:
        a = r.get("assessment") or {}
        if a.get("status") not in ("not_adequate", "relies_on_control"):
            continue
        out.append({
            "priority": "high" if a["status"] == "not_adequate" else "medium",
            "category": "risk",
            "title": (f"{r.get('title')} is not adequately controlled" if a["status"] == "not_adequate"
                      else f"{r.get('title')} relies on one control"),
            "detail": a.get("reason"),
            "steps": [a["fix"]] if a.get("fix") else [],
            "source": None, "helps": None,
        })
    return out


def assess_asset_risks(risks: list, appetite: float) -> list[dict]:
    """Each risk the device is under, with its current score and verdict
    against the appetite (controls carry health and link strength)."""
    out = []
    for r in risks or []:
        controls = [{
            "id": c.get("id"), "title": c.get("title"), "status": c.get("status"),
            "health": c.get("effectiveness"), "strength": c.get("strength"),
        } for c in r.get("controls") or [] if c]
        explained = explain_risk({"risk": r.get("title"), "likelihood": r.get("likelihood"),
                                  "impact": r.get("impact"), "controls": controls}, control_id="")
        out.append({**r, "current_score": explained["current_score"],
                    "assessment": assess_risk(explained, appetite)})
    return out


def recommend_for_asset(profile: Mapping, fix_first: list, risks: list,
                        now: datetime | None = None) -> list[dict]:
    """Ranked actions for one device. ``risks`` should already carry their
    assessment (see assess_asset_risks)."""
    actions = (
        _patch_actions(fix_first, risks, _source(profile, "software") or _source(profile, "vulnerabilities"))
        + _protection_actions(profile, risks)
        + _health_actions(profile, risks)
        + _stale_actions(profile, now)
        + _risk_actions(risks)
        + _configuration_actions(profile, risks)
    )
    order = {id(a): i for i, a in enumerate(actions)}
    actions.sort(key=lambda a: (PRIORITY_RANK[a["priority"]], _CATEGORY_RANK[a["category"]], order[id(a)]))
    return actions
