"""
Residual risk: how GraphRisk turns a risk's likelihood and impact, and the
controls on it, into the score on screen -- and the working behind it.

    risk score = likelihood × impact × ∏ (1 − strength × health)

    health    how well a control is operating right now: the latest
              connector check result for it (e.g. Wazuh: share of devices
              reporting with antivirus running), or the status set by hand
              (Implemented 100%, Partially implemented 50%, Planned 20%,
              Not implemented 0%).
    strength  how much of *this* risk the control addresses when it works,
              set on the control-to-risk link. EDR does a lot against
              ransomware and less against data exfiltration, so one control
              can have different strengths on different risks. A link with
              no strength recorded counts as 100%.

Each control removes its share of whatever risk the others leave, so adding
a control always lowers the score, but partial controls never stack to zero.

The stored Risk.risk_score is computed by the same formula in Cypher
(graphrisk_core's _RECOMPUTE_RISK); this module is the readable twin the API
uses to explain a number and to answer "what if this control fails?". Keep
the two in step.
"""
from __future__ import annotations

from typing import Iterable, Mapping


def _unit(value, default: float) -> float:
    """A 0..1 fraction from whatever the graph holds (None, int, str)."""
    try:
        v = float(value)
    except (TypeError, ValueError):
        return default
    if v != v:  # NaN
        return default
    return min(max(v, 0.0), 1.0)


def control_factor(health, strength) -> float:
    """The share of the remaining risk one control leaves in place."""
    return 1.0 - _unit(strength, 1.0) * _unit(health, 0.0)


def residual_score(likelihood, impact, controls: Iterable[Mapping], *, failed_control_id: str | None = None) -> float:
    """Residual risk score, rounded to 2 places like the stored score.

    ``failed_control_id`` scores the risk as if that control had stopped
    working (health 0) -- the "if this control fails" figure."""
    inherent = float(likelihood or 0) * float(impact or 0)
    remaining = 1.0
    for c in controls:
        health = 0.0 if failed_control_id is not None and c.get("id") == failed_control_id else c.get("health")
        remaining *= control_factor(health, c.get("strength"))
    return round(inherent * remaining, 2)


def explain_risk(row: Mapping, control_id: str) -> dict:
    """The breakdown for one risk in a control's blast radius: inherent
    score, current score, the score if ``control_id`` fails, and each
    control's contribution, strongest first."""
    likelihood = row.get("likelihood") or 0
    impact = row.get("impact") or 0
    controls = [c for c in (row.get("controls") or []) if isinstance(c, Mapping)]
    inherent = round(float(likelihood) * float(impact), 2)
    breakdown = []
    for c in controls:
        health = _unit(c.get("health"), 0.0)
        strength = _unit(c.get("strength"), 1.0)
        breakdown.append({
            "id": c.get("id"),
            "title": c.get("title"),
            "status": c.get("status"),
            "health": round(health, 4),
            "strength": round(strength, 4),
            # How much of the remaining risk this control removes on its own.
            "reduction": round(strength * health, 4),
            "is_trigger": c.get("id") == control_id,
        })
    breakdown.sort(key=lambda b: (-b["reduction"], str(b["title"] or "")))
    return {
        "risk": row.get("risk"),
        "likelihood": likelihood,
        "impact": impact,
        "inherent_score": inherent,
        "current_score": residual_score(likelihood, impact, controls),
        "if_control_fails": residual_score(likelihood, impact, controls, failed_control_id=control_id),
        "stored_score": row.get("risk_score"),
        "controls": breakdown,
    }
