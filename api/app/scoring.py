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


# ── Adequacy ─────────────────────────────────────────────────────────────────
# Whether the controls on a risk are enough is only meaningful against a
# target: the organisation's risk appetite, the highest residual score it is
# willing to accept (same 0–25 scale as the score). The default is "low":
# roughly, an unlikely event with a moderate impact.
DEFAULT_RISK_APPETITE = 4.0
MAX_RISK_SCORE = 25.0
_EPS = 1e-9


def _fmt(v: float) -> str:
    return f"{v:.2f}".rstrip("0").rstrip(".")


def _pct(v: float) -> str:
    return f"{round(v * 100)}%"


def _score_with(explained: Mapping, health_overrides: Mapping) -> float:
    controls = [
        {**c, "health": health_overrides.get(c.get("id"), c.get("health"))}
        for c in explained.get("controls") or []
    ]
    return residual_score(explained.get("likelihood"), explained.get("impact"), controls)


def assess_risk(explained: Mapping, appetite: float) -> dict:
    """Is a risk adequately controlled, and if not, what would close the gap?

    ``explained`` is explain_risk()'s output. Three outcomes:

    not_adequate      the score now is above the appetite. The fix names the
                      single control whose improvement closes the gap, or
                      says when only a new/stronger control would.
    relies_on_control within appetite now, but one control failing would
                      push it over -- a single point of failure.
    adequate          within appetite, and stays within it if any one
                      control fails.
    """
    appetite = float(appetite)
    current = float(explained.get("current_score") or 0.0)
    controls = [c for c in explained.get("controls") or [] if isinstance(c, Mapping)]
    base = {"appetite": appetite}

    if current > appetite + _EPS:
        # One control at a time brought to full health, best first.
        options = []
        for c in controls:
            if (c.get("health") or 0) < 1.0 - _EPS and (c.get("strength") or 0) > _EPS:
                options.append((_score_with(explained, {c.get("id"): 1.0}), c))
        options.sort(key=lambda o: o[0])
        best_case = _score_with(explained, {c.get("id"): 1.0 for c in controls})
        if options and options[0][0] <= appetite + _EPS:
            score, c = options[0]
            fix = (f"Bringing {c.get('title')} to full health (now {_pct(c.get('health') or 0)}) "
                   f"would lower it to {_fmt(score)}, within appetite.")
        elif best_case <= appetite + _EPS:
            weak = [c.get("title") for c in controls if (c.get("health") or 0) < 1.0 - _EPS]
            fix = (f"Improving {', '.join(weak)} together would lower it to {_fmt(best_case)}, "
                   "within appetite.")
        elif not controls:
            fix = "No control mitigates this risk yet — it needs one."
        else:
            fix = (f"Even with every linked control at full health it would score {_fmt(best_case)}. "
                   "It needs another control, or a stronger one.")
            idle = [c.get("title") for c in controls if (c.get("strength") or 0) <= _EPS]
            if idle:
                fix += (f" {', '.join(idle)} {'is' if len(idle) == 1 else 'are'} linked but recorded "
                        "as addressing none of this risk — check that link's strength.")
        return {**base, "status": "not_adequate", "label": "Not adequate",
                "reason": f"Scores {_fmt(current)}, above your risk appetite of {_fmt(appetite)}.",
                "fix": fix}

    # Within appetite: which single failures would push it over?
    single_points = []
    for c in controls:
        if (c.get("health") or 0) > _EPS and (c.get("strength") or 0) > _EPS:
            failed = _score_with(explained, {c.get("id"): 0.0})
            if failed > appetite + _EPS:
                single_points.append((failed, c))
    if single_points:
        # The control this view is about first, then the worst failure.
        single_points.sort(key=lambda p: (not p[1].get("is_trigger"), -p[0]))
        failed, c = single_points[0]
        others = [p[1].get("title") for p in single_points[1:]]
        return {**base, "status": "relies_on_control", "label": "Relies on one control",
                "reason": (f"Scores {_fmt(current)}, within your appetite of {_fmt(appetite)}, but if "
                           f"{c.get('title')} failed it would rise to {_fmt(failed)}"
                           + (f"; losing {', '.join(others)} would also push it over." if others else ".")),
                "fix": (f"Strengthen another control on this risk, or add one, so that losing "
                        f"{c.get('title')} alone doesn't push it over your appetite.")}

    return {**base, "status": "adequate", "label": "Adequate",
            "reason": (f"Scores {_fmt(current)}, within your appetite of {_fmt(appetite)}"
                       + (", and stays within it if any one control fails." if controls else ".")),
            "fix": None}
