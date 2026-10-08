"""
GraphRisk -- rescore stored risks with the current residual-risk formula.

    risk score = likelihood × impact × ∏ (1 − strength × health)

(see app/scoring.py). Scores are normally recalculated whenever something
changes -- a control's status, a connector check, a new control-risk link --
but risks nothing has touched since the formula changed keep their old
score. Run this once after deploying a formula change, or any time the
stored scores look stale.

Run from the api folder with the venv active, against whichever Neo4j your
environment points at (for the live site: the same NEO4J_URI / NEO4J_USER /
NEO4J_PASSWORD Render uses):

    python recalculate_risk_scores.py              # every tenant
    python recalculate_risk_scores.py demo         # one tenant

It prints each risk's old and new score, then writes only after you type
"yes". Nothing is deleted; only Risk.risk_score changes, and running it
again gives the same result.
"""
import sys

from app.graph.connection import run_query, run_write, get_graph_client, close_graph_client
from app.graph import queries
from app.scoring import residual_score

TENANT_ID = sys.argv[1] if len(sys.argv) > 1 else None

CURRENT_SCORES = """
    MATCH (r:Risk)
    WHERE $tenant_id IS NULL OR r.tenant_id = $tenant_id
    RETURN r.tenant_id AS tenant_id, r.title AS risk, r.likelihood AS likelihood,
           r.impact AS impact, r.risk_score AS risk_score,
           [(c:Control)-[m:MITIGATES]->(r) | {id: c.id, title: c.title,
               health: c.effectiveness_score, strength: m.effectiveness}] AS controls
    ORDER BY tenant_id, risk
"""


def main() -> None:
    get_graph_client()
    try:
        scope = f"tenant '{TENANT_ID}'" if TENANT_ID else "every tenant"
        print("=" * 72)
        print(f"  Rescore risks in {scope}")
        print("  score = likelihood x impact x product(1 - strength x health)")
        print("=" * 72)

        rows = run_query(CURRENT_SCORES, {"tenant_id": TENANT_ID}) or []
        if not rows:
            print("  No risks found.")
            return

        changed = 0
        current_tenant = None
        for r in rows:
            if r["tenant_id"] != current_tenant:
                current_tenant = r["tenant_id"]
                print(f"\n  [{current_tenant}]")
            old = r.get("risk_score")
            new = residual_score(r.get("likelihood"), r.get("impact"), r.get("controls") or [])
            mark = "" if old is not None and abs(float(old) - new) < 0.005 else "  <- changes"
            if mark:
                changed += 1
            old_txt = "-" if old is None else f"{float(old):.2f}"
            print(f"    {str(r['risk'])[:40]:<40} {old_txt:>6} -> {new:>6.2f}{mark}")
            for c in r.get("controls") or []:
                health = c.get("health")
                strength = c.get("strength")
                h = "?" if health is None else f"{float(health):.0%}"
                s = "100% (not set)" if strength is None else f"{float(strength):.0%}"
                print(f"        {str(c.get('title'))[:34]:<34} health {h:>5}   strength {s}")

        print(f"\n  {changed} of {len(rows)} risk scores change.")
        if not changed:
            return
        if input('  Type "yes" to write the new scores: ').strip().lower() != "yes":
            print("  Nothing written.")
            return
        written = run_write(queries.RECALCULATE_RISK_SCORES, {"tenant_id": TENANT_ID}) or []
        print(f"  Rescored {len(written)} risks.")
    finally:
        close_graph_client()


if __name__ == "__main__":
    main()
