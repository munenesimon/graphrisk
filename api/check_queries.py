"""
GraphRisk -- check that the newer local graph queries are valid Cypher
against your real Neo4j, without changing anything.

Each query is run with EXPLAIN, which makes Neo4j parse and plan it but not
execute it: no data is read back or written. Run it from the api folder
with the venv active, using the same NEO4J_* settings as
recalculate_risk_scores.py:

    python check_queries.py
"""
from app.graph.connection import get_graph_client, close_graph_client, run_query
from app.graph import queries

CHECKS = {
    "FRAMEWORK_ADHERENCE_ALL": {"tenant_id": "check"},
    "FRAMEWORK_REQUIREMENTS": {"tenant_id": "check", "framework_id": "check"},
    "SET_ATTESTATION": {"tenant_id": "check", "framework_id": "check", "requirement_id": "check",
                        "status": "in_place", "note": None, "evidence_url": None, "attested_by": "check"},
    "DELETE_ATTESTATION": {"tenant_id": "check", "requirement_id": "check"},
    "LINK_SCANNED_VULNERABILITY": {"tenant_id": "check", "asset_id": "check", "cve_id": "check",
                                   "source": "check"},
    "RECONCILE_SCANNED_VULNERABILITIES": {"tenant_id": "check", "asset_id": "check", "source": "check",
                                          "seen": ["check"]},
    "GET_ASSET_DETAIL": {"tenant_id": "check", "asset_id": "check"},
    "RECORD_PROGRESS_PEAK": {"tenant_id": "check", "control_title": "check", "source": "check",
                             "open_weight": 0.0},
}


def main() -> None:
    get_graph_client()
    failures = 0
    try:
        for name, params in CHECKS.items():
            try:
                run_query("EXPLAIN " + getattr(queries, name), params)
                print(f"  OK    {name}")
            except Exception as e:
                failures += 1
                print(f"  FAIL  {name}: {e}")
    finally:
        close_graph_client()
    print("\nAll queries are valid." if not failures else f"\n{failures} query(s) failed -- send me the output.")


if __name__ == "__main__":
    main()
