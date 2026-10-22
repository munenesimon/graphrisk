"""
Several connectors can measure one control. Each one's latest result is kept
per (control, source, check) and the control takes the weakest -- see
WRITE_CHECK_RESULT in app/graph/queries.py.
"""
from app.connectors.models import CheckCategory, CheckResult, CheckStatus
from app.connectors.registry import CheckRegistry
from app.graph import queries as app_queries


def test_each_source_is_kept_and_the_weakest_wins():
    q = app_queries.WRITE_CHECK_RESULT
    assert "MERGE (m:CheckMeasurement {tenant_id: $tenant_id, control_title: $control_title" in q
    assert "source: $source, check_id: $check_id" in q
    assert "ORDER BY meas.score ASC" in q
    assert "c.effectiveness_score = weakest.score" in q


def test_registry_writes_the_source_and_check_with_each_result(fake_graph):
    result = CheckResult(check_id="okta_mfa", check_name="Okta MFA", category=CheckCategory.IAM,
                         source="okta", tenant_id="acme", status=CheckStatus.WARNING, score=0.6,
                         affected_count=4, total_count=10, detail="6 of 10 users", control_title="Multi-Factor Authentication")
    CheckRegistry()._write_to_graph(result)
    query, params = fake_graph.write.call_args[0]
    assert query == app_queries.WRITE_CHECK_RESULT
    assert params["source"] == "okta" and params["check_id"] == "okta_mfa"
    assert params["control_title"] == "Multi-Factor Authentication" and params["score"] == 0.6
