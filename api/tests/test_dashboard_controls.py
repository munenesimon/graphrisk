"""
Dashboard controls card: each control with its current health, not just a
count of controls marked Implemented.
"""
from app.api.v1.dashboard import summarise_controls
from app.graph import queries


def _ctrl(title, status, health=None, source=None):
    return {"id": title.lower().replace(" ", "-"), "title": title, "status": status,
            "health": health, "source": source, "detail": None, "last_tested_at": None}


def test_health_shows_progress_a_pass_count_would_hide():
    rows = [
        _ctrl("Endpoint Protection", "Implemented", 1.0, "wazuh"),
        _ctrl("Secure Configuration Baseline", "NotImplemented", 0.28, "wazuh"),
        _ctrl("Vulnerability & Patch Management", "NotImplemented", 0.06, "wazuh"),
    ]
    s = summarise_controls(rows)
    assert s["total"] == 3 and s["implemented"] == 1
    assert (s["working"], s["partial"], s["not_working"]) == (1, 2, 0)
    assert s["avg_health_pct"] == round((1.0 + 0.28 + 0.06) / 3 * 100, 1)
    assert [i["state"] for i in s["items"]] == ["working", "partial", "partial"]
    assert all(i["measured"] for i in s["items"])


def test_hand_set_status_is_used_when_nothing_has_measured_the_control():
    s = summarise_controls([_ctrl("Policy", "PartiallyImplemented"), _ctrl("Backups", "Planned"),
                            _ctrl("Training", None)])
    assert [i["health"] for i in s["items"]] == [0.5, 0.2, 0.0]
    assert [i["state"] for i in s["items"]] == ["partial", "partial", "not_working"]
    assert not any(i["measured"] for i in s["items"])


def test_no_controls_has_no_average():
    s = summarise_controls([])
    assert s["total"] == 0 and s["avg_health_pct"] is None and s["items"] == []


def test_health_is_clamped_and_bad_values_count_as_zero():
    s = summarise_controls([_ctrl("A", None, 1.7), _ctrl("B", None, "n/a")])
    assert [i["health"] for i in s["items"]] == [1.0, 0.0]


def test_summary_endpoint_returns_control_health(client, fake_graph, as_user):
    as_user(graph_tenant_id="acme")

    def fake(query, params):
        if query == queries.DASHBOARD_CONTROLS_DETAIL:
            assert params == {"t": "acme"}
            return [_ctrl("Endpoint Protection", "Implemented", 1.0, "wazuh"),
                    _ctrl("Secure Configuration Baseline", "NotImplemented", 0.28, "wazuh")]
        return []
    fake_graph.query.side_effect = fake
    body = client.get("/api/v1/dashboard/summary").json()
    c = body["controls"]
    assert c["total"] == 2 and c["working"] == 1 and c["partial"] == 1
    assert c["avg_health_pct"] == 64.0
    assert [i["title"] for i in c["items"]] == ["Endpoint Protection", "Secure Configuration Baseline"]


# ── Control status follows health ──────────────────────────────────────────
from app.connectors.models import CheckStatus
from app.connectors.registry import implementation_status_for


def test_status_is_graded_by_health_not_just_pass_or_fail():
    assert implementation_status_for(CheckStatus.PASS, 1.0) == "Implemented"
    assert implementation_status_for(CheckStatus.FAIL, 0.28) == "PartiallyImplemented"
    assert implementation_status_for(CheckStatus.FAIL, 0.06) == "PartiallyImplemented"
    assert implementation_status_for(CheckStatus.WARNING, 0.85) == "PartiallyImplemented"
    assert implementation_status_for(CheckStatus.FAIL, 0.0) == "NotImplemented"


def test_status_without_a_score_falls_back_to_the_check_result():
    assert implementation_status_for(CheckStatus.WARNING, None) == "PartiallyImplemented"
    assert implementation_status_for(CheckStatus.FAIL, None) == "NotImplemented"


def test_errors_and_skips_leave_the_status_alone():
    assert implementation_status_for(CheckStatus.ERROR, 0.0) is None
    assert implementation_status_for(CheckStatus.SKIPPED, None) is None


def test_a_failing_check_on_a_partly_working_control_is_written_as_partial(fake_graph):
    from app.connectors.models import CheckCategory, CheckResult
    from app.connectors.registry import CheckRegistry
    result = CheckResult(check_id="sca", check_name="SCA", category=CheckCategory.ENDPOINT, source="wazuh",
                         tenant_id="t", status=CheckStatus.FAIL, score=0.28, detail="296 of 412 failing",
                         control_title="Secure Configuration Baseline")
    CheckRegistry()._write_to_graph(result)
    query, params = fake_graph.write.call_args[0]
    assert query == queries.WRITE_CHECK_RESULT
    assert params["implementation_status"] == "PartiallyImplemented"
    assert params["score"] == 0.28 and params["control_title"] == "Secure Configuration Baseline"
