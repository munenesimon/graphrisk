"""
Tests for the per-control coverage breakdown on GET /frameworks/{id}/controls
-- the endpoint behind the Frameworks screen's drill-down ("which specific
controls are covered vs. not yet covered", not just the framework-wide
percentage already covered by the dashboard's framework-coverage endpoint).
"""
from app.graph import queries as app_queries


def _rows(*statuses):
    """Builds fake GET_FRAMEWORK_CONTROLS_WITH_STATUS rows, one per status."""
    rows = []
    for i, status in enumerate(statuses):
        rows.append({
            "id": f"fc-{i}",
            "control_reference": f"REF-{i}",
            "title": f"Requirement {i}",
            "domain": "Access Control" if i % 2 == 0 else "Logging",
            "summary": "summary",
            "official_url": None,
            "direct_controls": ["MFA"] if status == "direct" else [],
            "mapped_controls": ["Logging Control"] if status == "mapped" else [],
            "status": status,
        })
    return rows


def test_framework_controls_reports_covered_and_not_covered_counts(client, fake_graph, as_user):
    as_user()
    fake_graph.query.return_value = _rows("direct", "mapped", "not_covered", "not_covered")

    resp = client.get("/api/v1/frameworks/fw-1/controls")

    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 4
    assert body["covered"] == 2
    assert body["not_covered"] == 2
    assert len(body["controls"]) == 4
    # Passes the caller's graph tenant, not a hardcoded one, so coverage
    # reflects the actual tenant's own Control nodes.
    call_args = fake_graph.query.call_args
    assert call_args[0][0] == app_queries.GET_FRAMEWORK_CONTROLS_WITH_STATUS
    assert call_args[0][1]["tenant_id"] == "demo"
    assert call_args[0][1]["framework_id"] == "fw-1"


def test_framework_controls_can_filter_to_only_not_covered(client, fake_graph, as_user):
    as_user()
    fake_graph.query.return_value = _rows("direct", "mapped", "not_covered")

    resp = client.get("/api/v1/frameworks/fw-1/controls?status=not_covered")

    assert resp.status_code == 200
    body = resp.json()
    # Totals still reflect the whole framework, not just the filtered page.
    assert body["total"] == 3
    assert body["covered"] == 2
    assert body["not_covered"] == 1
    assert len(body["controls"]) == 1
    assert body["controls"][0]["status"] == "not_covered"


def test_framework_controls_can_filter_to_only_covered(client, fake_graph, as_user):
    as_user()
    fake_graph.query.return_value = _rows("direct", "mapped", "not_covered")

    resp = client.get("/api/v1/frameworks/fw-1/controls?status=covered")

    assert resp.status_code == 200
    body = resp.json()
    assert len(body["controls"]) == 2
    assert all(c["status"] != "not_covered" for c in body["controls"])


def test_framework_controls_404s_for_an_unknown_framework(client, fake_graph, as_user):
    as_user()
    fake_graph.query.return_value = []

    resp = client.get("/api/v1/frameworks/does-not-exist/controls")

    assert resp.status_code == 404
