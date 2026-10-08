"""
Residual risk -- app/scoring.py. The expected numbers are the public demo's
own controls and links (api/seed_demo.py), worked by hand:

    Ransomware      3 × 5 = 15   EDR 0.8 × 1.0, MFA 0.7 × 0.9   → 15 × 0.2 × 0.37 = 1.11
    Data exfil      3 × 4 = 12   EDR 0.6 × 1.0, DLP 0.0 × 0.0   → 12 × 0.4 × 1.0  = 4.8
    Identity        4 × 5 = 20   MFA 0.9 × 0.9, PAM 0.5 × 0.5   → 20 × 0.19 × 0.75 = 2.85
"""
from app.graph import queries as app_queries
from app.scoring import control_factor, explain_risk, residual_score

EDR = "ctrl-edr"

RANSOMWARE = {
    "risk": "Ransomware Infection Risk", "likelihood": 3, "impact": 5, "risk_score": 0.0,
    "controls": [
        {"id": EDR, "title": "Endpoint Detection & Response", "status": "Implemented", "health": 1.0, "strength": 0.8},
        {"id": "ctrl-mfa", "title": "Multi-Factor Authentication", "status": "Implemented", "health": 0.9, "strength": 0.7},
    ],
}
EXFIL = {
    "risk": "Data Exfiltration Risk", "likelihood": 3, "impact": 4, "risk_score": 0.0,
    "controls": [
        {"id": EDR, "title": "Endpoint Detection & Response", "health": 1.0, "strength": 0.6},
        {"id": "ctrl-dlp", "title": "Data Loss Prevention", "status": "Planned", "health": 0.0, "strength": 0.0},
    ],
}
IDENTITY_CONTROLS = [
    {"id": "ctrl-mfa", "health": 0.9, "strength": 0.9},
    {"id": "ctrl-pam", "health": 0.5, "strength": 0.5},
]


def test_controls_combine_using_each_links_strength():
    assert residual_score(3, 5, RANSOMWARE["controls"]) == 1.11
    assert residual_score(3, 4, EXFIL["controls"]) == 4.8
    assert residual_score(4, 5, IDENTITY_CONTROLS) == 2.85


def test_a_fully_healthy_control_no_longer_zeroes_a_risk_it_only_partly_covers():
    # The old formula gave 0 here: EDR at 100% wiped out data exfiltration
    # even though the link says EDR only covers 60% of it.
    assert residual_score(3, 4, [{"health": 1.0, "strength": 0.6}]) == 4.8


def test_no_controls_means_the_inherent_score():
    assert residual_score(3, 5, []) == 15.0


def test_missing_strength_counts_as_full_and_missing_health_as_none():
    assert control_factor(1.0, None) == 0.0      # old links: previous behaviour
    assert control_factor(None, 0.8) == 1.0      # no health recorded: no credit


def test_bad_values_are_clamped_not_trusted():
    assert control_factor(1.7, 2.0) == 0.0
    assert control_factor(-1, 0.5) == 1.0
    assert control_factor("not a number", 0.5) == 1.0
    assert residual_score(3, 5, [{"health": 5, "strength": 5}]) == 0.0


def test_if_control_fails_drops_only_that_controls_health():
    assert residual_score(3, 5, RANSOMWARE["controls"], failed_control_id=EDR) == 5.55  # 15 × 1.0 × 0.37
    assert residual_score(3, 4, EXFIL["controls"], failed_control_id=EDR) == 12.0


def test_explain_risk_gives_the_working_strongest_control_first():
    out = explain_risk(RANSOMWARE, EDR)
    assert out["inherent_score"] == 15.0
    assert out["current_score"] == 1.11
    assert out["if_control_fails"] == 5.55
    assert [c["title"] for c in out["controls"]] == ["Endpoint Detection & Response", "Multi-Factor Authentication"]
    edr, mfa = out["controls"]
    assert edr["reduction"] == 0.8 and edr["is_trigger"] is True
    assert mfa["reduction"] == 0.63 and mfa["is_trigger"] is False


# ── API ──────────────────────────────────────────────────────────────────────

CONTROL_ROW = {
    "control_title": "Endpoint Detection & Response", "control_status": "Implemented",
    "effectiveness_score": 1.0, "exposed_risks": ["Data Exfiltration Risk", "Ransomware Infection Risk"],
    "affected_assets": [], "affected_asset_ids": [], "impacted_processes": [],
    "frameworks": [], "framework_controls": [], "mapped_framework_controls": [],
    "risk_count": 2, "asset_count": 0,
}


def test_blast_radius_returns_each_risks_working(client, fake_graph, as_user):
    as_user(graph_tenant_id="acme")

    def _fake(query, params=None):
        if query == app_queries.BLAST_RADIUS_CONTROL:
            return [CONTROL_ROW]
        if query == app_queries.BLAST_RADIUS_RISK_SCORES:
            assert params == {"control_id": EDR, "tenant_id": "acme"}
            return [EXFIL, RANSOMWARE]
        return []
    fake_graph.query.side_effect = _fake

    resp = client.get(f"/api/v1/graph/blast-radius/control/{EDR}")
    assert resp.status_code == 200, resp.text
    scores = {s["risk"]: s for s in resp.json()["blast_radius"]["risk_scores"]}
    assert scores["Data Exfiltration Risk"]["current_score"] == 4.8
    assert scores["Data Exfiltration Risk"]["if_control_fails"] == 12.0
    assert scores["Ransomware Infection Risk"]["current_score"] == 1.11


def test_blast_radius_still_works_if_the_breakdown_query_fails(client, fake_graph, as_user):
    as_user(graph_tenant_id="acme")

    def _fake(query, params=None):
        if query == app_queries.BLAST_RADIUS_CONTROL:
            return [CONTROL_ROW]
        if query == app_queries.BLAST_RADIUS_RISK_SCORES:
            raise RuntimeError("neo4j hiccup")
        return []
    fake_graph.query.side_effect = _fake

    resp = client.get(f"/api/v1/graph/blast-radius/control/{EDR}")
    assert resp.status_code == 200
    assert resp.json()["blast_radius"]["risk_scores"] == []


def test_link_strength_must_be_a_fraction(client, fake_graph, as_user):
    as_user(graph_tenant_id="acme")
    resp = client.post("/api/v1/risks/r1/link-control", params={"control_id": "c1", "effectiveness": 1.5})
    assert resp.status_code == 422
