"""
Tests for CheckRegistry._ingest_assets -- the asset-ingestion half of the
universal connector architecture (see registry.py's docstring on the
method). Wazuh is the first adapter to populate CheckResult.discovered_assets
(one entry per monitored endpoint -- see test_wazuh_connector.py), but the
interesting behavior here (dedup, no-op on empty, the exact params handed
to CREATE_ASSET) is adapter-agnostic, so it's exercised directly against
the registry with a synthetic CheckResult rather than through a real adapter.

Uses the `fake_graph` fixture from conftest.py, which patches
app.graph.connection.run_query/run_write -- the same mechanism that makes
_write_to_graph's deferred import pick up the fake (see conftest's
docstring), since _ingest_assets imports run_query/run_write the same way.
"""
from app.connectors.models import CheckResult, CheckStatus, CheckCategory
from app.connectors.registry import CheckRegistry
from app.graph import queries as app_queries


def _result(discovered_assets):
    return CheckResult(
        check_id="fake_check",
        check_name="Fake Check",
        category=CheckCategory.ENDPOINT,
        source="fake_connector",
        tenant_id="tenant-1",
        status=CheckStatus.PASS,
        score=1.0,
        detail="ok",
        control_title="Some Control",
        discovered_assets=discovered_assets,
    )


def test_ingest_assets_is_a_noop_when_nothing_was_discovered(fake_graph):
    """Every non-Wazuh adapter today leaves discovered_assets empty --
    this must not touch the graph at all, not even to look up existing assets."""
    CheckRegistry()._ingest_assets(_result([]), "tenant-1")
    fake_graph.query.assert_not_called()
    fake_graph.write.assert_not_called()


def test_ingest_assets_creates_a_new_asset_with_the_expected_shape(fake_graph):
    fake_graph.query.return_value = []  # no assets exist yet for this tenant
    CheckRegistry()._ingest_assets(
        _result([{"name": "Simo", "asset_type": "Endpoint", "vendor": "Microsoft", "product": "Windows"}]),
        "tenant-1",
    )

    # GET_ALL_ASSETS looked up exactly once, scoped to this tenant.
    assert fake_graph.query.call_count == 1
    _, lookup_params = fake_graph.query.call_args[0]
    assert lookup_params == {"tenant_id": "tenant-1"}

    # CREATE_ASSET, then the same two onboarding side effects
    # POST /assets/ triggers (correlate + cascade) -- three run_write calls.
    assert fake_graph.write.call_count == 3
    _, create_params = fake_graph.write.call_args_list[0][0]
    assert create_params["name"] == "Simo"
    assert create_params["asset_type"] == "Endpoint"
    assert create_params["vendor"] == "Microsoft"
    assert create_params["product"] == "Windows"
    assert create_params["tenant_id"] == "tenant-1"
    assert create_params["owner"] == "fake_connector connector"
    assert create_params["holds_personal_data"] is False

    asset_id = create_params["id"]
    for call in fake_graph.write.call_args_list[1:]:
        _, side_effect_params = call[0]
        assert side_effect_params["asset_id"] == asset_id
        assert side_effect_params["tenant_id"] == "tenant-1"


def test_ingest_assets_skips_a_name_that_already_exists(fake_graph):
    """Re-running a connector against the same device (every scheduled
    Wazuh run reports the same laptop) must not create a duplicate Asset
    node each time."""
    fake_graph.query.return_value = [{"name": "Simo", "id": "already-there"}]
    CheckRegistry()._ingest_assets(
        _result([{"name": "Simo", "asset_type": "Endpoint"}]),
        "tenant-1",
    )
    fake_graph.write.assert_not_called()


def test_ingest_assets_dedups_within_a_single_result_too(fake_graph):
    """Defensive: even if one check's discovered_assets somehow lists the
    same name twice, only one Asset node gets created."""
    fake_graph.query.return_value = []
    CheckRegistry()._ingest_assets(
        _result([
            {"name": "Simo", "asset_type": "Endpoint"},
            {"name": "Simo", "asset_type": "Endpoint"},
        ]),
        "tenant-1",
    )
    assert fake_graph.write.call_count == 3  # one CREATE_ASSET + its two side effects


def test_ingest_assets_ignores_an_entry_with_no_name(fake_graph):
    fake_graph.query.return_value = []
    CheckRegistry()._ingest_assets(_result([{"asset_type": "Endpoint"}]), "tenant-1")
    fake_graph.write.assert_not_called()


def test_ingest_assets_links_vulnerabilities_on_a_newly_created_asset(fake_graph):
    """The adapter-agnostic path: a scanner (Wazuh's indexer, Qualys,
    CrowdStrike Spotlight...) reports precise per-device CVEs alongside
    the asset itself, and they get linked the same run it's created."""
    fake_graph.query.return_value = []
    CheckRegistry()._ingest_assets(
        _result([{
            "name": "Simo", "asset_type": "Endpoint",
            "vulnerabilities": ["CVE-2024-1234", "CVE-2024-5678"],
        }]),
        "tenant-1",
    )

    # CREATE_ASSET + 2 onboarding side effects + 2 vulnerability links.
    assert fake_graph.write.call_count == 5
    _, create_params = fake_graph.write.call_args_list[0][0]
    asset_id = create_params["id"]

    linked_cves = set()
    for call in fake_graph.write.call_args_list[3:]:
        _, link_params = call[0]
        assert link_params["asset_id"] == asset_id
        assert link_params["tenant_id"] == "tenant-1"
        linked_cves.add(link_params["cve_id"])
    assert linked_cves == {"CVE-2024-1234", "CVE-2024-5678"}


def test_ingest_assets_links_vulnerabilities_on_an_already_existing_asset(fake_graph):
    """An asset that already exists (created on a previous run, or added
    by hand) still gets fresh vulnerability links -- without re-running
    CREATE_ASSET or its onboarding side effects."""
    fake_graph.query.return_value = [{"name": "Simo", "id": "existing-id"}]
    CheckRegistry()._ingest_assets(
        _result([{"name": "Simo", "vulnerabilities": ["CVE-2024-9999"]}]),
        "tenant-1",
    )

    assert fake_graph.write.call_count == 1
    _, link_params = fake_graph.write.call_args_list[0][0]
    assert link_params == {"asset_id": "existing-id", "tenant_id": "tenant-1", "cve_id": "CVE-2024-9999"}


def _write_side_effect(ransomware_use):
    """
    fake_graph.write is one Mock shared across every run_write call in a
    single _ingest_assets run (CREATE_ASSET, the two onboarding side
    effects, MERGE_VULNERABILITY_FROM_FINDING, ENSURE_RISK_FOR_
    VULNERABILITY, LINK_VULNERABILITY_TO_ASSET) -- a plain .return_value
    can't tell those apart, so the risk-cascade tests below need a
    side_effect that inspects which query is actually being run and only
    fakes MERGE_VULNERABILITY_FROM_FINDING's real return shape
    (see its docstring for why ransomware_use is on it at all).
    """
    def _side_effect(query, params):
        if query == app_queries.MERGE_VULNERABILITY_FROM_FINDING:
            return [{"id": params["cve_id"], "ransomware_use": ransomware_use}]
        return []
    return _side_effect


def _ensure_risk_call(fake_graph):
    """The one write call (if any) whose query resolves to
    ENSURE_RISK_FOR_VULNERABILITY -- a stub string under this test's
    graphrisk_core stub (see conftest.py), same as any other query this
    checkout doesn't have graphrisk-core connected to develop against
    directly, but still a real, distinct, deterministic value per name."""
    matches = [
        call[0][1] for call in fake_graph.write.call_args_list
        if call[0][0] == app_queries.ENSURE_RISK_FOR_VULNERABILITY
    ]
    return matches[0] if matches else None


def test_ingest_assets_cascades_a_generic_risk_for_a_critical_finding_on_a_new_asset(fake_graph):
    """The gap this closes: without this, a Critical/High finding got
    linked to the asset (EXPOSES) but Blast Radius and Vulnerability
    Impact -- which both walk Risk-IMPACTS->Asset, not Vulnerability-
    EXPOSES->Asset -- would never show it."""
    fake_graph.query.return_value = []
    fake_graph.write.side_effect = _write_side_effect(ransomware_use=False)
    CheckRegistry()._ingest_assets(
        _result([{
            "name": "Simo", "asset_type": "Endpoint",
            "vulnerabilities": [{"cve_id": "CVE-2026-1111", "severity": "Critical"}],
        }]),
        "tenant-1",
    )

    risk_params = _ensure_risk_call(fake_graph)
    assert risk_params is not None, "expected an ENSURE_RISK_FOR_VULNERABILITY write"
    assert risk_params["title"] == "Unpatched Vulnerability Risk"
    assert risk_params["likelihood"] == 4
    assert risk_params["impact"] == 5
    assert risk_params["tenant_id"] == "tenant-1"
    # Same asset_id CREATE_ASSET generated -- the whole point is linking
    # back to *this* device, not some other asset.
    create_params = fake_graph.write.call_args_list[0][0][1]
    assert risk_params["asset_id"] == create_params["id"]


def test_ingest_assets_reuses_the_ransomware_risk_when_the_cve_is_flagged(fake_graph):
    """A CVE that's already NVD/CISA-KEV-ingested with known ransomware
    use rolls into the tenant's existing "Ransomware Infection Risk"
    instead of a new generic one -- so it immediately inherits whatever
    Control already mitigates that risk (e.g. the demo seed's EDR
    control), with no new seed data needed for it to show up in Blast
    Radius."""
    fake_graph.query.return_value = []
    fake_graph.write.side_effect = _write_side_effect(ransomware_use=True)
    CheckRegistry()._ingest_assets(
        _result([{
            "name": "Simo", "asset_type": "Endpoint",
            "vulnerabilities": [{"cve_id": "CVE-2026-2222", "severity": "High"}],
        }]),
        "tenant-1",
    )

    risk_params = _ensure_risk_call(fake_graph)
    assert risk_params is not None
    assert risk_params["title"] == "Ransomware Infection Risk"
    assert risk_params["likelihood"] == 3
    assert risk_params["impact"] == 4


def test_ingest_assets_does_not_cascade_a_risk_for_a_medium_severity_finding(fake_graph):
    """Medium/Low findings still become a linked Vulnerability node
    (EXPOSES) -- they just don't cascade into a Risk, matching Wazuh's
    own Critical/High-only ingestion cutoff."""
    fake_graph.query.return_value = []
    fake_graph.write.side_effect = _write_side_effect(ransomware_use=False)
    CheckRegistry()._ingest_assets(
        _result([{
            "name": "Simo", "asset_type": "Endpoint",
            "vulnerabilities": [{"cve_id": "CVE-2026-3333", "severity": "Medium"}],
        }]),
        "tenant-1",
    )

    assert _ensure_risk_call(fake_graph) is None
    merged = [
        call[0][1] for call in fake_graph.write.call_args_list
        if call[0][0] == app_queries.MERGE_VULNERABILITY_FROM_FINDING
    ]
    assert len(merged) == 1  # the Vulnerability node + EXPOSES link still happen


def test_ingest_assets_cascades_risk_on_an_already_existing_asset_too(fake_graph):
    """The risk cascade isn't tied to the new-asset branch -- a device
    Wazuh already reported on a previous run still gets a Risk linked
    for a newly-seen Critical/High finding."""
    fake_graph.query.return_value = [{"name": "Simo", "id": "existing-id"}]
    fake_graph.write.side_effect = _write_side_effect(ransomware_use=False)
    CheckRegistry()._ingest_assets(
        _result([{
            "name": "Simo",
            "vulnerabilities": [{"cve_id": "CVE-2026-4444", "severity": "Critical"}],
        }]),
        "tenant-1",
    )

    risk_params = _ensure_risk_call(fake_graph)
    assert risk_params is not None
    assert risk_params["asset_id"] == "existing-id"


def _ingest_one_finding(fake_graph, ransomware_use, cve_id="CVE-2026-3333", severity="Critical"):
    fake_graph.query.return_value = []
    fake_graph.write.side_effect = _write_side_effect(ransomware_use=ransomware_use)
    CheckRegistry()._ingest_assets(
        _result([{
            "name": "Simo", "asset_type": "Endpoint",
            "vulnerabilities": [{"cve_id": cve_id, "severity": severity, "source": "Wazuh (NVD)"}],
        }]),
        "tenant-1",
    )
    return _ensure_risk_call(fake_graph)


def test_cisa_kev_known_ransomware_string_files_under_ransomware_risk(fake_graph):
    # CISA KEV's real value is the string "Known", not a boolean.
    params = _ingest_one_finding(fake_graph, ransomware_use="Known")
    assert params["title"] == "Ransomware Infection Risk"


def test_cisa_kev_unknown_ransomware_string_is_not_treated_as_ransomware(fake_graph):
    # Regression: "Unknown" is a non-empty string, and a bare truthiness
    # check filed every KEV-listed CVE under Ransomware Infection Risk.
    params = _ingest_one_finding(fake_graph, ransomware_use="Unknown")
    assert params["title"] == "Unpatched Vulnerability Risk"


def test_risk_link_records_the_driving_cve(fake_graph):
    params = _ingest_one_finding(fake_graph, ransomware_use=None, cve_id="CVE-2026-4444")
    assert params["cve_id"] == "CVE-2026-4444"
    assert params["source"] == "Wazuh (NVD)"
