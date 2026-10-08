"""
Recommended actions -- app/recommendations.py. Built from the shapes the
asset page already has (merged profile, fix_first, risks), using the test
tenant's real numbers for the risks.
"""
from app.recommendations import assess_asset_risks, recommend_for_asset

PROFILE = {
    "software": {"fields": {}, "sources": [{"source": "wazuh", "name": "Wazuh"}]},
    "health": {"fields": {"status": "online"}, "sources": [{"source": "wazuh", "name": "Wazuh"}]},
    "protection": {"fields": {
        "status": "Active", "product": "Microsoft Defender Antivirus",
        "policy": "Microsoft Defender settings: 6 of 9 CIS benchmark checks pass",
        "policy_gaps": ["Ensure 'Turn on behavior monitoring' is set to 'Enabled'"],
    }, "sources": [{"source": "wazuh", "name": "Wazuh"}]},
    "configuration": {"fields": {"benchmarks": [{
        "name": "CIS Microsoft Windows 10 Enterprise Benchmark v4.0.0", "score": 27, "passed": 115, "failed": 302,
        "failed_checks": [{"title": "Ensure 'Minimum password age' is set to '1 or more day(s)'",
                           "remediation": "Set it to 1 or more days."}],
    }]}, "sources": [{"source": "wazuh", "name": "Wazuh"}]},
}
FIX_FIRST = [
    {"name": "WinRAR", "version": "5.70", "cve_count": 5, "max_severity": "High", "ransomware": True,
     "max_cvss": 8.8, "cves": [{"cve_id": "CVE-2025-8088"}, {"cve_id": "CVE-2023-38831"}]},
    {"name": "Python 3.9.13", "cve_count": 18, "max_severity": "Critical", "ransomware": False, "max_cvss": 9.8, "cves": []},
    {"name": "n8n", "version": "1.120.4", "cve_count": 87, "max_severity": "High", "ransomware": False, "max_cvss": 8.8, "cves": []},
]
RISKS = [
    {"id": "r1", "title": "Unpatched Vulnerability Risk", "likelihood": 3, "impact": 4, "controls": [
        {"id": "vpm", "title": "Vulnerability & Patch Management", "effectiveness": 0.0, "strength": 0.8},
        {"id": "scb", "title": "Secure Configuration Baseline", "effectiveness": 0.2758, "strength": 0.4}]},
    {"id": "r2", "title": "Ransomware Infection Risk", "likelihood": 3, "impact": 5, "controls": [
        {"id": "vpm", "title": "Vulnerability & Patch Management", "effectiveness": 0.0, "strength": 0.6},
        {"id": "scb", "title": "Secure Configuration Baseline", "effectiveness": 0.2758, "strength": 0.5},
        {"id": "edr", "title": "Endpoint Detection & Response", "effectiveness": 1.0, "strength": 0.7}]},
]


def _actions(profile=PROFILE, fix_first=FIX_FIRST, appetite=4.0):
    return recommend_for_asset(profile, fix_first, assess_asset_risks(RISKS, appetite))


def test_risks_on_the_device_get_scores_and_verdicts():
    risks = {r["title"]: r for r in assess_asset_risks(RISKS, 4.0)}
    assert risks["Unpatched Vulnerability Risk"]["current_score"] == 10.68
    assert risks["Unpatched Vulnerability Risk"]["assessment"]["status"] == "not_adequate"
    assert risks["Ransomware Infection Risk"]["assessment"]["status"] == "relies_on_control"


def test_actions_are_ranked_ransomware_patch_first():
    titles = [(a["priority"], a["title"]) for a in _actions()]
    assert titles[:3] == [
        ("critical", "Update or remove WinRAR 5.70"),
        ("high", "Update or remove Python 3.9.13"),
        ("high", "Unpatched Vulnerability Risk is not adequately controlled"),
    ]
    assert ("medium", "Fix 1 Microsoft Defender setting") in titles
    assert ("medium", "Fix failed CIS Microsoft Windows 10 Enterprise Benchmark v4.0.0 checks") in titles


def test_each_action_names_the_control_and_risks_it_helps():
    winrar = _actions()[0]
    assert winrar["source"] == "Wazuh"
    assert winrar["helps"] == {"control": "Vulnerability & Patch Management",
                               "risks": ["Unpatched Vulnerability Risk", "Ransomware Infection Risk"]}
    assert winrar["cves"] == ["CVE-2025-8088", "CVE-2023-38831"]
    cis = next(a for a in _actions() if a["category"] == "configuration")
    assert cis["steps"] == ["Ensure 'Minimum password age' is set to '1 or more day(s)' — Set it to 1 or more days."]
    assert cis["helps"]["control"] == "Secure Configuration Baseline"


def test_missing_antivirus_and_a_silent_agent_are_flagged():
    profile = {**PROFILE,
               "protection": {"fields": {"status": "Not detected"}, "sources": [{"name": "Wazuh"}]},
               "health": {"fields": {"status": "offline", "last_seen": "2026-10-01T09:00:00"}, "sources": [{"name": "Wazuh"}]}}
    actions = _actions(profile=profile)
    assert actions[1]["title"] == "No antivirus or EDR is running" and actions[1]["priority"] == "critical"
    agent = next(a for a in actions if a["category"] == "health")
    assert agent["priority"] == "high" and "last seen 2026-10-01T09:00:00" in agent["detail"]


def test_no_evidence_means_no_advice():
    # A device no connector reports on (e.g. added by hand) gets only the
    # risk-level verdicts -- nothing is invented.
    actions = recommend_for_asset({}, [], assess_asset_risks([], 4.0))
    assert actions == []


def test_the_asset_page_returns_recommendations(client, fake_graph, as_user):
    from test_asset_profile import _get_profile  # same folder; pytest puts it on the path
    as_user(role="owner", graph_tenant_id="test")
    body = _get_profile(client, fake_graph).json()
    assert body["recommendations"][0]["title"] == "Update or remove WinRAR 6.02"
    assert body["recommendations"][0]["priority"] == "critical"
    assert body["risk_appetite"] == 4.0


# ── Refinements from the first real-data run ────────────────────────────────
from datetime import datetime, timezone

from app.api.v1.assets import _fix_first
from app.recommendations import data_age_hours


def test_one_install_listed_under_two_names_becomes_one_action():
    packages = [
        {"name": "Microsoft ASP.NET Core 8.0.14 - Shared Framework (x86)", "version": "8.0.14.25112",
         "cve_ids": ["CVE-A", "CVE-B"], "cve_count": 2, "max_severity": "High"},
        {"name": "Microsoft ASP.NET Core 8.0.14 Shared Framework (x86)", "version": "8.0.14.25112",
         "cve_ids": ["CVE-B", "CVE-C"], "cve_count": 2, "max_severity": "Critical"},
        {"name": "Microsoft ASP.NET Core 8.0.14 Shared Framework (x86)", "version": "9.0.1",
         "cve_ids": ["CVE-D"], "cve_count": 1, "max_severity": "High"},
    ]
    out = _fix_first(packages, {})
    assert len(out) == 2                                    # different version stays separate
    merged = next(p for p in out if p["version"] == "8.0.14.25112")
    assert [c["cve_id"] for c in merged["cves"]] == ["CVE-A", "CVE-B", "CVE-C"]
    assert merged["cve_count"] == 3 and merged["max_severity"] == "Critical"


def test_patch_actions_name_rating_and_cvss_separately_without_repeated_steps():
    n8n = {"name": "n8n", "version": "1.120.4", "cve_count": 87, "max_severity": "Critical",
           "ransomware": False, "max_cvss": 8.8, "cves": []}
    action = recommend_for_asset({}, [n8n], [])[0]
    assert action["detail"] == "87 CVEs, rated Critical, highest CVSS 8.8."
    assert action["steps"] == []


def test_stale_device_data_is_called_out():
    profile = {"health": {"fields": {"status": "online"},
                          "sources": [{"name": "Wazuh", "collected_at": "2026-10-06T19:32:00+00:00"}]}}
    now = datetime(2026, 10, 8, 7, 32, tzinfo=timezone.utc)
    assert data_age_hours(profile, now) == 36.0
    stale = [a for a in recommend_for_asset(profile, [], [], now=now) if a["category"] == "health"]
    assert stale[0]["title"] == "Re-run Wazuh: this device's data is 36 hours old"
    # Fresh data: nothing to say.
    assert recommend_for_asset(profile, [], [], now=datetime(2026, 10, 6, 21, 0, tzinfo=timezone.utc)) == []


# ── Progress-based control health (every fix counts) ────────────────────────
from app.connectors.models import CheckCategory, CheckResult, CheckStatus
from app.connectors.registry import CheckRegistry
from app.graph import queries as graph_queries


def _patch_result(open_weight, devices=1):
    return CheckResult(
        check_id="wazuh_vulnerability_patching", check_name="Patching", category=CheckCategory.ENDPOINT,
        source="wazuh", tenant_id="test", status=CheckStatus.FAIL, score=0.0,
        detail="findings open", control_title="Vulnerability & Patch Management",
        raw_data={"progress": {"open_weight": open_weight, "devices": devices}},
    )


def test_each_resolved_finding_raises_control_health(fake_graph):
    # The worst load ever seen for this control was 1697 (the laptop's first scan).
    fake_graph.write.side_effect = lambda q, p=None: (
        [{"peak": 1697.0}] if q == graph_queries.RECORD_CONTROL_PEAK else [])
    reg = CheckRegistry()

    first = _patch_result(1697.0)
    reg._apply_progress(first)
    assert first.score == 0.0

    after_winrar = _patch_result(1669.0)          # 7 High findings fixed (7 x 4)
    reg._apply_progress(after_winrar)
    assert after_winrar.score == round(1 - 1669 / 1697, 4)
    assert after_winrar.detail.endswith("2% of the worst level seen has been resolved")

    all_fixed = _patch_result(0.0)
    reg._apply_progress(all_fixed)
    assert all_fixed.score == 1.0 and all_fixed.status == CheckStatus.PASS


def test_progress_baseline_is_recorded_per_tenant_and_control(fake_graph):
    fake_graph.write.side_effect = lambda q, p=None: []
    CheckRegistry()._apply_progress(_patch_result(12.0))
    calls = [c.args for c in fake_graph.write.call_args_list if c.args[0] == graph_queries.RECORD_CONTROL_PEAK]
    assert calls[0][1] == {"tenant_id": "test", "control_title": "Vulnerability & Patch Management",
                           "open_weight": 12.0}
