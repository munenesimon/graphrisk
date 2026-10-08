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
