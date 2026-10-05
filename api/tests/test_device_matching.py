"""
Step 3 of the universal device profile: one device reported by several
connectors becomes one asset. Merged automatically only on a strong
identifier (serial number, MAC address, cloud instance id); a shared
hostname alone is flagged as "possibly the same device", never merged.
"""
from app.connectors.base import BaseConnector
from app.connectors.models import CheckResult, CheckStatus, CheckCategory
from app.connectors.profile import device_keys, hostname_key
from app.connectors.registry import CheckRegistry
from app.graph import queries as Q


# ── Identifier extraction ────────────────────────────────────────────────────

def test_device_keys_keeps_strong_identifiers_and_drops_junk():
    keys = device_keys({
        "identity": {"serial_number": " pf3xyz ", "cloud_instance_id": "i-0abc", "hostname": "SIMO.corp.local"},
        "network": {"mac_addresses": [
            "3C-52-82-00-11-22",      # real, normalised
            "00:05:9a:3c:7a:00",      # Cisco AnyConnect virtual adapter
            "02:42:ac:11:00:02",      # locally administered (docker/randomised)
            "00:00:00:00:00:00",
        ]},
    })
    assert keys == {"serial": ["PF3XYZ"], "mac": ["3c:52:82:00:11:22"],
                    "instance": ["i-0abc"], "hostname": ["simo"]}


def test_placeholder_serials_and_generic_hostnames_are_ignored():
    assert device_keys({"identity": {"serial_number": "To be filled by O.E.M.", "hostname": "localhost"}}) == {}
    assert hostname_key("ubuntu") is None
    assert hostname_key("FIN-LT-07.example.org") == "fin-lt-07"


# ── Registry behaviour ───────────────────────────────────────────────────────

class _ToolA(BaseConnector):
    CONNECTOR_ID = "tool_a"
    CONNECTOR_NAME = "Tool A"
    PROFILE_SECTIONS = ("identity", "network", "os")
    def authenticate(self): pass
    def supported_checks(self): return []
    def run_check(self, check_id): raise NotImplementedError


def _registry():
    r = CheckRegistry()
    r.register(_ToolA, [])
    return r


def _result(assets):
    return CheckResult(check_id="c", check_name="C", category=CheckCategory.ENDPOINT, source="tool_a",
                       tenant_id="t1", status=CheckStatus.PASS, score=1.0, detail="ok",
                       discovered_assets=assets)


def _graph(fake_graph, assets, identifiers):
    def query(q, params):
        if q == Q.GET_ALL_ASSETS:
            return assets
        if q == Q.GET_ASSET_IDENTIFIERS:
            return identifiers
        return []
    fake_graph.query.side_effect = query


def _writes(fake_graph, q):
    return [c[0][1] for c in fake_graph.write.call_args_list if c[0][0] == q]


EXISTING = [{"name": "Simo", "id": "a1"}]
EXISTING_IDS = [{"id": "a1", "name": "Simo", "serial": ["PF3XYZ"], "mac": ["3c:52:82:00:11:22"],
                 "instance": [], "hostname": ["simo"]}]


def test_same_serial_under_another_name_merges_into_the_existing_asset(fake_graph):
    _graph(fake_graph, EXISTING, EXISTING_IDS)
    _registry()._ingest_assets(_result([{
        "name": "SIMO-LT",
        "profile": {"identity": {"serial_number": "PF3XYZ", "hostname": "SIMO-LT"}, "os": {"name": "Windows 11"}},
    }]), "t1")

    assert _writes(fake_graph, Q.CREATE_ASSET) == []
    profile_writes = _writes(fake_graph, Q.UPSERT_ASSET_PROFILE_SECTION)
    assert {w["asset_id"] for w in profile_writes} == {"a1"}
    ident = _writes(fake_graph, Q.MERGE_ASSET_IDENTIFIERS)[0]
    assert ident["asset_id"] == "a1"
    assert ident["aliases"] == ["SIMO-LT (tool_a, same serial number)"]
    assert _writes(fake_graph, Q.LINK_POSSIBLE_DUPLICATE) == []


def test_same_mac_merges_but_a_virtual_adapter_mac_does_not(fake_graph):
    _graph(fake_graph, EXISTING, EXISTING_IDS)
    _registry()._ingest_assets(_result([
        {"name": "laptop-wifi", "profile": {"network": {"mac_addresses": ["3C:52:82:00:11:22"]}}},
    ]), "t1")
    assert _writes(fake_graph, Q.CREATE_ASSET) == []

    fake_graph.write.reset_mock()
    ids = [dict(EXISTING_IDS[0], mac=["3c:52:82:00:11:22"])]
    _graph(fake_graph, EXISTING, ids)
    _registry()._ingest_assets(_result([
        # Only a VPN adapter MAC in common -- not evidence of the same machine.
        {"name": "other-box", "profile": {"network": {"mac_addresses": ["00:05:9a:3c:7a:00"]}}},
    ]), "t1")
    assert [w["name"] for w in _writes(fake_graph, Q.CREATE_ASSET)] == ["other-box"]


def test_hostname_only_match_is_flagged_not_merged(fake_graph):
    _graph(fake_graph, EXISTING, [dict(EXISTING_IDS[0], serial=[], mac=[])])
    _registry()._ingest_assets(_result([
        {"name": "SIMO", "profile": {"identity": {"hostname": "SIMO"}, "os": {"name": "Windows 11"}}},
    ]), "t1")

    created = _writes(fake_graph, Q.CREATE_ASSET)
    assert [w["name"] for w in created] == ["SIMO"]               # kept separate
    dup = _writes(fake_graph, Q.LINK_POSSIBLE_DUPLICATE)
    assert len(dup) == 1
    assert dup[0]["asset_id"] == created[0]["id"] and dup[0]["other_id"] == "a1"
    assert "same hostname" in dup[0]["reason"]


def test_two_records_with_one_serial_in_the_same_run_become_one_asset(fake_graph):
    _graph(fake_graph, [], [])
    _registry()._ingest_assets(_result([
        {"name": "web-01", "profile": {"identity": {"serial_number": "VMW-1234-ABCD"}}},
        {"name": "web-01.internal", "profile": {"identity": {"serial_number": "VMW-1234-ABCD"}}},
    ]), "t1")
    assert [w["name"] for w in _writes(fake_graph, Q.CREATE_ASSET)] == ["web-01"]


def test_assets_without_a_profile_skip_matching_entirely(fake_graph):
    _graph(fake_graph, [], [])
    _registry()._ingest_assets(_result([{"name": "manual-style"}]), "t1")
    assert not any(c[0][0] == Q.GET_ASSET_IDENTIFIERS for c in fake_graph.query.call_args_list)
    assert _writes(fake_graph, Q.MERGE_ASSET_IDENTIFIERS) == []


# ── API ──────────────────────────────────────────────────────────────────────

def test_profile_endpoint_reports_aliases_and_lookalikes_without_raw_identifiers(client, fake_graph, as_user):
    as_user(role="member", graph_tenant_id="t1")
    fake_graph.query.side_effect = [
        [{"asset": {"id": "a1", "name": "Simo", "aliases": ["SIMO-LT (crowdstrike, same serial number)"],
                    "device_serials": ["PF3XYZ"], "device_macs": ["3c:52:82:00:11:22"]},
          "risks": [], "vulnerabilities": [],
          "possible_duplicates": [{"id": "a2", "name": "SIMO", "reason": "same hostname, no shared serial/MAC/instance id"}]}],
        [],
    ]
    body = client.get("/api/v1/assets/a1/profile").json()
    assert body["also_known_as"] == ["SIMO-LT (crowdstrike, same serial number)"]
    assert body["possible_duplicates"][0]["name"] == "SIMO"
    assert not any(k.startswith("device_") for k in body["asset"])   # never leak serials/MACs
