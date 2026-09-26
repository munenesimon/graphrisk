"""
Confirms the multi-tenancy fix documented at the top of
app/api/v1/connectors.py holds across the other data routers too: the
tenant scoping every graph query uses comes from the verified JWT
(user.graph_tenant_id), never from a client-supplied parameter, so one
tenant can never see or write another tenant's data by passing a
different id somewhere in the request.
"""
import pytest


LIST_ENDPOINTS = [
    ("/api/v1/assets/", "GET_ALL_ASSETS"),
    ("/api/v1/risks/", "GET_ALL_RISKS"),
    ("/api/v1/controls/", "GET_ALL_CONTROLS"),
]


@pytest.mark.parametrize("path,expected_query_name", LIST_ENDPOINTS)
def test_list_endpoint_scopes_by_the_jwts_tenant(client, fake_graph, as_user, path, expected_query_name):
    as_user(graph_tenant_id="tenant-a")
    resp = client.get(path)
    assert resp.status_code == 200, resp.text

    assert fake_graph.query.call_count >= 1
    query_arg, params_arg = fake_graph.query.call_args.args
    assert params_arg["tenant_id"] == "tenant-a"
    assert expected_query_name in query_arg  # our stub queries.__getattr__ echoes the name back


@pytest.mark.parametrize("path", [p for p, _ in LIST_ENDPOINTS])
def test_list_endpoint_ignores_a_client_supplied_tenant_query_param(client, fake_graph, as_user, path):
    """These routes don't even declare a tenant_id parameter -- confirm
    trying to smuggle one in via the query string has no effect at all."""
    as_user(graph_tenant_id="tenant-a")
    resp = client.get(path, params={"tenant_id": "someone-elses-tenant"})
    assert resp.status_code == 200, resp.text
    _, params_arg = fake_graph.query.call_args.args
    assert params_arg["tenant_id"] == "tenant-a"


def test_two_different_users_are_scoped_to_their_own_tenants(client, fake_graph, as_user):
    as_user(graph_tenant_id="tenant-a")
    client.get("/api/v1/assets/")
    _, params_a = fake_graph.query.call_args.args
    assert params_a["tenant_id"] == "tenant-a"

    as_user(graph_tenant_id="tenant-b")
    client.get("/api/v1/assets/")
    _, params_b = fake_graph.query.call_args.args
    assert params_b["tenant_id"] == "tenant-b"


class TestDashboardSummary:
    def test_dashboard_reports_the_jwts_own_tenant(self, client, fake_graph, as_user):
        as_user(graph_tenant_id="tenant-a")
        resp = client.get("/api/v1/dashboard/summary")
        assert resp.status_code == 200, resp.text
        assert resp.json()["tenant_id"] == "tenant-a"

        calls = fake_graph.query.call_args_list
        # dashboard.py queries a mix of {"t": ...} and {"tenant_id": ...} params
        tenant_values = {
            params.get("t") or params.get("tenant_id")
            for _, params in (c.args for c in calls)
            if params.get("t") or params.get("tenant_id")
        }
        assert tenant_values == {"tenant-a"}

    def test_dashboard_ignores_a_client_supplied_tenant_id(self, client, fake_graph, as_user):
        """dashboard_summary() takes no tenant parameter at all -- there is
        no field for a client to even attempt to override."""
        as_user(graph_tenant_id="tenant-a")
        resp = client.get("/api/v1/dashboard/summary", params={"tenant_id": "attacker-tenant"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["tenant_id"] == "tenant-a"


def test_get_by_id_endpoint_also_scopes_by_jwt_tenant(client, fake_graph, as_user):
    as_user(graph_tenant_id="tenant-a")
    fake_graph.query.return_value = []
    resp = client.get("/api/v1/assets/some-asset-id")
    assert resp.status_code in (200, 404)
    _, params_arg = fake_graph.query.call_args.args
    assert params_arg["tenant_id"] == "tenant-a"
    assert params_arg["asset_id"] == "some-asset-id"
