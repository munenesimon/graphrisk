"""
API endpoints for the connector framework.
Includes a mock adapter registered alongside the real connectors so the
whole pipeline (registry -> adapter -> CheckResult -> Neo4j write) can be
tested end-to-end without needing real vendor credentials.

Tenant scoping: the tenant for any check run comes from the verified JWT
(user.graph_tenant_id), never from a client-supplied query parameter --
this matches the same fix already applied to dashboard, assets, risks,
controls, and blast_radius.
"""
from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel
from app.connectors.registry import registry
from app.connectors.base import BaseConnector
from app.connectors.models import CheckResult, CheckStatus, CheckCategory
from app.auth.jwt_auth import get_current_user, CurrentUser

router = APIRouter()


# -- Mock adapter -- proves the architecture works end-to-end -----------------
class MockAdapter(BaseConnector):
    """
    A fake connector with no real API calls, used to verify that the
    three-layer architecture (BaseConnector -> Registry -> Neo4j write)
    works correctly before wiring up real vendor credentials.
    """
    CONNECTOR_ID   = "mock"
    CONNECTOR_NAME = "Mock Connector (Testing)"
    REQUIRED_CONFIG_KEYS: list[str] = []

    def authenticate(self) -> None:
        self._set_token("mock-token", expires_in=3600)

    def supported_checks(self) -> list[str]:
        return ["mock_mfa_check"]

    def run_check(self, check_id: str) -> CheckResult:
        return CheckResult(
            check_id="mock_mfa_check",
            check_name="Mock MFA Check",
            category=CheckCategory.IAM,
            source=self.CONNECTOR_ID,
            tenant_id=self.tenant_id,
            status=CheckStatus.PASS,
            score=0.9,
            affected_count=1,
            total_count=10,
            detail="Mock result: 1 of 10 simulated users without MFA",
            control_title="Multi-Factor Authentication",
        )


registry.register(MockAdapter, ["mock_mfa_check"])


# -- Request body for real connector credentials -------------------------------
class ConnectorRunRequest(BaseModel):
    """
    Per-vendor config (api_url/username/password, tenant_id/client_id/
    client_secret, etc. -- whatever that adapter's REQUIRED_CONFIG_KEYS
    lists) for connectors that need real credentials to run.

    Defaults to an empty dict so existing mock-check calls with no body
    keep working exactly as before -- this used to be the ONLY value ever
    passed to any connector (see the note below), which meant entra_id,
    aws, okta, and now wazuh could never actually run against a real
    vendor through this API at all, only mock. That's fixed here: the
    caller now supplies real config per-request rather than it being
    silently hardcoded to {} regardless of which connector was asked for.
    """
    config: dict = {}


# -- Endpoints ------------------------------------------------------------
@router.get("/")
async def list_connectors(user: CurrentUser = Depends(get_current_user)):
    """List all registered connectors and their supported checks. Global, not tenant-scoped."""
    return {
        "connectors": registry.registered_connectors,
        "checks": registry.all_checks,
    }


@router.post("/run-check")
async def run_check(
    check_id: str = Query(description="e.g. mock_mfa_check, wazuh_agent_connectivity"),
    body: ConnectorRunRequest = ConnectorRunRequest(),
    user: CurrentUser = Depends(get_current_user),
):
    """
    Run a single check by check_id, scoped to the caller's own tenant
    (from their verified JWT). The registry routes it to the correct
    adapter automatically based on which connector registered it.
    Real connectors need their credentials in the request body, e.g.:
        {"config": {"api_url": "https://your-manager:55000",
                     "username": "...", "password": "..."}}
    """
    try:
        result = registry.run_check(check_id, user.graph_tenant_id, body.config)
        return {
            "check_id":       result.check_id,
            "source":         result.source,
            "status":         result.status.value,
            "score":          result.score,
            "detail":         result.detail,
            "affected_count": result.affected_count,
            "total_count":    result.total_count,
            "control_title":  result.control_title,
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Check execution failed: {e}")


@router.post("/run-connector/{connector_id}")
async def run_connector(
    connector_id: str,
    body: ConnectorRunRequest = ConnectorRunRequest(),
    user: CurrentUser = Depends(get_current_user),
):
    """
    Run every check supported by a specific connector, scoped to the
    caller's own tenant. The response always reports both successful
    results and any errors -- a connector with missing credentials
    returns HTTP 200 with an empty results list and a populated errors
    list explaining exactly why, rather than a silent empty response.
    Real connectors need their credentials in the request body -- see
    run_check above for the shape.
    """
    try:
        results, errors = registry.run_all(connector_id, user.graph_tenant_id, body.config)
        return {
            "connector_id": connector_id,
            "checks_run":   len(results),
            "checks_failed": len(errors),
            "results": [
                {
                    "check_id": r.check_id,
                    "status":   r.status.value,
                    "score":    r.score,
                    "detail":   r.detail,
                }
                for r in results
            ],
            "errors": [e.to_dict() for e in errors],
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Connector run failed: {e}")
