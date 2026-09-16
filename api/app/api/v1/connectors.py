"""
API endpoints for the connector framework.
Includes a mock adapter registered alongside Entra ID so the whole
pipeline (registry -> adapter -> CheckResult -> Neo4j write) can be
tested end-to-end without needing real Entra ID / Azure credentials.
"""
from fastapi import APIRouter, HTTPException, Query
from app.connectors.registry import registry
from app.connectors.base import BaseConnector
from app.connectors.models import CheckResult, CheckStatus, CheckCategory

router = APIRouter()


# ── Mock adapter — proves the architecture works end-to-end ──────────────────
class MockAdapter(BaseConnector):
    """
    A fake connector with no real API calls, used to verify that the
    three-layer architecture (BaseConnector -> Registry -> Neo4j write)
    works correctly before wiring up real vendor credentials.
    """
    CONNECTOR_ID   = "mock"
    CONNECTOR_NAME = "Mock Connector (Testing)"

    def authenticate(self) -> None:
        # No real auth needed — just satisfy the token cache
        self._set_token("mock-token", expires_in=3600)

    def supported_checks(self) -> list[str]:
        return ["mock_mfa_check"]

    def run_check(self, check_id: str) -> CheckResult:
        # Simulate a realistic result without calling any external API
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


# ── Endpoints ──────────────────────────────────────────────────────────────
@router.get("/")
async def list_connectors():
    """List all registered connectors and their supported checks."""
    return {
        "connectors": registry.registered_connectors,
        "checks": registry.all_checks,
    }


@router.post("/run-check")
async def run_check(
    check_id: str = Query(description="e.g. mock_mfa_check, mfa_enabled"),
    tenant_id: str = Query(default="demo"),
):
    """
    Run a single check by check_id. The registry routes it to the
    correct adapter automatically based on which connector registered it.
    """
    try:
        # Mock adapter needs no real config; real adapters need vendor credentials
        config = {} if check_id.startswith("mock_") else {}
        result = registry.run_check(check_id, tenant_id, config)
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
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Check execution failed: {e}")


@router.post("/run-connector/{connector_id}")
async def run_connector(
    connector_id: str,
    tenant_id: str = Query(default="demo"),
):
    """Run every check supported by a specific connector."""
    try:
        config = {} if connector_id == "mock" else {}
        results = registry.run_all(connector_id, tenant_id, config)
        return {
            "connector_id": connector_id,
            "checks_run":   len(results),
            "results": [
                {
                    "check_id": r.check_id,
                    "status":   r.status.value,
                    "score":    r.score,
                    "detail":   r.detail,
                }
                for r in results
            ],
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Connector run failed: {e}")
