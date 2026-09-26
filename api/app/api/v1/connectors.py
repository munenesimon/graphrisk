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
import logging
import uuid

from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel
from app.connectors.registry import registry
from app.connectors.base import BaseConnector
from app.connectors.models import CheckResult, CheckStatus, CheckCategory
from app.connectors.crypto import encrypt_config, decrypt_config, ConfigDecryptionError
from app.auth.jwt_auth import get_current_user, CurrentUser
from app.graph.connection import run_query, run_write

router = APIRouter()
logger = logging.getLogger(__name__)

CONFIG_EDITORS = {"owner", "admin"}

# -- Saved connector config (per tenant, per connector) -------------------
# One ConnectorConfig node per (tenant_id, connector_id) pair. The config
# itself is stored as a single Fernet-encrypted JSON blob (see crypto.py) --
# never as individual plaintext properties -- and config_keys duplicates
# just the *names* of the keys inside it in plaintext, purely so GET
# /config can report what's saved without ever decrypting anything.
SET_CONNECTOR_CONFIG = """
    MERGE (cc:ConnectorConfig {tenant_id: $tenant_id, connector_id: $connector_id})
    SET cc.encrypted_config = $encrypted_config,
        cc.config_keys      = $config_keys,
        cc.updated_at       = datetime()
    RETURN cc.connector_id AS connector_id
"""

GET_CONNECTOR_CONFIGS = """
    MATCH (cc:ConnectorConfig {tenant_id: $tenant_id})
    RETURN cc.connector_id AS connector_id, cc.config_keys AS config_keys, cc.updated_at AS updated_at
"""

GET_CONNECTOR_CONFIG_ONE = """
    MATCH (cc:ConnectorConfig {tenant_id: $tenant_id, connector_id: $connector_id})
    RETURN cc.encrypted_config AS encrypted_config
"""

DELETE_CONNECTOR_CONFIG = """
    MATCH (cc:ConnectorConfig {tenant_id: $tenant_id, connector_id: $connector_id})
    DELETE cc
    RETURN count(cc) AS deleted
"""


def _load_stored_config(tenant_id: str, connector_id: str) -> dict:
    """Decrypted saved config for one (tenant, connector) pair, or {} if none is saved."""
    rows = run_query(GET_CONNECTOR_CONFIG_ONE, {"tenant_id": tenant_id, "connector_id": connector_id})
    encrypted = rows[0].get("encrypted_config") if rows else None
    if not encrypted:
        return {}
    try:
        return decrypt_config(encrypted)
    except ConfigDecryptionError as e:
        logger.error(f"{connector_id}/{tenant_id}: {e}")
        return {}


# Config keys that determine *where* a connector sends requests. These may
# only ever come from a tenant's saved config (set by an owner/admin via
# PUT /{connector_id}/config) -- never from a per-request override. Letting
# a request body set one of these let any authenticated tenant member
# redirect a connector's real, stored credentials to an attacker-controlled
# host (credential exfiltration via the OAuth/basic-auth flow) and/or use
# the backend as an open SSRF proxy. Matched by substring, case-insensitive,
# so it also covers keys future adapters might introduce (endpoint_url,
# webhook_host, etc.), not just today's base_url/api_url/org_url.
_CONNECTION_KEY_MARKERS = ("url", "endpoint", "host", "domain")


def _is_connection_key(key: str) -> bool:
    lowered = key.lower()
    return any(marker in lowered for marker in _CONNECTION_KEY_MARKERS)


def _merged_config(tenant_id: str, connector_id: str, override: dict) -> dict:
    """
    Saved config, with any *non-connection* keys present in `override`
    taking precedence -- lets a caller run with saved credentials
    untouched, or temporarily override a value like a secret to test it,
    without re-saving. Connection-endpoint keys (base_url/api_url/org_url
    and similar -- see _CONNECTION_KEY_MARKERS) are always dropped from
    `override`: they can only be set via the saved config, which requires
    the owner/admin role.
    """
    stored = _load_stored_config(tenant_id, connector_id)
    safe_override = {
        k: v for k, v in override.items() if v and not _is_connection_key(k)
    }
    rejected = sorted(k for k, v in override.items() if v and _is_connection_key(k))
    if rejected:
        logger.warning(
            f"{connector_id}/{tenant_id}: ignored disallowed config override key(s) "
            f"in run request: {rejected}"
        )
    return {**stored, **safe_override}


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


# -- Request bodies --------------------------------------------------------
class ConnectorRunRequest(BaseModel):
    """
    Per-vendor config (api_url/username/password, tenant_id/client_id/
    client_secret, etc. -- whatever that adapter's REQUIRED_CONFIG_KEYS
    lists) for connectors that need real credentials to run.

    Defaults to an empty dict so existing mock-check calls with no body
    keep working exactly as before. Any key supplied here is layered on
    top of that tenant's saved config for this connector, if any was set
    via PUT /{connector_id}/config -- so a caller can run with saved
    credentials untouched by sending {}, or override one field for a
    single run (e.g. test a new secret) without re-saving anything.
    """
    config: dict = {}


class SaveConnectorConfigRequest(BaseModel):
    """
    Config to encrypt and save for this tenant + connector, replacing
    whatever was saved before for that pair. Must be non-empty -- use
    DELETE /{connector_id}/config to clear a saved config instead of
    PUT-ing {}.
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


@router.get("/config")
async def list_connector_configs(user: CurrentUser = Depends(get_current_user)):
    """
    Which connectors this tenant has saved credentials for, and which
    config keys are set for each -- never the values themselves. Any
    authenticated tenant member can see this (it's not a secret which
    keys exist); only owner/admin can change it.
    """
    rows = run_query(GET_CONNECTOR_CONFIGS, {"tenant_id": user.graph_tenant_id})
    return {
        "configs": {
            r["connector_id"]: {
                "config_keys": sorted(r["config_keys"] or []),
                "updated_at": r["updated_at"].isoformat() if r.get("updated_at") else None,
            }
            for r in rows
        }
    }


@router.put("/{connector_id}/config")
async def save_connector_config(
    connector_id: str,
    body: SaveConnectorConfigRequest,
    user: CurrentUser = Depends(get_current_user),
):
    """
    Encrypt and save config for this tenant + connector, replacing any
    config saved for that pair before. Subsequent runs of this connector
    (run-check / run-connector) use it automatically unless overridden
    per-request. The plaintext values are never written anywhere except
    inside the encrypted blob -- see crypto.py.
    """
    if user.role not in CONFIG_EDITORS:
        raise HTTPException(status_code=403, detail="Only an organisation owner or admin can save connector credentials")
    if connector_id not in registry.registered_connectors:
        raise HTTPException(status_code=404, detail=f"Unknown connector: {connector_id}")
    if not body.config:
        raise HTTPException(status_code=400, detail="config must not be empty -- use DELETE to clear a saved config")

    config_keys = sorted(body.config.keys())
    run_write(SET_CONNECTOR_CONFIG, {
        "tenant_id": user.graph_tenant_id,
        "connector_id": connector_id,
        "encrypted_config": encrypt_config(body.config),
        "config_keys": config_keys,
    })
    return {"connector_id": connector_id, "config_keys": config_keys}


@router.delete("/{connector_id}/config")
async def delete_connector_config(connector_id: str, user: CurrentUser = Depends(get_current_user)):
    """Remove any saved config for this tenant + connector."""
    if user.role not in CONFIG_EDITORS:
        raise HTTPException(status_code=403, detail="Only an organisation owner or admin can delete connector credentials")
    result = run_write(DELETE_CONNECTOR_CONFIG, {"tenant_id": user.graph_tenant_id, "connector_id": connector_id})
    deleted = bool(result and result[0].get("deleted"))
    return {"connector_id": connector_id, "deleted": deleted}


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
    Credentials come from this tenant's saved config for that connector
    (if any), the request body, or both merged -- see ConnectorRunRequest.
    """
    try:
        connector_id = registry.all_checks.get(check_id)
        config = _merged_config(user.graph_tenant_id, connector_id, body.config) if connector_id else body.config
        result = registry.run_check(check_id, user.graph_tenant_id, config)
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
        error_id = uuid.uuid4().hex[:12]
        logger.exception(f"[{error_id}] run-check failed for check_id={check_id}")
        raise HTTPException(
            status_code=500,
            detail=f"Check execution failed (ref: {error_id}) -- see server logs for details",
        )


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
    Credentials come from this tenant's saved config for this connector
    (if any), the request body, or both merged -- see ConnectorRunRequest.
    """
    try:
        config = _merged_config(user.graph_tenant_id, connector_id, body.config)
        results, errors = registry.run_all(connector_id, user.graph_tenant_id, config)
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
        error_id = uuid.uuid4().hex[:12]
        logger.exception(f"[{error_id}] run-connector failed for connector_id={connector_id}")
        raise HTTPException(
            status_code=500,
            detail=f"Connector run failed (ref: {error_id}) -- see server logs for details",
        )
