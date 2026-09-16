"""
Layer 3 of the universal connector architecture: CheckRegistry.

The orchestration layer -- knows which adapter handles which check, routes
execution, writes CheckResult objects to Neo4j, and triggers blast radius
propagation. Adding a new vendor means registering its adapter class here;
nothing else in the system needs to change.
"""
import logging
from typing import Optional

from .base import BaseConnector, CheckError
from .models import CheckResult

logger = logging.getLogger(__name__)


# Neo4j write: update the Control node and cascade risk score recalculation
WRITE_RESULT = """
    MATCH (c:Control {title: $control_title, tenant_id: $tenant_id})
    SET c.implementation_status = CASE $status
            WHEN "PASS"    THEN "Implemented"
            WHEN "WARNING" THEN "PartiallyImplemented"
            WHEN "FAIL"    THEN "NotImplemented"
            ELSE c.implementation_status
        END,
        c.effectiveness_score = $score,
        c.last_tested_at      = datetime(),
        c.last_check_source   = $source,
        c.last_check_detail   = $detail
    WITH c
    OPTIONAL MATCH (c)-[:MITIGATES]->(r:Risk)
    SET r.risk_score = r.likelihood * r.impact * (1.0 - $score)
    RETURN c.title AS control, count(r) AS risks_updated
"""


class CheckRegistry:
    """
    Central registry mapping check_ids to the adapter class that implements them.
    A singleton instance (`registry`, below) is used throughout the application.
    """

    def __init__(self):
        self._adapters:  dict[str, type[BaseConnector]] = {}
        self._check_map: dict[str, str] = {}   # check_id -> connector_id

    def register(self, adapter_class: type[BaseConnector], checks: list[str]) -> None:
        """
        Register an adapter and the check_ids it implements.
        `checks` must be passed explicitly since supported_checks() is an
        instance method and adapters aren\'t instantiated until first use.
        """
        connector_id = adapter_class.CONNECTOR_ID
        self._adapters[connector_id] = adapter_class
        for check_id in checks:
            self._check_map[check_id] = connector_id
        logger.info(f"Registered connector: {connector_id} ({len(checks)} checks)")

    def run_check(self, check_id: str, tenant_id: str, config: dict) -> CheckResult:
        """Run a single check using whichever adapter implements it."""
        connector_id = self._check_map.get(check_id)
        if not connector_id:
            raise ValueError(f"No adapter registered for check: {check_id}")
        adapter_class = self._adapters[connector_id]
        adapter = adapter_class(tenant_id=tenant_id, config=config)

        config_error = adapter.validate_config()
        if config_error:
            raise ValueError(config_error.message)

        result = adapter.run_check(check_id)
        self._write_to_graph(result)
        return result

    def run_all(
        self, connector_id: str, tenant_id: str, config: dict
    ) -> tuple[list[CheckResult], list[CheckError]]:
        """
        Run every check supported by a specific connector.
        Returns (results, errors) so callers -- including the API layer --
        can report exactly what succeeded and what failed, and why.
        """
        adapter_class = self._adapters.get(connector_id)
        if not adapter_class:
            raise ValueError(f"Unknown connector: {connector_id}")
        adapter = adapter_class(tenant_id=tenant_id, config=config)
        results, errors = adapter.run_all_checks()
        for result in results:
            self._write_to_graph(result)
        return results, errors

    def _write_to_graph(self, result: CheckResult) -> None:
        """Write a CheckResult to Neo4j, updating the Control and cascading to Risks."""
        if not result.control_title:
            logger.warning(f"CheckResult {result.check_id} has no control_title -- skipping graph write")
            return
        try:
            from app.graph.connection import run_write
            run_write(WRITE_RESULT, {
                **result.to_neo4j_params(),
                "control_title": result.control_title,
            })
        except Exception as e:
            logger.error(f"Graph write failed for {result.check_id}: {e}")

    @property
    def registered_connectors(self) -> list[str]:
        return list(self._adapters.keys())

    @property
    def all_checks(self) -> dict[str, str]:
        """Map of check_id -> connector_id for every registered check."""
        return dict(self._check_map)


# ── Singleton registry — import `registry` from this module everywhere ────────
registry = CheckRegistry()
