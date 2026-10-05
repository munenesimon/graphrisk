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
        instance method and adapters aren't instantiated until first use.
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
        self._ingest_assets(result, tenant_id)
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
            self._ingest_assets(result, tenant_id)
        return results, errors

    def _write_to_graph(self, result: CheckResult) -> None:
        """Write a CheckResult to Neo4j, updating the Control and cascading to Risks."""
        if not result.control_title:
            logger.warning(f"CheckResult {result.check_id} has no control_title -- skipping graph write")
            return
        try:
            from app.graph.connection import run_write
            from graphrisk_core.queries import WRITE_CHECK_RESULT
            run_write(WRITE_CHECK_RESULT, {
                **result.to_neo4j_params(),
                "control_title": result.control_title,
            })
        except Exception as e:
            logger.error(f"Graph write failed for {result.check_id}: {e}")

    def _ingest_assets(self, result: CheckResult, tenant_id: str) -> None:
        """
        Upsert result.discovered_assets into the graph, reusing the exact
        same queries the Assets REST API uses -- CREATE_ASSET plus its two
        onboarding side effects for a new asset, LINK_VULNERABILITY_TO_ASSET
        for anything the adapter itself already knows is present on that
        asset -- so a connector-discovered asset and its vulnerabilities
        behave identically to what a person adds by hand through the UI:
        same CVE correlation, same risk cascade, same shape the
        Assets/Dashboard/Blast-Radius screens expect.

        This is deliberately adapter-agnostic: any connector can populate
        `vulnerabilities` (a list of CVE ids) on a discovered_assets entry
        once it has real per-device findings to report, not just Wazuh.
        Today that's Wazuh's indexer-backed vulnerability detection; a scanner
        like Qualys or CrowdStrike's Spotlight could report through the exact
        same field with no registry changes needed.

        De-duplicated on (tenant_id, name) in Python rather than a Cypher
        MERGE: re-running a connector (e.g. Wazuh reporting the same laptop
        every run) must not create a fresh Asset node each time, and reading
        the existing list first also means a completely wrong/misspelled
        asset_type here can't corrupt an asset a person already created and
        is managing by hand. Vulnerability links, by contrast, are relinked
        on every run regardless of whether the asset was just created or
        already existed -- LINK_VULNERABILITY_TO_ASSET is the same
        idempotent MERGE the REST endpoint relies on, so a CVE a device is
        still exposed to simply stays linked; nothing here removes a link
        for a CVE that stopped showing up in one run's findings, since a
        transient scan gap shouldn't read as "resolved."

        A dict-shaped (real finding detail) vulnerability also goes through
        _ensure_risk_for_finding below when it's Critical/High severity --
        CORRELATE_NEW_ASSET_AGAINST_ALL_VULNERABILITIES and
        LINK_VULNERABILITY_TO_ASSET only ever create (Vulnerability)-
        [:EXPOSES]->(Asset) edges, but Blast Radius and Vulnerability
        Impact both walk (Risk)-[:IMPACTS]->(Asset) instead, and nothing
        else creates that edge for a brand-new asset (CASCADE_RISK_ON_NEW_
        ASSET only rescales a Risk that's already linked). Without this
        step a connector-discovered device's real CVEs would be attached
        to it but invisible to both of those views.
        """
        if not result.discovered_assets:
            return
        try:
            import uuid
            from app.graph.connection import run_query, run_write
            # Imported as the `queries` module (like api/v1/assets.py does),
            # not `from graphrisk_core.queries import CREATE_ASSET` -- the
            # latter would raise ImportError under tests/conftest.py's stub,
            # which only gives `app.graph.queries` a fallback for unknown
            # attributes, not the raw graphrisk_core.queries module itself.
            from app.graph import queries

            existing_ids_by_name = {
                a["name"]: a.get("id")
                for a in run_query(queries.GET_ALL_ASSETS, {"tenant_id": tenant_id})
            }
            matcher = _DeviceMatcher(tenant_id, result)
            for asset in result.discovered_assets:
                name = asset.get("name")
                if not name:
                    continue
                asset_id = existing_ids_by_name.get(name)
                if asset_id is None:
                    # Same device already known under another name (another
                    # connector's hostname) -- matched on serial number, MAC
                    # address or cloud instance id; see _DeviceMatcher.
                    asset_id = matcher.find(asset.get("profile"))
                if asset.get("profile_only"):
                    # Detail about a device some other check discovers --
                    # never create an asset from it (see models.py).
                    if asset_id is not None:
                        self._store_profile(asset.get("profile"), asset_id, tenant_id, result)
                    continue
                if asset_id is None:
                    asset_id = str(uuid.uuid4())
                    run_write(queries.CREATE_ASSET, {
                        "id": asset_id,
                        "name": name,
                        "asset_type": asset.get("asset_type", "Endpoint"),
                        "criticality": asset.get("criticality", "Medium"),
                        "owner": asset.get("owner", f"{result.source} connector"),
                        "vendor": asset.get("vendor"),
                        "product": asset.get("product"),
                        "holds_personal_data": asset.get("holds_personal_data", False),
                        "environment": asset.get("environment", "Production"),
                        "tenant_id": tenant_id,
                    })
                    # Same onboarding side effects as POST /assets/ -- no-ops
                    # immediately if vendor/product weren't set on this asset.
                    run_write(queries.CORRELATE_NEW_ASSET_AGAINST_ALL_VULNERABILITIES, {
                        "asset_id": asset_id, "tenant_id": tenant_id,
                    })
                    run_write(queries.CASCADE_RISK_ON_NEW_ASSET, {
                        "asset_id": asset_id, "tenant_id": tenant_id,
                    })
                    existing_ids_by_name[name] = asset_id

                matcher.record(asset_id, name, asset.get("profile"))
                self._store_profile(asset.get("profile"), asset_id, tenant_id, result)

                for vuln in asset.get("vulnerabilities", []):
                    # A plain CVE id string means "link this if we already
                    # have it cataloged" (e.g. from NVD/CISA KEV ingestion);
                    # a dict means the adapter has real finding detail
                    # (severity, CVSS, description...) and wants a
                    # Vulnerability node created from it when one doesn't
                    # already exist -- see MERGE_VULNERABILITY_FROM_FINDING's
                    # own docstring for why that's ON CREATE-only.
                    if isinstance(vuln, dict):
                        cve_id = vuln.get("cve_id")
                    else:
                        cve_id = vuln
                    if not cve_id:
                        continue
                    if isinstance(vuln, dict):
                        merged = run_write(queries.MERGE_VULNERABILITY_FROM_FINDING, {
                            "cve_id": cve_id,
                            "description": vuln.get("description", ""),
                            "cvss_score": vuln.get("cvss_score", 0.0),
                            "severity": vuln.get("severity", "Unknown"),
                            "published_at": vuln.get("published_at", ""),
                            "source": vuln.get("source", result.source),
                        })
                        self._ensure_risk_for_finding(vuln, merged, asset_id, tenant_id)
                    run_write(queries.LINK_VULNERABILITY_TO_ASSET, {
                        "asset_id": asset_id, "tenant_id": tenant_id, "cve_id": cve_id,
                    })
        except Exception as e:
            logger.error(f"Asset ingestion failed for {result.check_id}: {e}")

    def _store_profile(self, raw_profile, asset_id: str, tenant_id: str, result: CheckResult) -> None:
        """
        Store a discovered asset's device profile, one snapshot per section,
        keyed on (asset, connector, section): a later run of the same
        connector replaces only its own sections, and another connector's
        view of the same device is never overwritten. Sections the adapter
        didn't declare in PROFILE_SECTIONS are ignored, so the declared
        capability and the stored data can't drift apart. A storage failure
        is logged and skipped -- device detail is never worth failing the
        connector run (or the asset/vulnerability writes) over.
        """
        from .profile import normalize_profile, to_storage
        profile = normalize_profile(raw_profile)
        if not profile:
            return
        adapter_class = self._adapters.get(result.source)
        declared = set(getattr(adapter_class, "PROFILE_SECTIONS", ()) or ())
        try:
            from app.graph.connection import run_write
            from app.graph import queries
            for section, fields in profile.items():
                if section != "extra" and section not in declared:
                    logger.warning(f"{result.source} reported undeclared profile section {section!r} -- ignored")
                    continue
                run_write(queries.UPSERT_ASSET_PROFILE_SECTION, {
                    "asset_id": asset_id,
                    "tenant_id": tenant_id,
                    "source": result.source,
                    "section": section,
                    "data": to_storage(fields),
                    "collected_at": result.executed_at.isoformat(),
                })
        except Exception as e:
            logger.error(f"Profile write failed for asset {asset_id} from {result.source}: {e}")

    # Severity -> (likelihood, impact) for a freshly-created Risk, on the
    # same 1-5 scale seed_demo.py's hand-authored risks use (e.g. "Identity
    # Compromise Risk" is likelihood=4, impact=5). Only Critical/High get a
    # Risk at all -- matches Wazuh's own DEFAULT_MIN_VULNERABILITY_SEVERITIES
    # cutoff, and the same reasoning applies to any future adapter: a
    # Medium/Low finding still becomes a Vulnerability node linked to the
    # asset (EXPOSES), it just doesn't cascade into a Risk.
    _RISK_PROFILE_BY_SEVERITY = {
        "Critical": {"likelihood": 4, "impact": 5},
        "High":     {"likelihood": 3, "impact": 4},
    }
    _RANSOMWARE_RISK_TITLE = "Ransomware Infection Risk"
    _GENERIC_VULNERABILITY_RISK_TITLE = "Unpatched Vulnerability Risk"

    def _ensure_risk_for_finding(self, vuln: dict, merge_result: list, asset_id: str, tenant_id: str) -> None:
        """
        Closes a gap CASCADE_RISK_ON_NEW_ASSET doesn't: that query only
        rescales a Risk already linked to an asset via IMPACTS, it never
        creates that link (see its own comment in graphrisk-core) -- so
        without this, a connector-reported CVE gets attached to an asset
        (EXPOSES) but stays invisible to both Blast Radius and
        Vulnerability Impact, which walk (Risk)-[:IMPACTS]->(Asset), not
        (Vulnerability)-[:EXPOSES]->(Asset). Discovered while investigating
        why a live Wazuh-ingested device wasn't showing up in Blast Radius
        under any control.

        A ransomware-flagged CVE (per merge_result's ransomware_use --
        see MERGE_VULNERABILITY_FROM_FINDING's docstring for where that
        comes from) rolls into "Ransomware Infection Risk" specifically,
        so it reuses whatever Control a tenant already has mitigating that
        risk (e.g. the demo seed's EDR control) instead of landing as a
        new, orphaned risk no Control's Blast Radius would ever reach.
        Everything else -- the common case, since most CVEs aren't
        ransomware-associated -- rolls into a generic "Unpatched
        Vulnerability Risk", which starts unmitigated until a human links
        a Control to it. That's an honest gap, not a bug to paper over:
        nothing in the tenant's graph actually claims to cover it yet.

        Only ever called for a dict-shaped (real finding detail) entry --
        a plain CVE-id string carries no severity here to gate on, so it
        stays link-only exactly as before (see the caller).
        """
        severity = vuln.get("severity", "Unknown")
        profile = self._RISK_PROFILE_BY_SEVERITY.get(severity)
        if not profile:
            return
        ransomware_use = merge_result[0].get("ransomware_use") if merge_result else None
        # CISA KEV records knownRansomwareCampaignUse as the *string* "Known"
        # or "Unknown" (data-ingestion/ingest/06_cisa_kev.py stores it as-is).
        # This used to be a bare truthiness check, which "Unknown" passes --
        # so every KEV-listed CVE was filed under Ransomware Infection Risk,
        # even with no evidence of ransomware use. Only an explicit "Known"
        # counts (True is accepted too, for any future boolean source).
        if ransomware_use is True or str(ransomware_use or "").strip().lower() == "known":
            title = self._RANSOMWARE_RISK_TITLE
            description = "Risk of ransomware encrypting critical business data and systems"
        else:
            title = self._GENERIC_VULNERABILITY_RISK_TITLE
            description = f"Risk of exploitation of {vuln.get('cve_id', 'an unpatched vulnerability')} or similar unpatched findings"

        import uuid
        from app.graph.connection import run_write
        from app.graph import queries
        run_write(queries.ENSURE_RISK_FOR_VULNERABILITY, {
            "id": str(uuid.uuid4()),
            "asset_id": asset_id,
            "tenant_id": tenant_id,
            "title": title,
            "description": description,
            "likelihood": profile["likelihood"],
            "impact": profile["impact"],
            "owner": "Security Team",
            # Root cause: recorded on the Risk-[:IMPACTS]->Asset link itself,
            # so Blast Radius can answer "which CVE put this asset under
            # this risk?" instead of only "this asset is under this risk".
            "cve_id": vuln.get("cve_id"),
            "source": vuln.get("source", "connector"),
        })

    @property
    def profile_capabilities(self) -> dict[str, dict]:
        """connector_id -> {"name", "sections"} for every connector that can
        fill in any part of the device profile."""
        return {
            cid: {"name": cls.CONNECTOR_NAME, "sections": list(cls.PROFILE_SECTIONS)}
            for cid, cls in self._adapters.items()
            if getattr(cls, "PROFILE_SECTIONS", ())
        }

    @property
    def registered_connectors(self) -> list[str]:
        return list(self._adapters.keys())

    @property
    def all_checks(self) -> dict[str, str]:
        """Map of check_id -> connector_id for every registered check."""
        return dict(self._check_map)


class _DeviceMatcher:
    """
    Ties one physical/virtual device reported by several connectors to a
    single asset (step 3 of the universal device profile).

    Merges automatically only on a *strong* identifier -- serial number,
    MAC address (virtual/VPN/randomised MACs excluded) or cloud instance
    id -- because wrongly combining two different machines is worse than
    showing one machine twice. A hostname-only match ("SIMO" vs
    "simo.corp.local") is recorded as POSSIBLY_SAME_AS for a person to
    judge on the asset page, never merged.

    Lazy: the tenant's identifiers are only read the first time a
    discovered asset actually carries one, so connectors that report no
    device profile cost no extra query.
    """

    def __init__(self, tenant_id: str, result: CheckResult):
        self.tenant_id = tenant_id
        self.result = result
        self._loaded = False
        self._strong: dict[tuple, str] = {}       # (kind, value) -> asset id
        self._hosts: dict[str, set] = {}          # hostname key -> asset ids
        self._names: dict[str, str] = {}          # asset id -> name

    def _load(self):
        if self._loaded:
            return
        self._loaded = True
        from app.graph.connection import run_query
        from app.graph import queries
        from .profile import STRONG_KEYS, hostname_key
        for row in run_query(queries.GET_ASSET_IDENTIFIERS, {"tenant_id": self.tenant_id}) or []:
            aid = row.get("id")
            if not aid:
                continue
            self._names[aid] = row.get("name")
            for kind in STRONG_KEYS:
                for v in row.get(kind) or []:
                    self._strong.setdefault((kind, v), aid)
            for h in (row.get("hostname") or []) + [hostname_key(row.get("name"))]:
                if h:
                    self._hosts.setdefault(h, set()).add(aid)

    def find(self, raw_profile) -> Optional[str]:
        from .profile import STRONG_KEYS, device_keys
        keys = device_keys(raw_profile)
        if not any(k in keys for k in STRONG_KEYS):
            return None
        self._load()
        for kind in STRONG_KEYS:
            for v in keys.get(kind, []):
                if (kind, v) in self._strong:
                    return self._strong[(kind, v)]
        return None

    _REASONS = {"serial": "same serial number", "mac": "same MAC address", "instance": "same cloud instance id"}

    def record(self, asset_id: str, name: str, raw_profile) -> None:
        """Remember this asset's identifiers (in the graph and for the rest
        of this run), note an alias if it was merged in under another name,
        and flag hostname-only lookalikes."""
        if not raw_profile:
            # Only connectors that report a device profile take part in
            # matching; a bare name-only asset behaves exactly as before.
            return
        from .profile import STRONG_KEYS, device_keys, hostname_key
        keys = device_keys(raw_profile)
        host_keys = set(keys.get("hostname", [])) | ({hostname_key(name)} - {None})
        if not keys and not host_keys:
            return
        self._load()
        from datetime import datetime, timezone
        from app.graph.connection import run_write
        from app.graph import queries

        aliases = []
        known_name = self._names.get(asset_id)
        if known_name and known_name != name:
            # Merged in from a record with a different name.
            shared = next((k for k in STRONG_KEYS
                           if any(self._strong.get((k, v)) == asset_id for v in keys.get(k, []))), None)
            reason = self._REASONS.get(shared, "matched device")
            aliases.append(f"{name} ({self.result.source}, {reason})")
        run_write(queries.MERGE_ASSET_IDENTIFIERS, {
            "asset_id": asset_id, "tenant_id": self.tenant_id,
            "serial": keys.get("serial", []), "mac": keys.get("mac", []),
            "instance": keys.get("instance", []), "hostname": sorted(host_keys),
            "aliases": aliases,
        })

        # Hostname-only lookalikes: same short hostname, different asset,
        # and no strong identifier in common -- flag, don't merge.
        lookalikes = set()
        for h in host_keys:
            lookalikes |= self._hosts.get(h, set())
        lookalikes.discard(asset_id)
        for other in sorted(lookalikes):
            run_write(queries.LINK_POSSIBLE_DUPLICATE, {
                "asset_id": asset_id, "other_id": other, "tenant_id": self.tenant_id,
                "reason": "same hostname, no shared serial/MAC/instance id",
                "detected_at": datetime.now(timezone.utc).isoformat(),
            })

        # This run's later assets can match against this one too.
        self._names.setdefault(asset_id, name)
        for kind in STRONG_KEYS:
            for v in keys.get(kind, []):
                self._strong.setdefault((kind, v), asset_id)
        for h in host_keys:
            self._hosts.setdefault(h, set()).add(asset_id)


# ── Singleton registry — import `registry` from this module everywhere ────────
registry = CheckRegistry()
