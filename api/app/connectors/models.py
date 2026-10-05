"""
Canonical data models for the universal connector framework.
Every adapter, regardless of vendor, produces CheckResult objects in this shape.
This is what makes the graph writer, blast radius engine, and UI vendor-agnostic.
"""
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timezone
from typing import Any


class CheckStatus(Enum):
    PASS    = "PASS"
    FAIL    = "FAIL"
    WARNING = "WARNING"
    ERROR   = "ERROR"
    SKIPPED = "SKIPPED"


class CheckCategory(Enum):
    IAM               = "iam"
    PRIVILEGED_ACCESS = "privileged_access"
    ENDPOINT          = "endpoint"
    PATCH_MGMT        = "patch_management"
    CLOUD_POSTURE     = "cloud_posture"
    BACKUP_RECOVERY   = "backup_recovery"
    VENDOR_RISK       = "vendor_risk"


@dataclass
class CheckResult:
    """
    Universal shape for a single control check result.
    Every connector adapter must produce this exact shape regardless of vendor,
    so downstream code (graph writer, blast radius, UI) never needs vendor logic.
    """
    # Identity
    check_id:   str              # e.g. "mfa_enabled"
    check_name: str              # e.g. "MFA Enabled Check"
    category:   CheckCategory
    source:     str              # e.g. "entra_id", "crowdstrike", "aws"
    tenant_id:  str

    # Result
    status:         CheckStatus
    score:          float        # 0.0 (complete fail) to 1.0 (full pass)
    detail:         str          # Human-readable result summary
    affected_count: int = 0      # e.g. 14 users without MFA
    total_count:    int = 0      # e.g. 87 total users checked

    # Metadata
    executed_at:   datetime      = field(default_factory=lambda: datetime.now(timezone.utc))
    raw_data:      dict[str, Any] = field(default_factory=dict)
    error_message: str           = ""

    # Neo4j control mapping — links this result to a Control node by title
    control_title: str           = ""

    # Assets this check's raw data reveals (e.g. one per Wazuh agent, one
    # per scanned host) -- optional, empty for connectors that don't map
    # cleanly onto individual devices/systems (Entra ID, Okta, AWS...).
    # CheckRegistry upserts these into the graph the same way it writes
    # the check result itself, keyed on (tenant_id, name) so re-running a
    # connector doesn't create duplicates. Each dict may contain: name
    # (required), asset_type, criticality, environment, vendor, product,
    # holds_personal_data -- same shape as AssetCreate in api/v1/assets.py --
    # plus an optional "vulnerabilities" list of CVE ids the adapter has
    # *actually observed* on that specific device (as opposed to the
    # generic vendor/product correlation CORRELATE_NEW_ASSET_AGAINST_ALL_
    # VULNERABILITIES already runs once for every new asset). Each entry is
    # either:
    #   - a plain string CVE id ("CVE-2024-1234") -- linked only if that CVE
    #     is already in our ingested NVD/CISA KEV catalog; a no-op otherwise,
    #     same as the manual "link vulnerability" UI action.
    #   - a dict with real finding detail: {"cve_id": ..., "description":
    #     ..., "cvss_score": ..., "severity": ..., "published_at": ...,
    #     "source": ...} (only "cve_id" required) -- CheckRegistry creates a
    #     real Vulnerability node from this when one doesn't already exist,
    #     then links it. This is the shape to use for a scanner reporting
    #     findings NVD/CISA KEV likely never covers, e.g. Wazuh's
    #     indexer-backed vulnerability detection drawing on OSV/GitHub
    #     Security Advisories for OS-package and npm/pip-style CVEs.
    # Adapter-agnostic either way -- Qualys or CrowdStrike Spotlight could
    # report through the exact same field with no registry changes needed.
    #
    # Two more optional keys per entry:
    #   - "profile": {section: {field: value}} -- device detail in the
    #     universal profile shape (see connectors/profile.py), limited to
    #     the sections the adapter declares in PROFILE_SECTIONS. Stored per
    #     (asset, connector, section), merged across connectors on read.
    #   - "profile_only": True -- only update the profile of an asset that
    #     already exists (matched by name); never create one. For a check
    #     that adds detail (e.g. configuration results) about devices
    #     another check is responsible for discovering.
    discovered_assets: list[dict] = field(default_factory=list)

    @property
    def pass_rate(self) -> float:
        if self.total_count == 0:
            return self.score
        return round((self.total_count - self.affected_count) / self.total_count, 4)

    def to_neo4j_params(self) -> dict:
        return {
            "check_id":       self.check_id,
            "check_name":     self.check_name,
            "category":       self.category.value,
            "source":         self.source,
            "status":         self.status.value,
            "score":          self.score,
            "detail":         self.detail,
            "affected_count": self.affected_count,
            "total_count":    self.total_count,
            "executed_at":    self.executed_at.isoformat(),
            "tenant_id":      self.tenant_id,
        }

    def __repr__(self) -> str:
        return (f"CheckResult({self.source}/{self.check_id}: "
                f"{self.status.value}, score={self.score})")
