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
