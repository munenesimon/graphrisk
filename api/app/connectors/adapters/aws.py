"""
Layer 2: AWS Security Posture adapter.

Demonstrates the universal connector pattern generalizes beyond OAuth 2.0 --
AWS uses IAM access keys via boto3, a completely different auth mechanism
from Entra ID\'s OAuth client credentials flow. BaseConnector\'s HTTP/retry/
pagination helpers are not used here since boto3 handles that internally;
only the token-cache convention (_set_token) is reused to satisfy the
BaseConnector contract.
"""
import boto3
from datetime import datetime, timezone, timedelta

from ..base import BaseConnector
from ..models import CheckResult, CheckStatus, CheckCategory

SUPPORTED_CHECKS = [
    "aws_root_mfa",
    "aws_public_buckets",
    "aws_unused_keys",
    "aws_cloudtrail",
]


class AWSAdapter(BaseConnector):
    CONNECTOR_ID   = "aws"
    CONNECTOR_NAME = "AWS Security Posture"

    def authenticate(self) -> None:
        """
        AWS uses boto3 with an access key + secret -- no OAuth token flow.
        A boto3.Session is created and cached; _set_token satisfies
        BaseConnector\'s token-freshness contract with a long-lived dummy value
        since boto3 manages its own credential refresh internally.
        """
        self._boto_session = boto3.Session(
            aws_access_key_id=self.config["aws_access_key_id"],
            aws_secret_access_key=self.config["aws_secret_access_key"],
            region_name=self.config.get("region", "us-east-1"),
        )
        self._set_token("boto3-session", expires_in=86400)

    def supported_checks(self) -> list[str]:
        return SUPPORTED_CHECKS

    def run_check(self, check_id: str) -> CheckResult:
        self._ensure_token()  # Ensures self._boto_session exists
        dispatch = {
            "aws_root_mfa":       self._check_root_mfa,
            "aws_public_buckets": self._check_public_buckets,
            "aws_unused_keys":    self._check_unused_keys,
            "aws_cloudtrail":     self._check_cloudtrail,
        }
        if check_id not in dispatch:
            raise ValueError(f"Unknown check for AWSAdapter: {check_id}")
        return dispatch[check_id]()

    # ── Individual checks ────────────────────────────────────────────────────
    def _check_root_mfa(self) -> CheckResult:
        iam = self._boto_session.client("iam")
        summary = iam.get_account_summary()["SummaryMap"]
        mfa_enabled = summary.get("AccountMFAEnabled", 0) == 1

        return CheckResult(
            check_id="aws_root_mfa",
            check_name="AWS Root Account MFA",
            category=CheckCategory.PRIVILEGED_ACCESS,
            source=self.CONNECTOR_ID,
            tenant_id=self.tenant_id,
            status=CheckStatus.PASS if mfa_enabled else CheckStatus.FAIL,
            score=1.0 if mfa_enabled else 0.0,
            detail=(
                "Root account MFA enabled" if mfa_enabled
                else "CRITICAL: Root account MFA is disabled"
            ),
            control_title="Multi-Factor Authentication",
        )

    def _check_public_buckets(self) -> CheckResult:
        s3 = self._boto_session.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
        public = []

        for b in buckets:
            try:
                acl = s3.get_bucket_acl(Bucket=b["Name"])
                for grant in acl.get("Grants", []):
                    grantee = grant.get("Grantee", {})
                    uri = grantee.get("URI", "")
                    if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                        public.append(b["Name"])
                        break
            except Exception:
                continue  # Skip buckets we lack permission to inspect

        count = len(public)
        total = len(buckets)
        return CheckResult(
            check_id="aws_public_buckets",
            check_name="Public S3 Bucket Check",
            category=CheckCategory.CLOUD_POSTURE,
            source=self.CONNECTOR_ID,
            tenant_id=self.tenant_id,
            status=CheckStatus.PASS if count == 0 else CheckStatus.FAIL,
            score=0.0 if count > 0 else 1.0,
            affected_count=count,
            total_count=total,
            detail=f"{count} of {total} S3 buckets are publicly accessible",
            raw_data={"public_buckets": public},
            control_title="Cloud Storage Security",
        )

    def _check_unused_keys(self, threshold_days: int = 90) -> CheckResult:
        iam    = self._boto_session.client("iam")
        cutoff = datetime.now(timezone.utc) - timedelta(days=threshold_days)
        users  = iam.list_users()["Users"]
        stale  = []

        for u in users:
            keys = iam.list_access_keys(UserName=u["UserName"])["AccessKeyMetadata"]
            for k in keys:
                if k["Status"] != "Active":
                    continue
                last = iam.get_access_key_last_used(AccessKeyId=k["AccessKeyId"])
                last_used = last.get("AccessKeyLastUsed", {}).get("LastUsedDate")
                if not last_used or last_used < cutoff:
                    stale.append(u["UserName"])
                    break

        count = len(stale)
        total = len(users)
        score = round(1.0 - (count / total), 4) if total > 0 else 1.0

        return CheckResult(
            check_id="aws_unused_keys",
            check_name="Unused IAM Access Keys",
            category=CheckCategory.IAM,
            source=self.CONNECTOR_ID,
            tenant_id=self.tenant_id,
            status=CheckStatus.PASS if count == 0 else CheckStatus.FAIL,
            score=score,
            affected_count=count,
            total_count=total,
            detail=f"{count} of {total} users have access keys unused for more than {threshold_days} days",
            raw_data={"stale_users": stale},
            control_title="Access Key Management",
        )

    def _check_cloudtrail(self) -> CheckResult:
        ct = self._boto_session.client("cloudtrail")
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        active = [
            t for t in trails
            if t.get("IsMultiRegionTrail") and t.get("HasCustomEventSelectors") is not None
        ]

        return CheckResult(
            check_id="aws_cloudtrail",
            check_name="CloudTrail Logging Check",
            category=CheckCategory.CLOUD_POSTURE,
            source=self.CONNECTOR_ID,
            tenant_id=self.tenant_id,
            status=CheckStatus.PASS if active else CheckStatus.FAIL,
            score=1.0 if active else 0.0,
            total_count=len(trails),
            detail=f"{len(active)} of {len(trails)} multi-region CloudTrail trails are active",
            control_title="Security Logging and Monitoring",
        )
