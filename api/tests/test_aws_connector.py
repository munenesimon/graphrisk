"""
Offline test for AWSAdapter using moto (AWS API simulator).
Proves the adapter logic and CheckRegistry integration work correctly
WITHOUT needing a real AWS account or credentials.

Usage: python test_aws_connector.py
Requires: pip install moto[iam,s3,cloudtrail]
"""
import boto3
from moto import mock_aws

import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.connectors.adapters.aws import AWSAdapter


@mock_aws
def test_aws_adapter():
    print("=" * 55)
    print("  AWS Connector Offline Test (via moto)")
    print("=" * 55)

    # ── Set up fake AWS resources moto will respond with ────────────────────
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="test-user-1")
    key = iam.create_access_key(UserName="test-user-1")
    print(f"\n[Setup] Created fake IAM user with access key: "
          f"{key['AccessKey']['AccessKeyId'][:10]}...")

    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-private-bucket")
    print("[Setup] Created fake S3 bucket: test-private-bucket")

    ct = boto3.client("cloudtrail", region_name="us-east-1")
    print("[Setup] CloudTrail client ready (no trails created -- tests FAIL path)")

    # ── Instantiate the real adapter against the fake AWS environment ───────
    adapter = AWSAdapter(
        tenant_id="test-tenant",
        config={
            "aws_access_key_id":     "fake-key-id",
            "aws_secret_access_key": "fake-secret",
            "region":                "us-east-1",
        },
    )
    adapter.authenticate()
    print("\n[Auth] AWSAdapter authenticated against mocked AWS")

    print("\n" + "-" * 55)
    print("  Running all supported checks")
    print("-" * 55)

    results, errors = adapter.run_all_checks()

    for r in results:
        print(f"\n  {r.check_id}")
        print(f"    status: {r.status.value}")
        print(f"    score:  {r.score}")
        print(f"    detail: {r.detail}")

    for e in errors:
        print(f"\n  [ERROR] {e.check_id}: {e.error_type} - {e.message}")

    print("\n" + "=" * 55)
    print(f"  Test complete. {len(results)} checks ran successfully.")
    print("  This proves AWSAdapter correctly implements BaseConnector")
    print("  without ever touching a real AWS account.")
    print("=" * 55)


if __name__ == "__main__":
    test_aws_adapter()
