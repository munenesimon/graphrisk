"""
One-off live verification of WazuhAdapter against a real Wazuh manager.

Run this from the api/ directory of your GraphRisk checkout, with the repo's
Python dependencies installed (whatever your local venv/dev setup already
uses to run the API). It does NOT need Postgres, Neo4j, or the FastAPI app
running -- it talks to the adapter class directly.

Credentials are read from environment variables so they never have to be
pasted into chat or committed anywhere. Set them in your own terminal
first:

    PowerShell:
        $env:WAZUH_API_URL = "https://<your-vm-ip-or-hostname>:55000"
        $env:WAZUH_USERNAME = "<your wazuh api username>"
        $env:WAZUH_PASSWORD = "<your wazuh api password>"
        $env:WAZUH_VERIFY_SSL = "false"   # set to "true" if you have a real cert

    (bash/zsh equivalent: export WAZUH_API_URL=... etc.)

Then:
    python verify_wazuh_live.py

Note: WAZUH_VERIFY_SSL defaults to false here because most self-hosted
Wazuh installs run the default self-signed certificate. Set it to "true"
only if you've replaced that with a real trusted cert.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.connectors.adapters.wazuh import WazuhAdapter  # noqa: E402


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        print(f"Missing required environment variable: {name}")
        print("See the top of this script for how to set it.")
        sys.exit(1)
    return value


def main() -> None:
    config = {
        "api_url": _require_env("WAZUH_API_URL"),
        "username": _require_env("WAZUH_USERNAME"),
        "password": _require_env("WAZUH_PASSWORD"),
        "verify_ssl": os.environ.get("WAZUH_VERIFY_SSL", "false").strip().lower() == "true",
    }

    print("=" * 60)
    print("  WazuhAdapter live verification")
    print("=" * 60)
    print(f"  Target:     {config['api_url']}")
    print(f"  verify_ssl: {config['verify_ssl']}")
    print()

    adapter = WazuhAdapter(tenant_id="live-verification", config=config)

    print("[1/2] Authenticating...")
    try:
        adapter.authenticate()
        print("      OK -- got a session token from the manager.")
    except Exception as e:
        print(f"      FAILED: {type(e).__name__}: {e}")
        print()
        print("Common causes: wrong api_url/port, wrong username/password,")
        print("self-signed cert with WAZUH_VERIFY_SSL not set to false, or")
        print("the manager isn't reachable from this machine's network.")
        sys.exit(1)

    print()
    print("[2/2] Running all supported checks...")
    results, errors = adapter.run_all_checks()

    for r in results:
        print(f"\n  {r.check_id}")
        print(f"    status: {r.status.value}")
        print(f"    score:  {r.score}")
        print(f"    detail: {r.detail}")

    for e in errors:
        print(f"\n  [ERROR] {e.check_id}: {e.error_type} - {e.message}")

    print()
    print("=" * 60)
    if errors:
        print(f"  Done with {len(errors)} error(s) -- see above.")
    else:
        print(f"  Done. {len(results)} check(s) ran successfully against your live manager.")
    print("=" * 60)


if __name__ == "__main__":
    main()
