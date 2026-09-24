"""
GraphRisk — Clear Tenant Data
One-off cleanup: deletes a tenant's Asset/Risk/Control nodes and its
Organisation (regulatory profile) node, with their relationships, so
seed_demo.py can be re-run against that tenant without duplicating
everything it already created.

Talks to Neo4j directly via the API's own connection module (not through
the REST API) since there's no bulk-delete endpoint, and adding one just
for this one-off refresh isn't worth the extra permanent API surface.

Run from the graphrisk-api folder with venv active, against whichever
Neo4j your .env in that folder points at:
    python clear_demo_tenant.py [tenant_id]
Defaults to tenant_id "demo" if none is given.

Only deletes tenant-scoped nodes (Asset/Risk/Control/Organisation) -- never touches
Vulnerability, Framework, FrameworkControl or Technique nodes, which are
shared/global data, not per-tenant.

DESTRUCTIVE AND IRREVERSIBLE. Requires typing the tenant id back to
confirm. Double-check your .env points at the graph you actually mean to
clear (local dev vs. the live Google Cloud instance) before confirming.
"""
import sys
from app.graph.connection import run_write, get_graph_client, close_graph_client

TENANT_ID = sys.argv[1] if len(sys.argv) > 1 else "demo"

CLEAR_TENANT_DATA = """
    MATCH (n) WHERE (n:Asset OR n:Risk OR n:Control OR n:Organisation) AND n.tenant_id = $tenant_id
    DETACH DELETE n
    RETURN count(n) AS deleted
"""


def main():
    print("=" * 55)
    print(f"  Clear tenant data: '{TENANT_ID}'")
    print("=" * 55)
    print("  This permanently deletes every Asset/Risk/Control node and the")
    print("  regulatory profile for this tenant, and every relationship attached")
    print("  to them. Vulnerability,")
    print("  Framework and Technique nodes are shared data and are NOT touched.")
    print()
    confirm = input(f"  Type the tenant id ('{TENANT_ID}') to confirm, anything else to abort: ")
    if confirm != TENANT_ID:
        print("  Aborted -- input didn't match. Nothing was deleted.")
        return

    get_graph_client()
    result = run_write(CLEAR_TENANT_DATA, {"tenant_id": TENANT_ID})
    deleted = result[0]["deleted"] if result else 0
    close_graph_client()

    print(f"\n  Deleted {deleted} node(s) for tenant '{TENANT_ID}'.")
    print("  Run seed_demo.py again to repopulate it fresh.")
    print("=" * 55)


if __name__ == "__main__":
    main()
