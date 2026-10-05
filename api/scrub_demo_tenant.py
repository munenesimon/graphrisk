"""
GraphRisk -- remove connector data from the shared demo tenant.

Before the demo became read-only (and before real connectors got their own
tenant), connectors were run against "demo", so real devices discovered by
a connector -- with their real vulnerabilities -- and saved connector
credentials can still be sitting in the public demo. This removes exactly
that, and nothing the demo seed created:

  - assets a connector created (owner "<connector> connector"), with every
    relationship attached to them and their device-profile snapshots
  - a connector-created "Unpatched Vulnerability Risk" left with no assets
  - saved connector credentials for the tenant (ConnectorConfig nodes)

Shared data (Vulnerability, Framework, Technique nodes) is never touched,
and nor are the seeded assets, risks and controls.

Run from the api folder with the venv active, against whichever Neo4j your
.env points at (for the live demo: the Google Cloud instance):
    python scrub_demo_tenant.py [tenant_id]        # defaults to "demo"
It lists what it found first, and deletes only after you type the tenant id
back. DESTRUCTIVE AND IRREVERSIBLE for what it deletes.
"""
import sys
from app.graph.connection import run_query, run_write, get_graph_client, close_graph_client

TENANT_ID = sys.argv[1] if len(sys.argv) > 1 else "demo"

FIND_CONNECTOR_ASSETS = """
    MATCH (a:Asset {tenant_id: $tenant_id})
    WHERE a.owner ENDS WITH ' connector'
    OPTIONAL MATCH (v:Vulnerability)-[:EXPOSES]->(a)
    OPTIONAL MATCH (r:Risk)-[:IMPACTS]->(a)
    RETURN a.id AS id, a.name AS name, a.owner AS owner,
           count(DISTINCT v) AS vulnerabilities, collect(DISTINCT r.title) AS risks
"""
FIND_CONFIGS = """
    MATCH (cc:ConnectorConfig {tenant_id: $tenant_id})
    RETURN cc.connector_id AS connector_id
"""
DELETE_ASSETS = """
    MATCH (a:Asset {tenant_id: $tenant_id}) WHERE a.id IN $ids
    OPTIONAL MATCH (a)-[:HAS_PROFILE]->(p:AssetProfileSection)
    DETACH DELETE p, a
    RETURN count(DISTINCT a) AS deleted
"""
DELETE_ORPHAN_UNPATCHED_RISK = """
    MATCH (r:Risk {tenant_id: $tenant_id, title: 'Unpatched Vulnerability Risk'})
    WHERE NOT (r)-[:IMPACTS]->(:Asset)
    DETACH DELETE r
    RETURN count(r) AS deleted
"""
DELETE_CONFIGS = """
    MATCH (cc:ConnectorConfig {tenant_id: $tenant_id})
    DETACH DELETE cc
    RETURN count(cc) AS deleted
"""


def main():
    print("=" * 60)
    print(f"  Remove connector data from tenant '{TENANT_ID}'")
    print("=" * 60)
    get_graph_client()
    try:
        assets = run_query(FIND_CONNECTOR_ASSETS, {"tenant_id": TENANT_ID})
        configs = run_query(FIND_CONFIGS, {"tenant_id": TENANT_ID})

        if not assets and not configs:
            print("  Nothing to remove -- no connector-created assets or saved credentials.")
            return
        print("  Connector-created assets (deleted with their links and profiles):")
        for a in assets:
            risks = ", ".join(r for r in a["risks"] if r) or "none"
            print(f"    - {a['name']}  [{a['owner']}]  {a['vulnerabilities']} CVEs, risks: {risks}")
        if not assets:
            print("    (none)")
        print("  Saved connector credentials (deleted):")
        for c in configs:
            print(f"    - {c['connector_id']}")
        if not configs:
            print("    (none)")
        print("  Plus a connector-created 'Unpatched Vulnerability Risk' if no asset is left on it.")
        print()

        confirm = input(f"  Type the tenant id ('{TENANT_ID}') to delete the above, anything else to abort: ")
        if confirm != TENANT_ID:
            print("  Aborted -- nothing was deleted.")
            return

        deleted_assets = run_write(DELETE_ASSETS, {"tenant_id": TENANT_ID, "ids": [a["id"] for a in assets]})
        deleted_risk = run_write(DELETE_ORPHAN_UNPATCHED_RISK, {"tenant_id": TENANT_ID})
        deleted_cfg = run_write(DELETE_CONFIGS, {"tenant_id": TENANT_ID})
        print()
        print(f"  Deleted {deleted_assets[0]['deleted'] if deleted_assets else 0} asset(s), "
              f"{deleted_risk[0]['deleted'] if deleted_risk else 0} orphaned risk(s), "
              f"{deleted_cfg[0]['deleted'] if deleted_cfg else 0} saved credential set(s).")
    finally:
        close_graph_client()
    print("=" * 60)


if __name__ == "__main__":
    main()
