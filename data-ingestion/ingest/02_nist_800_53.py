import requests, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from neo4j_utils import Neo4jClient

OSCAL_URL = "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"

MERGE_FRAMEWORK = """
    MERGE (f:Framework {id: "NIST_800_53_R5"})
    SET f.name="NIST_800_53", f.version="Rev5", f.owner="NIST",
        f.url="https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"
    RETURN f.id AS id
"""

MERGE_CONTROLS = """
    UNWIND $batch AS row
    MERGE (fc:FrameworkControl {id: row.id})
    SET fc.control_reference = row.ref,
        fc.title             = row.title,
        fc.domain            = row.family,
        fc.family            = row.family,
        fc.official_url      = row.url
    WITH fc
    MATCH (f:Framework {id: "NIST_800_53_R5"})
    MERGE (fc)-[:PART_OF]->(f)
"""

def ingest():
    print("=" * 55)
    print("  DS-02: NIST SP 800-53 Rev5 Ingestion")
    print("=" * 55)
    print("\n[1/4] Fetching from NIST OSCAL GitHub...")
    try:
        r = requests.get(OSCAL_URL, timeout=60)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        print(f"  ERROR: {e}"); return
    catalog = data.get("catalog", data)
    groups  = catalog.get("groups", [])
    print(f"  Fetched {len(groups)} control families")
    print("\n[2/4] Creating Framework node...")
    db = Neo4jClient()
    db.run(MERGE_FRAMEWORK)
    print("\n[3/4] Parsing controls and enhancements...")
    batch = []
    for group in groups:
        family = group.get("title", group.get("id", ""))
        for ctrl in group.get("controls", []):
            ref   = ctrl.get("id","").upper()
            batch.append({"id": f"NIST_800_53_R5_{ref}", "ref": ref,
                          "title": ctrl.get("title", ref), "family": family,
                          "url": f"https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_0/home?element={ref}"})
            for enh in ctrl.get("controls", []):
                eref = enh.get("id","").upper()
                batch.append({"id": f"NIST_800_53_R5_{eref}", "ref": eref,
                              "title": enh.get("title", eref), "family": family,
                              "url": f"https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_0/home?element={eref}"})
    print(f"  Parsed {len(batch)} controls and enhancements")
    print("\n[4/4] Loading into Neo4j...")
    db.run_batch(MERGE_CONTROLS, batch)
    db.close()
    print("\n" + "=" * 55)
    print("  NIST SP 800-53 Rev5 Ingestion Complete")
    print("=" * 55)
    print(f"  Controls loaded : {len(batch)}")
    print("\n  Verify in Neo4j Browser:")
    print("  MATCH (fc:FrameworkControl)-[:PART_OF]->(f:Framework {id:'NIST_800_53_R5'})")
    print("  RETURN count(fc) AS total")
    print("=" * 55)

if __name__ == "__main__": ingest()
