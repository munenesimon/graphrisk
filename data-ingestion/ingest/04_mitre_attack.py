import requests, tempfile, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from neo4j_utils import Neo4jClient
from config import MITRE_ATTACK_URL, ATTACK_VERSION
from tqdm import tqdm
from mitreattack.stix20 import MitreAttackData

MERGE_TACTIC = """
    UNWIND $batch AS row
    MERGE (t:Tactic {id: row.id})
    SET t.name=row.name, t.short_name=row.short_name, t.description=row.description
"""

MERGE_TECHNIQUE = """
    UNWIND $batch AS row
    MERGE (tech:Technique {id: row.id})
    SET tech.name=row.name, tech.technique_id=row.technique_id,
        tech.description=row.description, tech.is_subtechnique=row.is_sub
    WITH tech, row
    MATCH (t:Tactic {short_name: row.tactic})
    MERGE (tech)-[:BELONGS_TO]->(t)
"""

def ingest():
    print("=" * 55)
    print("  DS-04: MITRE ATT&CK Ingestion")
    print("=" * 55)
    print(f"\n[1/4] Downloading ATT&CK bundle (~50MB)...")
    r = requests.get(MITRE_ATTACK_URL, stream=True, timeout=180)
    r.raise_for_status()
    total = int(r.headers.get("content-length", 0))
    tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="wb")
    with tqdm(total=total, unit="B", unit_scale=True) as pbar:
        for chunk in r.iter_content(chunk_size=8192):
            tmp.write(chunk); pbar.update(len(chunk))
    tmp.close()

    print("\n[2/4] Parsing STIX bundle...")
    attack = MitreAttackData(tmp.name)
    db = Neo4jClient()

    print("\n[3/4] Loading Tactics...")
    tactics = attack.get_tactics(remove_revoked_deprecated=True)
    tactic_batch = [{
        "id":         str(t["id"]),
        "name":       t.get("name", ""),
        "short_name": t.get("x_mitre_shortname", ""),
        "description":t.get("description", "")[:400]
    } for t in tactics]
    db.run_batch(MERGE_TACTIC, tactic_batch)
    print(f"  {len(tactic_batch)} tactics loaded")

    print("\n[4/4] Loading Techniques...")
    techniques = attack.get_techniques(remove_revoked_deprecated=True)
    tech_batch, seen = [], set()
    for t in techniques:
        refs   = t.get("external_references", [])
        ext_id = next((r.get("external_id","") for r in refs if r.get("source_name")=="mitre-attack"), "")
        for phase in t.get("kill_chain_phases", [{"phase_name":"unknown"}]):
            key = f"{t['id']}_{phase['phase_name']}"
            if key in seen: continue
            seen.add(key)
            tech_batch.append({
                "id":           str(t["id"]),
                "name":         t.get("name",""),
                "technique_id": ext_id,
                "description":  t.get("description","")[:400],
                "is_sub":       t.get("x_mitre_is_subtechnique", False),
                "tactic":       phase["phase_name"]
            })
    db.run_batch(MERGE_TECHNIQUE, tech_batch)
    unique = len(set(t["id"] for t in tech_batch))
    print(f"  {unique} techniques loaded")
    db.close()
    os.unlink(tmp.name)

    print("\n" + "=" * 55)
    print(f"  Done. {len(tactic_batch)} tactics, {unique} techniques.")
    print("  MATCH (t:Tactic) RETURN t.name ORDER BY t.name")
    print("=" * 55)

if __name__ == "__main__": ingest()
