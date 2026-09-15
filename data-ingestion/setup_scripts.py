"""
GraphRisk — Script Setup
Run this once to create all ingestion scripts with correct encoding.
Usage: python setup_scripts.py
"""
import os

BASE = os.path.dirname(os.path.abspath(__file__))
INGEST = os.path.join(BASE, "ingest")
os.makedirs(INGEST, exist_ok=True)


def write(path, content):
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"  Written: {os.path.relpath(path, BASE)}")


# ── 01_nist_csf.py ───────────────────────────────────────────────────────────
write(os.path.join(INGEST, "01_nist_csf.py"), '''import requests, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from neo4j_utils import Neo4jClient
from config import NIST_CSF_URL

MERGE_FRAMEWORK = """
    MERGE (f:Framework {id: "NIST_CSF_2"})
    SET f.name="NIST_CSF", f.version="2.0", f.owner="NIST",
        f.url="https://www.nist.gov/cyberframework"
    RETURN f.id AS id
"""

MERGE_CONTROLS = """
    UNWIND $batch AS row
    MERGE (fc:FrameworkControl {id: row.id})
    SET fc.control_reference=row.ref, fc.title=row.title,
        fc.description=row.description, fc.domain=row.domain,
        fc.function=row.function
    WITH fc
    MATCH (f:Framework {id: "NIST_CSF_2"})
    MERGE (fc)-[:PART_OF]->(f)
"""

def ingest():
    print("=" * 55)
    print("  DS-01: NIST CSF 2.0 Ingestion")
    print("=" * 55)
    print("\\n[1/4] Fetching NIST CSF 2.0...")
    try:
        r = requests.get(NIST_CSF_URL, timeout=60)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        print(f"  ERROR: {e}"); return

    print("\\n[2/4] Creating Framework node...")
    db = Neo4jClient()
    db.run(MERGE_FRAMEWORK)

    print("\\n[3/4] Parsing controls...")
    batch = []
    items = data if isinstance(data, list) else data.get("response", {}).get("elements", [])
    for fn in items:
        fn_id   = fn.get("identifier", "")
        fn_name = fn.get("title", fn_id)
        for cat in fn.get("elements", []):
            cat_title = cat.get("title", "")
            for sub in cat.get("elements", []):
                ref = sub.get("identifier", "")
                if not ref: continue
                batch.append({
                    "id":          f"NIST_CSF_2_{ref}",
                    "ref":         ref,
                    "title":       sub.get("title", ref),
                    "description": sub.get("description", ""),
                    "domain":      cat_title,
                    "function":    fn_name,
                    "function_id": fn_id,
                })

    if not batch:
        print("  WARNING: No controls parsed — API format may have changed.")
        db.close(); return

    print(f"  Parsed {len(batch)} subcategories")
    print("\\n[4/4] Loading into Neo4j...")
    db.run_batch(MERGE_CONTROLS, batch)
    db.close()

    print("\\n" + "=" * 55)
    print(f"  Done. {len(batch)} controls loaded.")
    print("  MATCH (fc:FrameworkControl)-[:PART_OF]->(f:Framework {id:\\'NIST_CSF_2\\'})")
    print("  RETURN count(fc)")
    print("=" * 55)

if __name__ == "__main__": ingest()
''')


# ── 02_nist_800_53.py ────────────────────────────────────────────────────────
write(os.path.join(INGEST, "02_nist_800_53.py"), '''import requests, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from neo4j_utils import Neo4jClient
from config import NIST_80053_URL

MERGE_FRAMEWORK = """
    MERGE (f:Framework {id: "NIST_800_53_R5"})
    SET f.name="NIST_800_53", f.version="Rev5", f.owner="NIST"
    RETURN f.id AS id
"""

MERGE_CONTROLS = """
    UNWIND $batch AS row
    MERGE (fc:FrameworkControl {id: row.id})
    SET fc.control_reference=row.ref, fc.title=row.title,
        fc.description=row.description, fc.domain=row.family
    WITH fc
    MATCH (f:Framework {id: "NIST_800_53_R5"})
    MERGE (fc)-[:PART_OF]->(f)
"""

def ingest():
    print("=" * 55)
    print("  DS-02: NIST SP 800-53 Rev5 Ingestion")
    print("=" * 55)
    print("\\n[1/4] Fetching (may take 30-60s)...")
    try:
        r = requests.get(NIST_80053_URL, timeout=120)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        print(f"  ERROR: {e}"); return

    db = Neo4jClient()
    db.run(MERGE_FRAMEWORK)
    print("  Framework node created.")

    print("\\n[2/4] Parsing controls...")
    batch = []
    items = data if isinstance(data, list) else data.get("response", {}).get("elements", [])
    for family in items:
        family_name = family.get("title", family.get("identifier", ""))
        for ctrl in family.get("elements", []):
            ref = ctrl.get("identifier", "")
            if not ref: continue
            batch.append({
                "id":     f"NIST_800_53_R5_{ref}",
                "ref":    ref,
                "title":  ctrl.get("title", ref),
                "description": ctrl.get("text", ctrl.get("description", ""))[:800],
                "family": family_name,
            })
            for enh in ctrl.get("elements", []):
                eref = enh.get("identifier", "")
                if not eref: continue
                batch.append({
                    "id":     f"NIST_800_53_R5_{eref}",
                    "ref":    eref,
                    "title":  enh.get("title", eref),
                    "description": enh.get("text", enh.get("description", ""))[:800],
                    "family": family_name,
                })

    print(f"  Parsed {len(batch)} controls and enhancements")
    print("\\n[3/4] Loading into Neo4j...")
    db.run_batch(MERGE_CONTROLS, batch)
    db.close()

    print("\\n" + "=" * 55)
    print(f"  Done. {len(batch)} controls loaded.")
    print("  MATCH (fc:FrameworkControl)-[:PART_OF]->(f:Framework {id:\\'NIST_800_53_R5\\'})")
    print("  RETURN count(fc)")
    print("=" * 55)

if __name__ == "__main__": ingest()
''')


# ── 04_mitre_attack.py ───────────────────────────────────────────────────────
write(os.path.join(INGEST, "04_mitre_attack.py"), '''import requests, tempfile, os, sys
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
    print(f"\\n[1/4] Downloading ATT&CK bundle (~50MB)...")
    r = requests.get(MITRE_ATTACK_URL, stream=True, timeout=180)
    r.raise_for_status()
    total = int(r.headers.get("content-length", 0))
    tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="wb")
    with tqdm(total=total, unit="B", unit_scale=True) as pbar:
        for chunk in r.iter_content(chunk_size=8192):
            tmp.write(chunk); pbar.update(len(chunk))
    tmp.close()

    print("\\n[2/4] Parsing STIX bundle...")
    attack = MitreAttackData(tmp.name)
    db = Neo4jClient()

    print("\\n[3/4] Loading Tactics...")
    tactics = attack.get_tactics(remove_revoked_deprecated=True)
    tactic_batch = [{
        "id":         str(t["id"]),
        "name":       t.get("name", ""),
        "short_name": t.get("x_mitre_shortname", ""),
        "description":t.get("description", "")[:400]
    } for t in tactics]
    db.run_batch(MERGE_TACTIC, tactic_batch)
    print(f"  {len(tactic_batch)} tactics loaded")

    print("\\n[4/4] Loading Techniques...")
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

    print("\\n" + "=" * 55)
    print(f"  Done. {len(tactic_batch)} tactics, {unique} techniques.")
    print("  MATCH (t:Tactic) RETURN t.name ORDER BY t.name")
    print("=" * 55)

if __name__ == "__main__": ingest()
''')


# ── 07_nvd_cve.py ────────────────────────────────────────────────────────────
write(os.path.join(INGEST, "07_nvd_cve.py"), '''import requests, time, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from neo4j_utils import Neo4jClient
from config import NVD_CVE_URL, NVD_API_KEY
from datetime import datetime, timezone
from tqdm import tqdm

MERGE_VULN = """
    UNWIND $batch AS row
    MERGE (v:Vulnerability {id: row.cve_id})
    SET v.cve_id=row.cve_id, v.description=row.description,
        v.cvss_score=row.cvss_score, v.severity=row.severity,
        v.published_at=row.published_at, v.source="NVD",
        v.patch_available=false,
        v.last_synced_at=row.synced_at
"""

def fetch_page(start, severity="CRITICAL"):
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    params  = {"cvssV3Severity": severity, "resultsPerPage": 2000, "startIndex": start}
    r = requests.get(NVD_CVE_URL, headers=headers, params=params, timeout=60)
    r.raise_for_status()
    return r.json()

def parse_cve(item):
    cve  = item.get("cve", {})
    desc = next((d["value"] for d in cve.get("descriptions",[]) if d.get("lang")=="en"), "")[:600]
    cvss = 0.0
    for m in cve.get("metrics",{}).get("cvssMetricV31",[]):
        cvss = m.get("cvssData",{}).get("baseScore", 0.0); break
    return {"cve_id": cve.get("id",""), "description": desc, "cvss_score": cvss,
            "severity": "Critical", "published_at": cve.get("published",""),
            "synced_at": datetime.now(timezone.utc).isoformat()}

def ingest(max_results=10000):
    print("=" * 55)
    print("  DS-07: NVD CVE Ingestion (Critical only)")
    print("=" * 55)
    if not NVD_API_KEY:
        print("  TIP: No API key set — slower rate limit.")
        print("  Get a free key: nvd.nist.gov/developers/request-an-api-key")
    print("\\n[1/3] Fetching first page...")
    try:
        first = fetch_page(0)
    except Exception as e:
        print(f"  ERROR: {e}"); return
    total = min(first.get("totalResults", 0), max_results)
    print(f"  Total available: {first.get('totalResults',0):,}  Fetching: {total:,}")
    all_batch = [parse_cve(v) for v in first.get("vulnerabilities",[])]
    print("\\n[2/3] Fetching remaining pages...")
    start = 2000
    with tqdm(total=total, initial=len(all_batch)) as pbar:
        while start < total:
            time.sleep(1)
            try:
                page  = fetch_page(start)
                chunk = [parse_cve(v) for v in page.get("vulnerabilities",[])]
                all_batch.extend(chunk); pbar.update(len(chunk)); start += 2000
            except Exception as e:
                print(f"\\n  Retrying ({e})..."); time.sleep(5)
    print(f"\\n[3/3] Loading {len(all_batch):,} CVEs into Neo4j...")
    db = Neo4jClient()
    db.run_batch(MERGE_VULN, all_batch)
    db.close()
    print("\\n" + "=" * 55)
    print(f"  Done. {len(all_batch):,} Critical CVEs loaded.")
    print("  MATCH (v:Vulnerability {source:\\'NVD\\'}) RETURN count(v)")
    print("=" * 55)

if __name__ == "__main__": ingest()
''')


# ── 09_daily_sync.py ─────────────────────────────────────────────────────────
write(os.path.join(INGEST, "09_daily_sync.py"), '''import requests, time, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from neo4j_utils import Neo4jClient
from config import CISA_KEV_URL, NVD_CVE_URL, NVD_API_KEY
from datetime import datetime, timedelta, timezone

MERGE_VULN = """
    UNWIND $batch AS row
    MERGE (v:Vulnerability {id: row.cve_id})
    SET v.cve_id=row.cve_id, v.title=row.title, v.description=row.description,
        v.vendor=row.vendor, v.product=row.product, v.cvss_score=row.cvss_score,
        v.severity=row.severity, v.ransomware_use=row.ransomware,
        v.patch_available=row.patch_available, v.source=row.source,
        v.last_synced_at=row.synced_at
"""

def sync_cisa_kev(db):
    print("  [KEV] Full sync...")
    data      = requests.get(CISA_KEV_URL, timeout=30).json()
    synced_at = datetime.now(timezone.utc).isoformat()
    batch = [{"cve_id": v.get("cveID",""), "title": v.get("vulnerabilityName",""),
              "description": v.get("shortDescription",""), "vendor": v.get("vendorProject",""),
              "product": v.get("product",""), "cvss_score": 0.0, "severity": "High",
              "ransomware": v.get("knownRansomwareCampaignUse","Unknown"),
              "patch_available": True, "source": "CISA_KEV", "synced_at": synced_at}
             for v in data.get("vulnerabilities",[])]
    db.run_batch(MERGE_VULN, batch)
    print(f"  [KEV] {len(batch)} entries synced")
    return len(batch)

def sync_nvd_delta(db):
    now   = datetime.now(timezone.utc)
    start = (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S.000")
    end   = now.strftime("%Y-%m-%dT%H:%M:%S.000")
    print(f"  [NVD] Delta {start[:10]} to {end[:10]}...")
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    try:
        r = requests.get(NVD_CVE_URL, headers=headers, timeout=60,
                         params={"pubStartDate": start, "pubEndDate": end,
                                 "cvssV3Severity": "CRITICAL", "resultsPerPage": 2000})
        r.raise_for_status()
        vulns = r.json().get("vulnerabilities", [])
    except Exception as e:
        print(f"  [NVD] WARNING: {e}"); return 0
    if not vulns:
        print("  [NVD] No new Critical CVEs today"); return 0
    batch = []
    synced_at = now.isoformat()
    for item in vulns:
        cve  = item.get("cve", {})
        desc = next((d["value"] for d in cve.get("descriptions",[]) if d.get("lang")=="en"), "")[:600]
        cvss = 0.0
        for m in cve.get("metrics",{}).get("cvssMetricV31",[]):
            cvss = m.get("cvssData",{}).get("baseScore",0.0); break
        batch.append({"cve_id": cve.get("id",""), "title": cve.get("id",""), "description": desc,
                      "vendor": "", "product": "", "cvss_score": cvss, "severity": "Critical",
                      "ransomware": "Unknown", "patch_available": False,
                      "source": "NVD", "synced_at": synced_at})
    db.run_batch(MERGE_VULN, batch)
    print(f"  [NVD] {len(batch)} new CVEs added")
    return len(batch)

def main():
    print("=" * 55)
    print(f"  DS-09: Daily Sync — {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print("=" * 55)
    db = Neo4jClient()
    kev = sync_cisa_kev(db)
    time.sleep(2)
    nvd = sync_nvd_delta(db)
    db.close()
    print("\\n" + "=" * 55)
    print(f"  KEV synced: {kev}  |  NVD new: {nvd}")
    print("=" * 55)

if __name__ == "__main__": main()
''')


# ── verify.py ────────────────────────────────────────────────────────────────
write(os.path.join(BASE, "verify.py"), '''import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from neo4j_utils import Neo4jClient

def verify():
    print("\\n" + "="*55)
    print("  GraphRisk — Graph Verification")
    print("="*55)
    db = Neo4jClient()

    print("\\n  Node Counts:")
    for row in db.run("MATCH (n) RETURN labels(n)[0] AS type, count(n) AS total ORDER BY total DESC"):
        print(f"    {(row.get(\'type\') or \'Unknown\'):<28} {row[\'total\']:>8,}")

    print("\\n  Relationship Counts:")
    for row in db.run("MATCH ()-[r]->() RETURN type(r) AS type, count(r) AS total ORDER BY total DESC"):
        print(f"    {row[\'type\']:<28} {row[\'total\']:>8,}")

    print("\\n  Frameworks Loaded:")
    for row in db.run("MATCH (fc:FrameworkControl)-[:PART_OF]->(f:Framework) RETURN f.name AS name, f.version AS ver, count(fc) AS c ORDER BY c DESC"):
        print(f"    {row[\'name\']:<20} v{row[\'ver\']:<10} {row[\'c\']:>6,} controls")

    print("\\n  Vulnerabilities by Source:")
    for row in db.run("MATCH (v:Vulnerability) RETURN v.source AS src, count(v) AS total ORDER BY total DESC"):
        print(f"    {(row[\'src\'] or \'Unknown\'):<20} {row[\'total\']:>8,}")

    db.close()
    print("\\n" + "="*55)

if __name__ == "__main__": verify()
''')


# ── run_initial_load.py ───────────────────────────────────────────────────────
write(os.path.join(BASE, "run_initial_load.py"), '''import sys, os, time, importlib.util
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from neo4j_utils import test_connection

BASE   = os.path.dirname(os.path.abspath(__file__))
INGEST = os.path.join(BASE, "ingest")

SCRIPTS = [
    ("ingest/06_cisa_kev.py",    "DS-06: CISA KEV"),
    ("ingest/01_nist_csf.py",    "DS-01: NIST CSF 2.0"),
    ("ingest/02_nist_800_53.py", "DS-02: NIST SP 800-53 Rev5"),
    ("ingest/04_mitre_attack.py","DS-04: MITRE ATT&CK"),
    ("ingest/07_nvd_cve.py",     "DS-07: NVD CVE (Critical)"),
]

def run(path, name):
    print(f"\\n{\\'=\\'*55}\\n  {name}\\n{\\'=\\'*55}")
    try:
        spec = importlib.util.spec_from_file_location("m", os.path.join(BASE, path))
        mod  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.ingest()
        return True
    except Exception as e:
        print(f"  FAILED: {e}"); return False

def main():
    print("\\n" + "="*55)
    print("  GraphRisk — Initial Data Load")
    print("="*55)
    if not test_connection():
        print("Cannot connect to Neo4j."); sys.exit(1)
    results = {}
    for path, name in SCRIPTS:
        ok = run(path, name)
        results[name] = "OK" if ok else "FAILED"
        if ok: time.sleep(2)
    print("\\n\\n" + "="*55)
    print("  Summary")
    print("="*55)
    for name, status in results.items():
        icon = "✓" if status == "OK" else "✗"
        print(f"  {icon}  {name}: {status}")
    print("="*55)

if __name__ == "__main__": main()
''')


print("\n" + "="*55)
print("  All scripts created successfully.")
print("="*55)
print("\n  Next — run DS-01 (NIST CSF):")
print("  python ingest\\01_nist_csf.py")
print("="*55)
