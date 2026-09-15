import sys, os, time, importlib.util
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
    print(f"\n{\'=\'*55}\n  {name}\n{\'=\'*55}")
    try:
        spec = importlib.util.spec_from_file_location("m", os.path.join(BASE, path))
        mod  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.ingest()
        return True
    except Exception as e:
        print(f"  FAILED: {e}"); return False

def main():
    print("\n" + "="*55)
    print("  GraphRisk — Initial Data Load")
    print("="*55)
    if not test_connection():
        print("Cannot connect to Neo4j."); sys.exit(1)
    results = {}
    for path, name in SCRIPTS:
        ok = run(path, name)
        results[name] = "OK" if ok else "FAILED"
        if ok: time.sleep(2)
    print("\n\n" + "="*55)
    print("  Summary")
    print("="*55)
    for name, status in results.items():
        icon = "✓" if status == "OK" else "✗"
        print(f"  {icon}  {name}: {status}")
    print("="*55)

if __name__ == "__main__": main()
