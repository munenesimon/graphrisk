import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from neo4j_utils import Neo4jClient

def verify():
    print("\n" + "="*55)
    print("  GraphRisk — Graph Verification")
    print("="*55)
    db = Neo4jClient()

    print("\n  Node Counts:")
    for row in db.run("MATCH (n) RETURN labels(n)[0] AS type, count(n) AS total ORDER BY total DESC"):
        print(f"    {(row.get('type') or 'Unknown'):<28} {row['total']:>8,}")

    print("\n  Relationship Counts:")
    for row in db.run("MATCH ()-[r]->() RETURN type(r) AS type, count(r) AS total ORDER BY total DESC"):
        print(f"    {row['type']:<28} {row['total']:>8,}")

    print("\n  Frameworks Loaded:")
    for row in db.run("MATCH (fc:FrameworkControl)-[:PART_OF]->(f:Framework) RETURN f.name AS name, f.version AS ver, count(fc) AS c ORDER BY c DESC"):
        print(f"    {row['name']:<20} v{row['ver']:<10} {row['c']:>6,} controls")

    print("\n  Vulnerabilities by Source:")
    for row in db.run("MATCH (v:Vulnerability) RETURN v.source AS src, count(v) AS total ORDER BY total DESC"):
        print(f"    {(row['src'] or 'Unknown'):<20} {row['total']:>8,}")

    db.close()
    print("\n" + "="*55)

if __name__ == "__main__": verify()
