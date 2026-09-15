import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from neo4j_utils import Neo4jClient
import anthropic
from config import ANTHROPIC_API_KEY
from tqdm import tqdm

client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

FETCH_MISSING = """
    MATCH (n)
    WHERE (n:FrameworkControl OR n:Technique)
    AND (n.graphrisk_summary IS NULL OR n.graphrisk_summary = "")
    RETURN n.id AS id,
           coalesce(n.title, n.name, n.control_reference, n.technique_id) AS title,
           coalesce(n.control_reference, n.technique_id, "") AS ref,
           coalesce(n.domain, n.family, "") AS domain,
           labels(n)[0] AS node_type
    LIMIT 2000
"""

SET_SUMMARY = """
    MATCH (n {id: $node_id})
    SET n.graphrisk_summary = $summary
"""

def build_prompt(title, ref, domain, node_type):
    if node_type == "Technique":
        return f"""You are GraphRisk, a cybersecurity risk intelligence platform.
Write a 2-3 sentence original description of the adversary technique '{title}' (ATT&CK ID: {ref}).
Focus on: what attackers achieve, what organizational risk it creates, what defenders should monitor.
Do not reproduce ATT&CK text. Write from general cybersecurity knowledge.
Output only the description with no labels or preamble."""
    else:
        return f"""You are GraphRisk, a cybersecurity risk intelligence platform.
Write a 2-3 sentence original description of the security control '{title}' (reference: {ref}, domain: {domain}).
Focus on: the risk management purpose, what organizational risk it reduces, why it matters to a CISO.
Do not reproduce copyrighted standard text. Write from general cybersecurity knowledge.
Output only the description with no labels or preamble."""

def generate_summary(title, ref, domain, node_type, retries=3):
    for attempt in range(retries):
        try:
            msg = client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=200,
                messages=[{"role": "user", "content": build_prompt(title, ref, domain, node_type)}]
            )
            return msg.content[0].text.strip()
        except Exception as e:
            if attempt < retries - 1:
                wait = 2 ** attempt * 2
                time.sleep(wait)
            else:
                raise e

def ingest():
    print("=" * 55)
    print("  DS-08: AI Summary Generation")
    print("=" * 55)

    if not ANTHROPIC_API_KEY:
        print("  ERROR: ANTHROPIC_API_KEY not set in .env")
        return

    db = Neo4jClient()
    nodes = db.run(FETCH_MISSING)
    print(f"\n  Nodes needing summaries: {len(nodes)}")

    if not nodes:
        print("  All nodes already have summaries.")
        db.close()
        return

    print(f"  Estimated cost: ~${len(nodes) * 0.0006:.2f} USD")
    print(f"  Estimated time: ~{len(nodes) // 30} minutes")
    print("\n  Starting generation...\n")

    success, failed = 0, 0
    for node in tqdm(nodes):
        try:
            summary = generate_summary(
                node.get("title") or node.get("ref") or "Unknown",
                node.get("ref") or "",
                node.get("domain") or "",
                node.get("node_type") or "FrameworkControl"
            )
            db.run(SET_SUMMARY, {"node_id": node["id"], "summary": summary})
            success += 1
            time.sleep(0.1)
        except Exception as e:
            failed += 1

    db.close()
    print("\n" + "=" * 55)
    print("  DS-08: AI Summary Generation Complete")
    print("=" * 55)
    print(f"  Success : {success}")
    print(f"  Failed  : {failed}")
    print("\n  Verify in Neo4j Browser:")
    print("  MATCH (n) WHERE n.graphrisk_summary IS NOT NULL")
    print("  RETURN count(n) AS nodes_with_summaries")
    print("=" * 55)

if __name__ == "__main__": ingest()
