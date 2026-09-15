from neo4j import GraphDatabase
from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD


class Neo4jClient:
    def __init__(self):
        self.driver = GraphDatabase.driver(
            NEO4J_URI,
            auth=(NEO4J_USER, NEO4J_PASSWORD)
        )

    def run(self, query, params=None):
        with self.driver.session() as session:
            result = session.run(query, params or {})
            return result.data()

    def run_batch(self, query, batch, batch_size=500):
        total = len(batch)
        for i in range(0, total, batch_size):
            chunk = batch[i:i + batch_size]
            with self.driver.session() as session:
                session.run(query, {"batch": chunk})
        return total

    def close(self):
        self.driver.close()


def test_connection():
    try:
        db = Neo4jClient()
        result = db.run("RETURN 'GraphRisk connected!' AS message")
        print(result[0]["message"])
        db.close()
        return True
    except Exception as e:
        print(f"Connection failed: {e}")
        return False


if __name__ == "__main__":
    test_connection()
