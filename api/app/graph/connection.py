from neo4j import GraphDatabase
from app.config import settings

_driver = None

def get_graph_client():
    global _driver
    if _driver is None:
        _driver = GraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password)
        )
    return _driver

def close_graph_client():
    global _driver
    if _driver:
        _driver.close()
        _driver = None

def run_query(query: str, params: dict = None):
    driver = get_graph_client()
    with driver.session() as session:
        result = session.run(query, params or {})
        return result.data()

def run_write(query: str, params: dict = None):
    driver = get_graph_client()
    with driver.session() as session:
        result = session.run(query, params or {})
        return result.data()
