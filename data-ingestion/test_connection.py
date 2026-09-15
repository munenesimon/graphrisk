import os
import hashlib
from neo4j import GraphDatabase

uri = os.environ["NEO4J_URI"]
pwd = os.environ["NEO4J_PASSWORD"]
usr = os.environ.get("NEO4J_USER", "MISSING")

print("USER len:", len(usr), "hash:", hashlib.sha256(usr.encode()).hexdigest()[:16])
print("PWD  len:", len(pwd), "hash:", hashlib.sha256(pwd.encode()).hexdigest()[:16])

print("Attempting with HARDCODED user 'neo4j'...")
driver = GraphDatabase.driver(uri, auth=("neo4j", pwd))
with driver.session() as s:
    print("Result:", s.run("RETURN 1 AS ok").single()["ok"])
driver.close()
print("CONNECTION OK with hardcoded user")
