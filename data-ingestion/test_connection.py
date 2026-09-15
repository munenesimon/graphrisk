import os
from neo4j import GraphDatabase

uri  = os.environ["NEO4J_URI"]
user = os.environ["NEO4J_USER"]
pwd  = os.environ["NEO4J_PASSWORD"]

print("URI repr :", repr(uri))
print("USER repr:", repr(user))
import hashlib; print("PWD HASH:", hashlib.sha256(pwd.encode()).hexdigest()[:16]); print("PWD chars:", repr(pwd[0]), "...", repr(pwd[-1]), "len:", len(pwd))

driver = GraphDatabase.driver(uri, auth=(user, pwd))
with driver.session() as s:
    result = s.run("RETURN 1 AS ok").single()["ok"]
    print("Query result:", result)
driver.close()
print("CONNECTION OK")
