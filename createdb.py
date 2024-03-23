import sqlite3

db = sqlite3.connect("db.sqlite3")
with open("schema.sql", "r") as f:
    sql = str(f.read())
    print(sql)
db.executescript(sql)
db.commit()
