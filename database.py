import sqlite3

conn = sqlite3.connect("security.db", check_same_thread=False)

cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    severity TEXT,
    risk_score INTEGER,
    summary TEXT
)
""")

conn.commit()