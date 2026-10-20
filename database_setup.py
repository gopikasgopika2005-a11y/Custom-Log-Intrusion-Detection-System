
import sqlite3

connection = sqlite3.connect("ids.db")

cursor = connection.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip TEXT NOT NULL,
    failed_attempts INTEGER NOT NULL,
    window_start TEXT,
    window_end TEXT,
    severity TEXT,
    alert_message TEXT
)
""")

connection.commit()
connection.close()

print("SQLite database created successfully!")
print("Database file: ids.db")
print("Table created: alerts")
