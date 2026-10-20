
import sqlite3

connection = sqlite3.connect("ids.db")
cursor = connection.cursor()

cursor.execute("SELECT * FROM alerts")
rows = cursor.fetchall()

print("\nSAVED SECURITY ALERTS")
print("-" * 50)

if rows:
    for row in rows:
        print(row)
else:
    print("No alerts found in database.")

connection.close()
