import sqlite3
conn = sqlite3.connect('zerotrust_edr.db')
print("=== alerts columns ===")
for row in conn.execute("PRAGMA table_info(alerts)").fetchall():
    print(f"  {row[1]:35s} {row[2]}")

print("\n=== alert_responses columns ===")
for row in conn.execute("PRAGMA table_info(alert_responses)").fetchall():
    print(f"  {row[1]:35s} {row[2]}")

print("\n=== alembic version ===")
print(conn.execute("SELECT * FROM alembic_version").fetchall())
conn.close()
