import sqlite3
conn = sqlite3.connect('zerotrust_edr.db')
tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
print("=== Tables in DB ===")
for t in tables:
    print(f"  {t[0]}")

print("\n=== users table columns ===")
try:
    for row in conn.execute("PRAGMA table_info(users)").fetchall():
        print(f"  {row[1]:35s} {row[2]}")
except Exception as e:
    print(f"  Error: {e}")

print("\n=== Sample users ===")
try:
    for row in conn.execute("SELECT id, username, email, is_active, role_id FROM users LIMIT 5").fetchall():
        print(f"  {row}")
except Exception as e:
    print(f"  No users or error: {e}")

conn.close()
