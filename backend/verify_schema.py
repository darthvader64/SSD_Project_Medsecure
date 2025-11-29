import sqlite3

conn = sqlite3.connect('health_records.db')
cursor = conn.cursor()

cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = cursor.fetchall()
print('[INFO] Tables in database:')
if tables:
    for table in tables:
        print(f'  ✓ {table[0]}')
else:
    print('  [EMPTY] No tables found')

if any(t[0] == 'health_records' for t in tables):
    cursor.execute('PRAGMA table_info(health_records)')
    cols = cursor.fetchall()
    print('[INFO] HealthRecord columns:')
    for col in cols:
        print(f'  ✓ {col[1]}')

conn.close()
print('[OK] Schema verification complete')
