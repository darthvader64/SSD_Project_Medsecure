import os
import sqlite3
import shutil
import time

db_path = 'health_records.db'
if os.path.exists(db_path):
    print(f'[INFO] Backing up old database: {db_path}')
    backup_path = 'health_records.db.backup'
    try:
        shutil.copy(db_path, backup_path)
        print(f'[OK] Backup created at {backup_path}')
        time.sleep(1)
        os.remove(db_path)
        print('[OK] Old database removed')
    except PermissionError:
        print('[WARN] Database is in use (Flask app running). Please close it first.')
        exit(1)

# IMPORTANT: Import models BEFORE engine to register them with Base
from models.user import User
from models.health_record import HealthRecord
from models.consent import Consent
from models.audit_log import AuditLog
from database.config import engine, Base

print('[INFO] Creating database tables with new schema...')
Base.metadata.create_all(bind=engine)
print('[OK] Database tables created')

# Verify
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = cursor.fetchall()
print('[INFO] Tables created:')
for table in tables:
    print(f'  ✓ {table[0]}')

if any(t[0] == 'health_records' for t in tables):
    cursor.execute('PRAGMA table_info(health_records)')
    columns = cursor.fetchall()
    print('[INFO] HealthRecord columns:')
    for col in columns:
        print(f'  ✓ {col[1]}')
    
    if any(c[1] == 'salt' for c in columns):
        print('[OK] ✓ Salt column present!')
    else:
        print('[ERROR] Salt column NOT found!')

conn.close()
print('[OK] Database schema verified')

