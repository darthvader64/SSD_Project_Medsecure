# force_tables.py
import sqlite3
import os

# Remove existing database
if os.path.exists("health_records.db"):
    os.remove("health_records.db")
    print("🗑️ Removed old database")

conn = sqlite3.connect('health_records.db')
cursor = conn.cursor()

# Create tables with direct SQL - NO SQLALCHEMY
tables = [
    '''CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        hashed_password TEXT NOT NULL,
        role TEXT NOT NULL,
        public_key TEXT,
        is_active BOOLEAN DEFAULT 1,
        created_at DATETIME
    )''',
    
    '''CREATE TABLE health_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id INTEGER NOT NULL,
        file_name TEXT NOT NULL,
        file_size INTEGER NOT NULL,
        storage_uri TEXT NOT NULL,
        encrypted_key TEXT NOT NULL,
        iv TEXT NOT NULL,
        algorithm TEXT NOT NULL,
        created_at DATETIME
    )''',
    
    '''CREATE TABLE consents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id INTEGER NOT NULL,
        doctor_id INTEGER NOT NULL,
        record_id INTEGER NOT NULL,
        wrapped_key TEXT NOT NULL,
        is_active BOOLEAN DEFAULT 1,
        granted_at DATETIME,
        expires_at DATETIME
    )''',
    
    '''CREATE TABLE audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        action TEXT NOT NULL,
        record_id INTEGER,
        ip_address TEXT,
        user_agent TEXT,
        timestamp DATETIME,
        status TEXT NOT NULL
    )'''
]

for sql in tables:
    cursor.execute(sql)

conn.commit()

# Verify
cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables_created = [row[0] for row in cursor.fetchall()]
print(f"🎯 Tables created: {tables_created}")

conn.close()
print("🚀 All tables created successfully!")