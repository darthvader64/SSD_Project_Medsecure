# final_fix.py
import sqlite3

def final_fix():
    conn = sqlite3.connect('health_records.db')
    cursor = conn.cursor()
    
    # Ensure all roles are uppercase
    cursor.execute("UPDATE users SET role = 'PATIENT' WHERE role = 'patient'")
    cursor.execute("UPDATE users SET role = 'DOCTOR' WHERE role = 'doctor'")
    
    # Verify
    cursor.execute("SELECT id, email, role FROM users")
    users = cursor.fetchall()
    print("✅ Final user roles:")
    for user in users:
        print(f"  {user[0]}: {user[1]} -> {user[2]}")
    
    conn.commit()
    conn.close()
    print("🎉 Database is now synchronized with your enum!")

if __name__ == "__main__":
    final_fix()