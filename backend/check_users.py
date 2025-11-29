# check_users.py
from database.config import SessionLocal
from models.user import User

db = SessionLocal()
users = db.query(User).all()

print("=== USERS IN DATABASE ===")
for user in users:
    print(f'ID: {user.id}, Email: {user.email}, Password: {user.hashed_password}, Role: {user.role}')

print(f"Total users: {len(users)}")
db.close()