# init_db.py
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from database.config import engine, Base

# CRITICAL: Import ALL models so SQLAlchemy knows about them
from models.user import User
from models.health_record import HealthRecord
from models.consent import Consent
from models.audit_log import AuditLog

def create_tables():
    """Create all database tables"""
    try:
        print("🔄 Creating database tables...")
        
        # This will create tables for ALL imported models
        Base.metadata.create_all(bind=engine)
        print("✅ All tables created successfully!")
        
        # Verify tables
        from sqlalchemy import inspect
        inspector = inspect(engine)
        table_names = inspector.get_table_names()
        print(f"📊 Tables in database: {table_names}")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    create_tables()