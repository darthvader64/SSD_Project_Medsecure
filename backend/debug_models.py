# debug_models.py
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

print("🔍 Debugging model imports...")

try:
    from database.config import Base
    print("✅ Base imported successfully")
    
    # Try importing each model one by one
    try:
        from models.user import User
        print("✅ User model imported")
    except Exception as e:
        print(f"❌ User model failed: {e}")
    
    try:
        from models.health_record import HealthRecord
        print("✅ HealthRecord model imported")
    except Exception as e:
        print(f"❌ HealthRecord model failed: {e}")
    
    try:
        from models.consent import Consent
        print("✅ Consent model imported")
    except Exception as e:
        print(f"❌ Consent model failed: {e}")
    
    try:
        from models.audit_log import AuditLog
        print("✅ AuditLog model imported")
    except Exception as e:
        print(f"❌ AuditLog model failed: {e}")
        
    # Check what tables Base knows about
    print(f"📊 Tables registered with Base: {list(Base.metadata.tables.keys())}")
    
except Exception as e:
    print(f"💥 Critical error: {e}")
    import traceback
    traceback.print_exc()