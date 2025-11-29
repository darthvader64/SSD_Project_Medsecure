#!/usr/bin/env python3
"""
Reset test database - removes test user to allow fresh test runs
"""

from database.config import SessionLocal, engine, Base
from models.user import User
from models.health_record import HealthRecord
from models.consent import Consent
from models.audit_log import AuditLog

def reset_test_data():
    """Remove test user and related data"""
    db = SessionLocal()
    
    try:
        # Delete test user
        test_user = db.query(User).filter_by(email='test_patient@example.com').first()
        if test_user:
            # Delete related records first (foreign key constraints)
            db.query(HealthRecord).filter_by(patient_id=test_user.id).delete()
            db.query(Consent).filter_by(patient_id=test_user.id).delete()
            db.query(Consent).filter_by(doctor_id=test_user.id).delete()
            db.query(AuditLog).filter_by(user_id=test_user.id).delete()
            
            # Delete the user
            db.delete(test_user)
            db.commit()
            print('[OK] Test user and related data deleted')
        else:
            print('[INFO] No test user found')
            
    except Exception as e:
        print(f'[ERROR] Failed to reset: {str(e)}')
        db.rollback()
        import traceback
        traceback.print_exc()
    finally:
        db.close()

if __name__ == '__main__':
    reset_test_data()
