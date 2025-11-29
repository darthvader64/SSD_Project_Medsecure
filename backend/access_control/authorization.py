from database.config import SessionLocal
from models.consent import Consent
from models.health_record import HealthRecord
from models.audit_log import AuditLog
from .rbac import has_permission, Permission

def check_record_access(user_id, user_role, record_id, action):
    """Check if user can access a specific health record"""
    
    db = SessionLocal()
    
    try:
        # Get the record
        record = db.query(HealthRecord).filter(HealthRecord.id == record_id).first()
        if not record:
            return False, "Record not found"
            
        # Check basic permission first
        if not has_permission(user_role, action):
            return False, "Role lacks permission for this action"
            
        # Patients can access their own records
        if record.patient_id == user_id:
            return True, "Owner access"
        
        # Doctors need active consent for read access
        if user_role == "doctor" and action == Permission.READ_RECORD:
            consent = db.query(Consent).filter(
                Consent.doctor_id == user_id,
                Consent.record_id == record_id,
                Consent.is_active == True
            ).first()
            
            if consent:
                return True, "Consent-based access"
            else:
                return False, "No active consent found"
        
        return False, "Access denied"
        
    except Exception as e:
        return False, f"Error checking access: {str(e)}"
    finally:
        db.close()

def check_consent_permission(patient_id, target_patient_id, action):
    """Check if user can manage consent for a patient"""
    # Patients can only manage their own consents
    if patient_id == target_patient_id and has_permission("patient", action):
        return True, "Owner consent management"
    return False, "Cannot manage consents for other patients"

def check_audit_access(user_id, target_user_id, user_role):
    """Check if user can view audit logs"""
    # Users can only view their own audit logs
    if user_id == target_user_id and has_permission(user_role, Permission.VIEW_AUDIT_LOGS):
        return True, "Own audit access"
    return False, "Cannot view other users' audit logs"

def check_doctor_list_access(user_role):
    """Check if user can view doctors list"""
    return has_permission(user_role, Permission.VIEW_DOCTORS_LIST)