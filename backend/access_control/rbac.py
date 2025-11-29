from enum import Enum

class Permission(Enum):
    # Record Permissions
    READ_RECORD = "read_record"
    CREATE_RECORD = "create_record" 
    UPDATE_RECORD = "update_record"
    DELETE_RECORD = "delete_record"
    LIST_RECORDS = "list_records"
    
    # Consent Permissions
    GRANT_CONSENT = "grant_consent"
    REVOKE_CONSENT = "revoke_consent"
    LIST_CONSENTS = "list_consents"
    
    # Audit Permissions
    VIEW_AUDIT_LOGS = "view_audit_logs"
    
    # User Permissions
    VIEW_DOCTORS_LIST = "view_doctors_list"

# Role-Based Access Control Matrix - USE UPPERCASE
ROLE_PERMISSIONS = {
    "PATIENT": [  # ✅ UPPERCASE
        Permission.READ_RECORD,
        Permission.CREATE_RECORD,
        Permission.DELETE_RECORD,
        Permission.LIST_RECORDS,
        Permission.GRANT_CONSENT,
        Permission.REVOKE_CONSENT,
        Permission.LIST_CONSENTS,
        Permission.VIEW_AUDIT_LOGS,
        Permission.VIEW_DOCTORS_LIST
    ],
    "DOCTOR": [  # ✅ UPPERCASE
        Permission.READ_RECORD,  # Only with consent
        Permission.LIST_RECORDS,  # Only accessible records
        Permission.VIEW_AUDIT_LOGS  # Only own logs
    ]
}

def has_permission(role, permission):
    """Check if a role has specific permission"""
    return permission in ROLE_PERMISSIONS.get(role, [])

def get_role_permissions(role):
    """Get all permissions for a role"""
    return ROLE_PERMISSIONS.get(role, [])