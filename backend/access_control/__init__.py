# This file makes the access_control directory a Python package
from .rbac import Permission, has_permission, get_role_permissions
from .authorization import check_record_access, check_consent_permission, check_audit_access
from .decorators import require_permission, require_record_access