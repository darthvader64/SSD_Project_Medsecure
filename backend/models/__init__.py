# models/__init__.py
# Import Base from database config (shared instance)
from database.config import Base

# Import all models here to register them with Base
from .user import User
from .health_record import HealthRecord
from .consent import Consent
from .audit_log import AuditLog

__all__ = ['Base', 'User', 'HealthRecord', 'Consent', 'AuditLog']