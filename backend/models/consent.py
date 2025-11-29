from sqlalchemy import Column, Integer, String, Boolean, DateTime, Enum, Text, ForeignKey
import enum
# Remove this line: from database.config import Base
from sqlalchemy.ext.declarative import declarative_base

from models import Base  # Import from shared models package# Add this line

class Consent(Base):
    __tablename__ = "consents"
    
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    patient_id = Column(Integer)  # REMOVED: ForeignKey("users.id")
    doctor_id = Column(Integer)   # REMOVED: ForeignKey("users.id")
    record_id = Column(Integer)   # REMOVED: ForeignKey("health_records.id")
    wrapped_key = Column(Text)
    is_active = Column(Boolean, default=True)
    granted_at = Column(DateTime)
    expires_at = Column(DateTime)