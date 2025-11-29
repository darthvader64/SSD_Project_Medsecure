from sqlalchemy import Column, Integer, String, Boolean, DateTime, Enum, Text, ForeignKey
import enum
# Remove this line: from database.config import Base
from sqlalchemy.ext.declarative import declarative_base

from models import Base  # Import from shared models package  # Add this line

class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer)  # REMOVED: ForeignKey("users.id")
    action = Column(String(100))
    record_id = Column(Integer)  # REMOVED: ForeignKey("health_records.id")
    ip_address = Column(String(45))
    user_agent = Column(Text)
    timestamp = Column(DateTime)
    status = Column(String(20))