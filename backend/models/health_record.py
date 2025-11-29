from sqlalchemy import Column, Integer, String, Boolean, DateTime, Enum, Text, ForeignKey
import enum
# Remove this line: from database.config import Base
from sqlalchemy.ext.declarative import declarative_base

from models import Base  # Import from shared models package  # Add this line

class HealthRecord(Base):
    __tablename__ = "health_records"
    
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    patient_id = Column(Integer)  # REMOVED: ForeignKey("users.id")
    file_name = Column(String(255))
    file_size = Column(Integer)
    storage_uri = Column(String(500))
    encrypted_key = Column(Text)  # Patient wrap (wrapped with passphrase)
    iv = Column(String(255))  # Initialization vector for AES
    salt = Column(String(255))  # Salt for PBKDF2 key derivation
    algorithm = Column(String(50))
    created_at = Column(DateTime)