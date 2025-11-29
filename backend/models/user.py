from sqlalchemy import Column, Integer, String, Boolean, DateTime, Enum, Text, ForeignKey
import enum
# Remove this line: from database.config import Base
from sqlalchemy.ext.declarative import declarative_base

from models import Base  # Import from shared models package # Add this line

class UserRole(enum.Enum):
    PATIENT = "PATIENT"
    DOCTOR = "DOCTOR"

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    email = Column(String(255), unique=True, index=True)
    hashed_password = Column(String(255))
    role = Column(Enum(UserRole))
    public_key = Column(Text)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime)