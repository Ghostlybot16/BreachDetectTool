from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime, timezone

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

class BreachCheckHistory(Base):
    __tablename__ = "breach_check_history"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE")) # if user is deleted, their breach history is auto removed
    email_checked = Column(String, nullable=False)
    breached = Column(String, nullable=True)
    check_time = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))