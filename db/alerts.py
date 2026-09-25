from sqlalchemy import Column, Integer, String, DateTime, Text, JSON, Boolean

from .models import Base
from utils.datetime_utils import utcnow


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    severity = Column(String(20), nullable=False, index=True)  # INFO, WARN, ALERT
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    source_ip = Column(String(45), nullable=True, index=True)
    target_ip = Column(String(45), nullable=True, index=True)
    rule = Column(String(100), nullable=True)
    payload = Column(JSON, nullable=True)
    timestamp = Column(DateTime, default=utcnow, index=True)
    acknowledged = Column(Boolean, default=False)
    acknowledged_at = Column(DateTime, nullable=True)
    action = Column(String(50), nullable=True)
