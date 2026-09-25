from sqlalchemy import Column, Integer, String, DateTime, Text, JSON

from .models import Base
from utils.datetime_utils import utcnow


class EventLog(Base):
    __tablename__ = "event_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_type = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), nullable=True, index=True)
    ip = Column(String(45), nullable=True, index=True)
    mac = Column(String(17), nullable=True)
    details = Column(Text, nullable=True)
    metadata = Column(JSON, nullable=True)
    timestamp = Column(DateTime, default=utcnow, index=True)
