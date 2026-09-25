from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean

from .models import Base
from utils.datetime_utils import utcnow


class ScanSession(Base):
    __tablename__ = "scan_sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    network = Column(String(50), nullable=False)
    range_start = Column(String(45), nullable=False)
    range_end = Column(String(45), nullable=False)
    started_at = Column(DateTime, default=utcnow)
    completed_at = Column(DateTime, nullable=True)
    total_hosts = Column(Integer, default=0)
    active_hosts = Column(Integer, default=0)
    new_hosts = Column(Integer, default=0)
    status = Column(String(20), default="running")
    scan_type = Column(String(20), default="normal")
    completed = Column(Boolean, default=False)
