"""Database models for scanner."""

import json
from sqlalchemy import Column, Integer, String, DateTime, Text, LargeBinary, ForeignKey
from sqlalchemy.orm import relationship, declarative_base
from utils.datetime_utils import utcnow

Base = declarative_base()


class Host(Base):
    __tablename__ = "hosts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip = Column(String(45), nullable=False, index=True)
    mac = Column(String(17), nullable=True, index=True)
    hostname = Column(String(255), nullable=True)
    mac_type = Column(String(20), nullable=True)
    vendor = Column(String(255), nullable=True)
    os_guess = Column(String(100), nullable=True)
    ttl = Column(Integer, nullable=True)
    ttl_src = Column(String(20), nullable=True)
    port = Column(Integer, nullable=True)
    open_ports = Column(Text, nullable=True)
    cves = Column(Text, nullable=True)
    banner = Column(Text, nullable=True)
    protocol = Column(String(50), nullable=True)
    classifications = Column(Text, nullable=True)
    is_sniffing = Column(Integer, default=0, nullable=True)
    sniffing_evidence = Column(Text, nullable=True)
    first_seen = Column(DateTime, default=utcnow, nullable=False)
    last_seen = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)
    scan_session_id = Column(Integer, ForeignKey("scan_sessions.id"), nullable=True)

    scan_session = relationship("ScanSession", back_populates="hosts")
    alerts = relationship("Alert", back_populates="host")
    events = relationship("EventLog", back_populates="host")
    services = relationship("Service", back_populates="host", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "mac_type": self.mac_type,
            "vendor": self.vendor,
            "os_guess": self.os_guess,
            "ttl": self.ttl,
            "ttl_src": self.ttl_src,
            "port": self.port,
            "open_ports": self.open_ports,
            "cves": json.loads(self.cves) if self.cves else [],
            "banner": self.banner,
            "protocol": self.protocol,
            "classifications": json.loads(self.classifications) if self.classifications else [],
            "is_sniffing": bool(self.is_sniffing),
            "sniffing_evidence": json.loads(self.sniffing_evidence) if self.sniffing_evidence else [],
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "scan_session_id": self.scan_session_id,
        }


class ScanSession(Base):
    __tablename__ = "scan_sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    start_time = Column(DateTime, default=utcnow, nullable=False)
    end_time = Column(DateTime, nullable=True)
    cidr = Column(String(50), nullable=False)
    iface = Column(String(50), nullable=True)
    total_hosts = Column(Integer, default=0)
    completed = Column(Integer, default=0)
    status = Column(String(20), default="running")

    hosts = relationship("Host", back_populates="scan_session")
    event_logs = relationship("EventLog", back_populates="scan_session")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False)
    type = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), default="info")
    message = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=utcnow, nullable=False)

    host = relationship("Host", back_populates="alerts")

    def to_dict(self):
        return {
            "id": self.id,
            "host_id": self.host_id,
            "host_ip": self.host.ip if self.host else None,
            "type": self.type,
            "severity": self.severity,
            "message": self.message,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }


class MacHistory(Base):
    __tablename__ = "mac_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    host_ip = Column(String(45), nullable=False, index=True)
    mac = Column(String(17), nullable=False, index=True)
    first_seen = Column(DateTime, default=utcnow, nullable=False)
    last_seen = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    host = relationship("Host", uselist=False, lazy="select", primaryjoin="MacHistory.host_ip == foreign(Host.ip)")


class Service(Base):
    __tablename__ = "services"

    id = Column(Integer, primary_key=True, autoincrement=True)
    host_ip = Column(String(45), nullable=False, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=True)
    scan_session_id = Column(Integer, ForeignKey("scan_sessions.id"), nullable=True)
    port = Column(Integer, nullable=False)
    name = Column(String(50), nullable=True)
    product = Column(String(255), nullable=True)
    version = Column(String(100), nullable=True)
    manufacturer = Column(String(255), nullable=True)
    default_credentials = Column(Text, nullable=True)
    banner = Column(Text, nullable=True)
    first_seen = Column(DateTime, default=utcnow, nullable=False)
    last_seen = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    scan_session = relationship("ScanSession", backref="services")
    host = relationship("Host", back_populates="services")

    def to_dict(self):
        return {
            "id": self.id,
            "host_ip": self.host_ip,
            "scan_session_id": self.scan_session_id,
            "port": self.port,
            "name": self.name,
            "product": self.product,
            "version": self.version,
            "manufacturer": self.manufacturer,
            "default_credentials": self.default_credentials,
            "banner": self.banner,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }


class WifiNetwork(Base):
    __tablename__ = "wifi_networks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    bssid = Column(String(30), nullable=False, unique=True, index=True)
    ssid = Column(String(255), nullable=True)
    mode = Column(String(30), nullable=True)
    channel = Column(String(20), nullable=True)
    security = Column(Text, nullable=True)
    signal = Column(Integer, nullable=True)
    first_seen = Column(DateTime, default=utcnow, nullable=False)
    last_seen = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)
    acknowledged = Column(Integer, default=0, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "bssid": self.bssid,
            "ssid": self.ssid,
            "mode": self.mode,
            "channel": self.channel,
            "security": json.loads(self.security) if self.security else [],
            "signal": self.signal,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "acknowledged": bool(self.acknowledged),
        }


class WifiAttack(Base):
    __tablename__ = "wifi_attacks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    bssid = Column(String(30), nullable=False, index=True)
    ssid = Column(String(255), nullable=True)
    type = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), default="info")
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    acknowledged = Column(Integer, default=0, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "bssid": self.bssid,
            "ssid": self.ssid,
            "type": self.type,
            "severity": self.severity,
            "description": self.description,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "acknowledged": bool(self.acknowledged),
        }


class EventLog(Base):
    __tablename__ = "event_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=True)
    scan_session_id = Column(Integer, ForeignKey("scan_sessions.id"), nullable=True)
    event_type = Column(String(50), nullable=False, index=True)
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=utcnow, nullable=False)

    host = relationship("Host", back_populates="events")
    scan_session = relationship("ScanSession", back_populates="event_logs")
