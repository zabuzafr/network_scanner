"""Pydantic models for FastAPI requests/responses."""

from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime


class HostOut(BaseModel):
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    mac_type: Optional[str] = None
    vendor: Optional[str] = None
    os_guess: Optional[str] = None
    ttl: Optional[int] = None
    ttl_src: Optional[str] = None
    port: Optional[int] = None
    banner: Optional[str] = None
    protocol: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


class ScanRequest(BaseModel):
    cidr: Optional[str] = "10.0.0.0/24"
    iface: Optional[str] = None
    timeout: Optional[int] = 2


class ScanResponse(BaseModel):
    scan_id: str
    hosts_scanned: int
    hosts: List[HostOut]


class ClassificationOut(BaseModel):
    device_class: Optional[str] = None
    confidence: Optional[float] = None
    matched_rules: Optional[List[str]] = None
    details: Optional[Dict[str, Any]] = None


class StatusOut(BaseModel):
    status: str
    version: str
    uptime: Optional[str] = None
