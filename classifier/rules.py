"""Classifier rules models: Pydantic for YAML-based device classification rules."""

from typing import Optional, Union, List, Dict, Any
from pydantic import BaseModel, field_validator
import re


class Match(BaseModel):
    """Single match condition for a rule."""
    oui: Optional[str] = None
    mac_regex: Optional[str] = None
    port: Optional[Union[int, str]] = None
    port_regex: Optional[str] = None
    os_guess: Optional[str] = None
    os_regex: Optional[str] = None
    vendor: Optional[str] = None
    vendor_regex: Optional[str] = None
    hostname: Optional[str] = None
    hostname_regex: Optional[str] = None
    banner: Optional[str] = None
    banner_regex: Optional[str] = None
    protocol: Optional[str] = None
    protocol_regex: Optional[str] = None
    product: Optional[str] = None
    product_regex: Optional[str] = None

    @field_validator("mac_regex", "port_regex", "os_regex", "vendor_regex", "hostname_regex", "banner_regex", "protocol_regex", "product_regex")
    @classmethod
    def validate_regex(cls, v: Optional[str]) -> Optional[str]:
        if v:
            try:
                re.compile(v)
            except re.error as e:
                raise ValueError(f"Invalid regex '{v}': {e}")
        return v

    def matches_host(self, host: Dict[str, Any]) -> bool:
        """Check if this match condition matches a host record."""
        if self.oui and host.get("mac", "").upper().startswith(self.oui.upper()):
            return True
        if self.mac_regex and host.get("mac"):
            try:
                if re.match(self.mac_regex, host["mac"], re.IGNORECASE):
                    return True
            except Exception:
                pass
        if self.port:
            # Check single port field
            if str(self.port) == str(host.get("port")):
                return True
            # Check open_ports list (from TCP port scan)
            open_ports = host.get("open_ports")
            if open_ports:
                if isinstance(open_ports, str):
                    open_ports = [int(p) for p in open_ports.split(",") if p.strip()]
                if int(self.port) in [int(p) for p in open_ports]:
                    return True
        if self.port_regex:
            candidates = []
            if host.get("port"):
                candidates.append(str(host["port"]))
            open_ports = host.get("open_ports")
            if open_ports:
                if isinstance(open_ports, str):
                    open_ports = [p.strip() for p in open_ports.split(",") if p.strip()]
                candidates.extend([str(p) for p in open_ports])
            for candidate in candidates:
                try:
                    if re.match(self.port_regex, candidate, re.IGNORECASE):
                        return True
                except Exception:
                    pass
        if self.os_guess and host.get("os_guess"):
            if self.os_guess.lower() in host["os_guess"].lower():
                return True
        if self.os_regex and host.get("os_guess"):
            try:
                if re.match(self.os_regex, host["os_guess"], re.IGNORECASE):
                    return True
            except Exception:
                pass
        if self.vendor and host.get("vendor"):
            if self.vendor.lower() in host["vendor"].lower():
                return True
        if self.vendor_regex and host.get("vendor"):
            try:
                if re.match(self.vendor_regex, host["vendor"], re.IGNORECASE):
                    return True
            except Exception:
                pass
        if self.hostname and host.get("hostname"):
            if self.hostname.lower() in host["hostname"].lower():
                return True
        if self.hostname_regex and host.get("hostname"):
            try:
                if re.match(self.hostname_regex, host["hostname"], re.IGNORECASE):
                    return True
            except Exception:
                pass
        if self.banner:
            banner_candidates = [host["banner"]] if host.get("banner") else []
            for svc in host.get("services", []):
                if svc.get("banner"):
                    banner_candidates.append(svc["banner"])
            for candidate in banner_candidates:
                if self.banner.lower() in candidate.lower():
                    return True
        if self.banner_regex:
            banner_candidates = [host["banner"]] if host.get("banner") else []
            for svc in host.get("services", []):
                if svc.get("banner"):
                    banner_candidates.append(svc["banner"])
            for candidate in banner_candidates:
                try:
                    if re.search(self.banner_regex, candidate, re.IGNORECASE):
                        return True
                except Exception:
                    pass
        if self.protocol and host.get("protocol"):
            if self.protocol.lower() == host["protocol"].lower():
                return True
        if self.protocol_regex and host.get("protocol"):
            try:
                if re.match(self.protocol_regex, host["protocol"], re.IGNORECASE):
                    return True
            except Exception:
                pass
        if self.product:
            for svc in host.get("services", []):
                if svc.get("product") and self.product.lower() in svc["product"].lower():
                    return True
        if self.product_regex:
            for svc in host.get("services", []):
                if svc.get("product"):
                    try:
                        if re.search(self.product_regex, svc["product"], re.IGNORECASE):
                            return True
                    except Exception:
                        pass
        return False


class Rule(BaseModel):
    """Single classification rule."""
    name: str
    category: str
    description: Optional[str] = None
    matches: List[Match]
    priority: int = 0
    tags: List[str] = []

    @field_validator("name", "category")
    @classmethod
    def non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Cannot be empty")
        return v

    @field_validator("priority")
    @classmethod
    def validate_priority(cls, v: int) -> int:
        if v < 0:
            raise ValueError("Priority must be >= 0")
        return v

    def matches_host(self, host: Dict[str, Any]) -> bool:
        """Check if all match conditions match."""
        return all(m.matches_host(host) for m in self.matches)


class RuleSet(BaseModel):
    """Collection of classification rules."""
    version: str = "1.0"
    rules: List[Rule] = []

    def classify_host(self, host: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Classify a host using all rules, sorted by priority."""
        classifications = []
        for rule in sorted(self.rules, key=lambda r: r.priority, reverse=True):
            if rule.matches_host(host):
                classifications.append({
                    "rule_name": rule.name,
                    "category": rule.category,
                    "description": rule.description,
                    "priority": rule.priority,
                    "tags": rule.tags
                })
        return classifications


def load_rules_from_yaml(yaml_path: str) -> RuleSet:
    """Load rules from YAML file."""
    import yaml
    with open(yaml_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return RuleSet(**data)


def load_rules_from_dict(data: Dict[str, Any]) -> RuleSet:
    """Load rules from dictionary."""
    return RuleSet(**data)
