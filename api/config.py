"""FastAPI configuration and app setup."""

from typing import Optional
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment."""
    app_name: str = "Network Scanner API"
    admin_email: str = "admin@localhost"
    db_url: str = "sqlite:///./network_scanner.db"
    scan_default_cidr: str = "10.0.0.0/24"
    scan_default_iface: Optional[str] = None
    scan_timeout: int = 2
    icmp_timeout: float = 1.0
    tcp_timeout: float = 1.0
    tcp_probes: str = "443,80"
    port_scan_ports: str = "22,80,8443,8899,554,9100,631,1883,8883,9001,5000,8080,443,42000,37781,17550,17551,3052"
    port_scan_timeout: float = 0.5
    banner_probe: bool = True
    banner_timeout: float = 1.5
    secret_key: str = "changeme-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    rules_yaml: str = "config/rules.yaml"
    notify_telegram: bool = False
    notify_discord: bool = False


settings = Settings()
