"""Database initialization and session helpers."""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from typing import Generator

from .models import Host, Alert, EventLog, ScanSession, Service, MacHistory, WifiNetwork, WifiAttack, Base

DATABASE_URL = "sqlite:///./network_scanner.db"

engine = create_engine(DATABASE_URL, echo=False, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_session() -> Generator:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _migrate_add_columns():
    from sqlalchemy import inspect, text

    inspector = inspect(engine)
    if "hosts" not in inspector.get_table_names():
        return
    existing = {col["name"] for col in inspector.get_columns("hosts")}
    with engine.begin() as conn:
        if "open_ports" not in existing:
            conn.execute(text("ALTER TABLE hosts ADD COLUMN open_ports TEXT"))
        if "cves" not in existing:
            conn.execute(text("ALTER TABLE hosts ADD COLUMN cves TEXT"))
        if "is_sniffing" not in existing:
            conn.execute(text("ALTER TABLE hosts ADD COLUMN is_sniffing INTEGER DEFAULT 0"))
        if "sniffing_evidence" not in existing:
            conn.execute(text("ALTER TABLE hosts ADD COLUMN sniffing_evidence TEXT"))


def init_db():
    Base.metadata.create_all(bind=engine)
    _migrate_add_columns()
