"""Logging utilities for structured JSON logging."""

import logging
import json

from .datetime_utils import utcnow


class JSONFormatter(logging.Formatter):
    """JSON log formatter."""

    def format(self, record):
        log_entry = {
            "timestamp": utcnow().isoformat() + "Z",
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry)


def setup_logging(level: str = "INFO"):
    """Setup JSON logging."""
    handler = logging.StreamHandler()
    handler.setFormatter(JSONFormatter())
    logger = logging.getLogger("network_scanner")
    logger.setLevel(getattr(logging, level.upper()))
    logger.addHandler(handler)
    return logger
