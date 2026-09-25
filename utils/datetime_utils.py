"""Time helpers."""

from datetime import datetime, timezone


def utcnow() -> datetime:
    """Return the current UTC time as a naive datetime (no tzinfo).

    Naive UTC values are stored in the database so that existing
    ``DateTime`` columns and prior comparisons keep working unchanged,
    while avoiding the deprecation warning emitted by
    ``datetime.utcnow()`` on Python 3.12+.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)
