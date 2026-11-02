from datetime import UTC, datetime


def as_utc(value: datetime | None) -> datetime | None:
    """SQLite returns naive datetimes; treat them as UTC so clients parse them
    correctly instead of interpreting them in the browser's local timezone."""
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def iso(value: datetime | None) -> str | None:
    normalized = as_utc(value)
    return normalized.isoformat() if normalized else None
