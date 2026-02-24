from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import unquote
from zoneinfo import ZoneInfo

try:
    from zoneinfo import ZoneInfoNotFoundError, available_timezones
except ImportError:  # pragma: no cover - fallback for older runtimes.
    ZoneInfoNotFoundError = Exception  # type: ignore[assignment]

    def available_timezones() -> set[str]:  # type: ignore[override]
        return {"UTC"}


TIMEZONE_COOKIE = "pfv_timezone"
DEFAULT_TIMEZONE = "UTC"
MAX_TIMEZONE_LENGTH = 64

try:
    _AVAILABLE_TIMEZONES = frozenset(available_timezones())
except Exception:  # pragma: no cover - runtime data issue fallback.
    _AVAILABLE_TIMEZONES = frozenset({DEFAULT_TIMEZONE})


def normalize_timezone(value: str | None) -> str | None:
    cleaned = (value or "").strip()
    if "%" in cleaned:
        try:
            cleaned = unquote(cleaned).strip()
        except Exception:
            pass
    if not cleaned:
        return None
    if len(cleaned) > MAX_TIMEZONE_LENGTH:
        return None
    if cleaned.upper() == "UTC":
        return DEFAULT_TIMEZONE
    if cleaned in _AVAILABLE_TIMEZONES:
        return cleaned
    try:
        ZoneInfo(cleaned)
    except ZoneInfoNotFoundError:
        return None
    except Exception:
        return None
    return cleaned


def timezone_options() -> list[str]:
    return sorted(_AVAILABLE_TIMEZONES)


def _zone_for_name(value: str | None) -> ZoneInfo:
    normalized = normalize_timezone(value) or DEFAULT_TIMEZONE
    try:
        return ZoneInfo(normalized)
    except Exception:
        return ZoneInfo(DEFAULT_TIMEZONE)


def format_datetime_for_timezone(value: datetime | None, tz_name: str | None) -> str:
    if not value:
        return "-"
    zone = _zone_for_name(tz_name)
    aware = value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value
    local = aware.astimezone(zone)
    label = local.tzname() or (normalize_timezone(tz_name) or DEFAULT_TIMEZONE)
    return f"{local.strftime('%Y-%m-%d %H:%M:%S')} {label}"


def format_datetime_iso_utc(value: datetime | None) -> str:
    if not value:
        return ""
    if value.tzinfo is None:
        return value.strftime("%Y-%m-%dT%H:%M:%SZ")
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
