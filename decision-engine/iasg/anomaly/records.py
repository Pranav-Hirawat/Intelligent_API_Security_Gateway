"""Parse the arrival and completion records needed for adaptive windowing."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any

from iasg.anomaly.spec import UNMATCHED_ROUTE


@dataclass(frozen=True)
class RequestRecord:
    request_id: str
    arrival_ts: datetime
    ip: str
    method: str
    path: str
    route_template: str = UNMATCHED_ROUTE
    completed_ts: datetime | None = None


def parse_ts(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    if "." in text:
        head, _, tail = text.partition(".")
        digits = ""
        while tail and tail[0].isdigit():
            digits, tail = digits + tail[0], tail[1:]
        text = f"{head}.{digits[:6]}{tail}" if digits else head + tail
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def arrival_from_json(obj: dict[str, Any]) -> RequestRecord | None:
    arrival_ts = parse_ts(obj.get("arrivalTs"))
    request_id = obj.get("requestId") or ""
    if arrival_ts is None or not request_id:
        return None
    return RequestRecord(
        request_id=request_id,
        arrival_ts=arrival_ts,
        ip=obj.get("ip") or "",
        method=obj.get("method") or "",
        path=obj.get("path") or "",
        route_template=obj.get("routeTemplate") or UNMATCHED_ROUTE,
    )


def completion_fields(obj: dict[str, Any]) -> dict[str, Any]:
    return {"completed_ts": parse_ts(obj.get("ts"))}


def record_from_event(obj: dict[str, Any]) -> RequestRecord | None:
    record = arrival_from_json(obj)
    return replace(record, **completion_fields(obj)) if record is not None else None
