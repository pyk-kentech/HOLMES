from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class Event:
    """Normalized event schema used by the MVP pipeline."""

    event_id: str
    ts: str | None
    event_type: str
    subject: str | None
    object: str | None
    raw: dict[str, Any]


class EventSchemaError(ValueError):
    """Raised when an input event cannot be normalized."""


def normalize_event(raw: dict[str, Any], index: int) -> Event:
    """Normalize flexible input JSON into the engine Event schema."""
    if not isinstance(raw, dict):
        raise EventSchemaError(f"Event at line {index} is not a JSON object")

    event_id = str(raw.get("event_id") or raw.get("id") or f"evt-{index}")
    ts = raw.get("ts") or raw.get("timestamp")
    if ts is not None:
        ts = str(ts)

    event_type = str(raw.get("event_type") or raw.get("type") or "unknown")

    subject = raw.get("subject")
    object_ = raw.get("object")
    if subject is not None:
        subject = str(subject)
    if object_ is not None:
        object_ = str(object_)

    return Event(
        event_id=event_id,
        ts=ts,
        event_type=event_type,
        subject=subject,
        object=object_,
        raw=raw,
    )


def load_events_jsonl(path: str | Path) -> list[Event]:
    """Load events from JSONL and normalize them to Event schema."""
    events: list[Event] = []
    p = Path(path)

    with p.open("r", encoding="utf-8") as f:
        for idx, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue

            try:
                raw = json.loads(line)
            except json.JSONDecodeError as exc:
                raise EventSchemaError(f"Invalid JSON at line {idx}: {exc}") from exc

            events.append(normalize_event(raw, idx))

    return events
