from __future__ import annotations

from dataclasses import dataclass, field
import json
import math
from pathlib import Path
from typing import Any

from engine.core.graph import ProvenanceGraph
from engine.core.matcher import TTPMatch
from engine.io.events import Event
from engine.rules.schema import Rule

BYTE_VALUE_KEYS: tuple[str, ...] = (
    "bytes",
    "size",
    "len",
    "nbytes",
    "byte_count",
    "total_bytes",
    "transfer_bytes",
    "sent_bytes",
    "recv_bytes",
    "write_bytes",
    "read_bytes",
)
BYTE_THRESHOLD_CHOICES: set[str] = {"p50", "p95", "p99", "max"}


@dataclass(slots=True)
class NoiseModel:
    version: int = 1
    benign_signatures: dict[str, dict[str, int]] = field(default_factory=dict)
    params: dict[str, Any] = field(default_factory=lambda: {"min_count": 5, "bytes_min_count": 20})
    byte_volume: dict[str, dict[str, float]] = field(default_factory=dict)


def _entity_prefix(entity: str) -> str:
    return entity.split(":", 1)[0].lower() if ":" in entity else entity.lower()


def _prereq_type(prereq: Any) -> str:
    if isinstance(prereq, str):
        return prereq
    t = getattr(prereq, "type", None)
    if isinstance(t, str):
        return t
    return str(type(prereq).__name__)


def build_signature(match: TTPMatch, rule: Rule | None, graph: ProvenanceGraph | None = None) -> dict[str, Any]:
    del graph
    bindings_shape = ",".join(sorted(match.bindings.keys()))
    entities_shape = ",".join(sorted(_entity_prefix(e) for e in match.entities))
    prereq_types = sorted({_prereq_type(p) for p in (rule.prerequisites if rule else [])})
    event_type = None
    if isinstance(match.metadata, dict):
        event_type = match.metadata.get("event_type")
    return {
        "rule_id": match.rule_id,
        "event_type": event_type,
        "bindings_shape": bindings_shape,
        "entities_shape": entities_shape,
        "prereq_types": prereq_types,
    }


def signature_key(signature: dict[str, Any]) -> str:
    return json.dumps(signature, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _to_nonneg_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        n = int(value)
        return n if n >= 0 else None
    if isinstance(value, str):
        v = value.strip()
        if not v:
            return None
        try:
            if "." in v:
                n = int(float(v))
            else:
                n = int(v)
        except ValueError:
            return None
        return n if n >= 0 else None
    return None


def extract_flow_bytes(event: Event) -> int | None:
    raw = event.raw
    if not isinstance(raw, dict):
        return None

    sent = _to_nonneg_int(raw.get("sent_bytes"))
    recv = _to_nonneg_int(raw.get("recv_bytes"))
    if sent is not None and recv is not None:
        return sent + recv

    written = _to_nonneg_int(raw.get("write_bytes"))
    read = _to_nonneg_int(raw.get("read_bytes"))
    if written is not None and read is not None:
        return written + read

    for key in BYTE_VALUE_KEYS:
        n = _to_nonneg_int(raw.get(key))
        if n is not None:
            return n
    return None


def _extract_match_bytes(match: TTPMatch, events_by_id: dict[str, Any]) -> float | None:
    values: list[int] = []
    for event_id in match.event_ids:
        event = events_by_id.get(event_id)
        if isinstance(event, Event):
            b = extract_flow_bytes(event)
            if b is not None:
                values.append(b)
        elif event is not None:
            raw = getattr(event, "raw", None)
            if isinstance(raw, dict):
                pseudo = Event(
                    event_id=str(getattr(event, "event_id", event_id)),
                    ts=None,
                    event_type=str(getattr(event, "event_type", "unknown")),
                    subject=None,
                    object=None,
                    raw=raw,
                )
                b = extract_flow_bytes(pseudo)
                if b is not None:
                    values.append(b)
    if not values:
        return None
    return float(sum(values))


def _percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = max(0, math.ceil(p * len(ordered)) - 1)
    idx = min(idx, len(ordered) - 1)
    return float(ordered[idx])


def _byte_volume_stats(values: list[float]) -> dict[str, float]:
    ordered = sorted(values)
    return {
        "count": float(len(ordered)),
        "p50": _percentile(ordered, 0.50),
        "p95": _percentile(ordered, 0.95),
        "p99": _percentile(ordered, 0.99),
        "max": float(ordered[-1]) if ordered else 0.0,
    }


def _as_int_if_whole(value: float) -> int | float:
    if float(value).is_integer():
        return int(value)
    return float(value)


def _normalize_byte_volume_stats(stats: dict[str, Any]) -> dict[str, float]:
    count = _to_nonneg_int(stats.get("count"))
    p50 = stats.get("p50")
    p95 = stats.get("p95")
    p99 = stats.get("p99")
    mx = stats.get("max")
    return {
        "count": float(count if count is not None else 0),
        "p50": float(p50) if isinstance(p50, (int, float)) else 0.0,
        "p95": float(p95) if isinstance(p95, (int, float)) else 0.0,
        "p99": float(p99) if isinstance(p99, (int, float)) else 0.0,
        "max": float(mx) if isinstance(mx, (int, float)) else 0.0,
    }


def train_noise_model(
    matches: list[TTPMatch],
    rule_by_id: dict[str, Rule],
    min_count: int = 5,
    bytes_min_count: int = 20,
    events_by_id: dict[str, Any] | None = None,
) -> NoiseModel:
    sig_counts: dict[str, int] = {}
    bytes_by_rule: dict[str, list[float]] = {}
    event_map = events_by_id or {}

    for match in matches:
        sig = build_signature(match, rule_by_id.get(match.rule_id))
        key = signature_key(sig)
        sig_counts[key] = sig_counts.get(key, 0) + 1

        b = _extract_match_bytes(match, event_map)
        if b is not None:
            bytes_by_rule.setdefault(match.rule_id, []).append(b)

    benign = {k: {"count": c} for k, c in sig_counts.items() if c >= int(min_count)}
    byte_volume: dict[str, dict[str, float]] = {}
    for rule_id, vals in bytes_by_rule.items():
        if len(vals) < int(bytes_min_count):
            continue
        byte_volume[rule_id] = _byte_volume_stats(vals)

    return NoiseModel(
        version=1,
        benign_signatures=benign,
        params={"min_count": int(min_count), "bytes_min_count": int(bytes_min_count)},
        byte_volume=byte_volume,
    )


def get_benign_drop_ids(
    matches: list[TTPMatch],
    rule_by_id: dict[str, Rule],
    model: NoiseModel,
    events_by_id: dict[str, Any] | None = None,
    bytes_threshold: str = "p95",
) -> tuple[set[str], dict[str, Any]]:
    if bytes_threshold not in BYTE_THRESHOLD_CHOICES:
        raise ValueError(f"bytes_threshold must be one of {sorted(BYTE_THRESHOLD_CHOICES)}")

    drop_ids: set[str] = set()
    by_signature = 0
    by_byte_volume = 0
    by_rule_id: dict[str, int] = {}
    event_map = events_by_id or {}

    for match in matches:
        sig = build_signature(match, rule_by_id.get(match.rule_id))
        key = signature_key(sig)
        if key in model.benign_signatures:
            drop_ids.add(match.match_id)
            by_signature += 1
            continue

        stats = model.byte_volume.get(match.rule_id)
        if isinstance(stats, dict):
            b = _extract_match_bytes(match, event_map)
            thr = stats.get(bytes_threshold)
            if b is not None and isinstance(thr, (int, float)) and b <= float(thr):
                drop_ids.add(match.match_id)
                by_byte_volume += 1
                by_rule_id[match.rule_id] = by_rule_id.get(match.rule_id, 0) + 1

    return drop_ids, {
        "by_signature": by_signature,
        "by_byte_volume": by_byte_volume,
        "byte_volume_by_rule_id": by_rule_id,
    }


def load_noise_model(path: str | Path) -> NoiseModel:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Noise model not found: {p}")
    payload = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("noise model root must be an object")

    version = int(payload.get("version", 1))
    benign = payload.get("benign_signatures", {})
    params = payload.get("params", {"min_count": 5, "bytes_min_count": 20})
    byte_volume = payload.get("byte_volume", {})
    legacy_byte_p95 = payload.get("byte_p95_by_rule", {})

    if not isinstance(benign, dict):
        raise ValueError("noise model benign_signatures must be an object")
    if not isinstance(params, dict):
        raise ValueError("noise model params must be an object")
    if not isinstance(byte_volume, dict):
        raise ValueError("noise model byte_volume must be an object")
    if not isinstance(legacy_byte_p95, dict):
        raise ValueError("noise model byte_p95_by_rule must be an object")

    normalized_benign: dict[str, dict[str, int]] = {}
    for k, v in benign.items():
        if isinstance(v, dict) and isinstance(v.get("count"), int):
            normalized_benign[str(k)] = {"count": int(v["count"])}

    normalized_byte_volume: dict[str, dict[str, float]] = {}
    for k, v in byte_volume.items():
        if isinstance(v, dict):
            normalized_byte_volume[str(k)] = _normalize_byte_volume_stats(v)

    for k, v in legacy_byte_p95.items():
        if str(k) in normalized_byte_volume:
            continue
        if isinstance(v, (int, float)):
            p95 = float(v)
            normalized_byte_volume[str(k)] = {
                "count": 0.0,
                "p50": p95,
                "p95": p95,
                "p99": p95,
                "max": p95,
            }

    return NoiseModel(version=version, benign_signatures=normalized_benign, params=params, byte_volume=normalized_byte_volume)


def save_noise_model(model: NoiseModel, path: str | Path) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": int(model.version),
        "benign_signatures": model.benign_signatures,
        "params": model.params,
    }
    if model.byte_volume:
        payload["byte_volume"] = {
            rid: {
                "count": _as_int_if_whole(v.get("count", 0.0)),
                "p50": float(v.get("p50", 0.0)),
                "p95": float(v.get("p95", 0.0)),
                "p99": float(v.get("p99", 0.0)),
                "max": float(v.get("max", 0.0)),
            }
            for rid, v in model.byte_volume.items()
        }
    p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
