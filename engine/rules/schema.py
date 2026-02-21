from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass(slots=True)
class Rule:
    """Placeholder TTP rule schema. Detection logic is intentionally minimal."""

    rule_id: str
    name: str
    source_types: list[str] = field(default_factory=list)
    target_types: list[str] = field(default_factory=list)
    prerequisites: list[str] = field(default_factory=list)
    event_predicate: dict[str, str] | None = None
    severity: float = 1.0


@dataclass(slots=True)
class RuleSet:
    rules: list[Rule] = field(default_factory=list)
    scoring_alpha: float = 1.0
    has_scoring_alpha: bool = False


class RuleValidationError(ValueError):
    pass


def _ensure_list_of_str(name: str, value: Any) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(x, str) for x in value):
        raise RuleValidationError(f"{name} must be a list[str]")
    return value


def _ensure_event_predicate(value: Any) -> dict[str, str] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise RuleValidationError("event_predicate must be a mapping")
    if len(value) != 1:
        raise RuleValidationError("event_predicate supports exactly one key: op or event_type")

    key = next(iter(value.keys()))
    if key not in {"op", "event_type"}:
        raise RuleValidationError("event_predicate supports exactly one key: op or event_type")

    predicate_value = value.get(key)
    if not isinstance(predicate_value, str) or not predicate_value:
        raise RuleValidationError(f"event_predicate.{key} must be a non-empty string")
    return {key: predicate_value}


def _ensure_severity(value: Any) -> float:
    if value is None:
        return 1.0
    if not isinstance(value, (int, float)):
        raise RuleValidationError("severity must be a number")
    return float(value)


def _ensure_scoring_alpha(payload: Any) -> tuple[float, bool]:
    if payload is None:
        return 1.0, False
    if not isinstance(payload, dict):
        raise RuleValidationError("scoring must be a mapping")
    has_alpha = "alpha" in payload
    alpha = payload.get("alpha", 1.0)
    if not isinstance(alpha, (int, float)):
        raise RuleValidationError("scoring.alpha must be a number")
    return float(alpha), has_alpha


def validate_ruleset(ruleset: RuleSet) -> None:
    seen: set[str] = set()
    for idx, rule in enumerate(ruleset.rules, start=1):
        if not rule.rule_id:
            raise RuleValidationError(f"rules[{idx}] missing rule_id")
        if rule.rule_id in seen:
            raise RuleValidationError(f"duplicate rule_id: {rule.rule_id}")
        seen.add(rule.rule_id)


def load_rules_yaml(path: str | Path) -> RuleSet:
    """Load YAML rulebook placeholder. Empty file/rules are valid."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Rule file not found: {p}")

    text = p.read_text(encoding="utf-8")
    if not text.strip():
        return RuleSet()

    payload = yaml.safe_load(text)
    if payload is None:
        return RuleSet()
    if not isinstance(payload, dict):
        raise RuleValidationError("rule file root must be a mapping")

    rule_items = payload.get("rules", [])
    if rule_items is None:
        rule_items = []
    if not isinstance(rule_items, list):
        raise RuleValidationError("rules must be a list")

    rules: list[Rule] = []
    for idx, item in enumerate(rule_items, start=1):
        if not isinstance(item, dict):
            raise RuleValidationError(f"rules[{idx}] must be a mapping")

        rule_id = item.get("rule_id")
        name = item.get("name")
        if not isinstance(rule_id, str) or not isinstance(name, str):
            raise RuleValidationError(f"rules[{idx}] requires string rule_id and name")

        rules.append(
            Rule(
                rule_id=rule_id,
                name=name,
                source_types=_ensure_list_of_str("source_types", item.get("source_types")),
                target_types=_ensure_list_of_str("target_types", item.get("target_types")),
                prerequisites=_ensure_list_of_str("prerequisites", item.get("prerequisites")),
                event_predicate=_ensure_event_predicate(item.get("event_predicate")),
                severity=_ensure_severity(item.get("severity")),
            )
        )

    scoring_alpha, has_scoring_alpha = _ensure_scoring_alpha(payload.get("scoring"))
    ruleset = RuleSet(rules=rules, scoring_alpha=scoring_alpha, has_scoring_alpha=has_scoring_alpha)
    validate_ruleset(ruleset)
    return ruleset
