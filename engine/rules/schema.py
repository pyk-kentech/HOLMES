from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

SUPPORTED_PATH_FACTOR_OPS: set[str] = {">=", "<=", ">", "<"}
APT_STAGES: tuple[str, ...] = (
    "Initial Compromise",
    "Establish Foothold",
    "Internal Recon",
    "Privilege Escalation",
    "Move Laterally",
    "Exfiltration",
    "Cleanup",
)
DEFAULT_APT_STAGE: str = APT_STAGES[0]
DEFAULT_STAGE: int = 1


@dataclass(slots=True, frozen=True)
class PathFactorPrerequisite:
    type: str = "path_factor"
    threshold: float = 0.0
    op: str = ">="


RulePrerequisite = str | PathFactorPrerequisite


@dataclass(slots=True)
class Rule:
    """Placeholder TTP rule schema. Detection logic is intentionally minimal."""

    rule_id: str
    name: str
    source_types: list[str] = field(default_factory=list)
    target_types: list[str] = field(default_factory=list)
    prerequisites: list[RulePrerequisite] = field(default_factory=list)
    event_predicate: dict[str, str] | None = None
    severity: float = 1.0
    apt_stage: str = DEFAULT_APT_STAGE
    stage: int | None = None
    cvss: float | None = None
    tactic: str | None = None
    technique: str | None = None


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


def _ensure_prerequisites(value: Any) -> list[RulePrerequisite]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise RuleValidationError("prerequisites must be a list")

    result: list[RulePrerequisite] = []
    for idx, item in enumerate(value, start=1):
        if isinstance(item, str):
            result.append(item)
            continue
        if not isinstance(item, dict):
            raise RuleValidationError(f"prerequisites[{idx}] must be str or mapping")

        prereq_type = item.get("type")
        if prereq_type != "path_factor":
            raise RuleValidationError(f"prerequisites[{idx}].type must be 'path_factor'")

        threshold = item.get("threshold")
        if not isinstance(threshold, (int, float)):
            raise RuleValidationError(f"prerequisites[{idx}].threshold must be a number")

        op = item.get("op", ">=")
        if not isinstance(op, str) or op not in SUPPORTED_PATH_FACTOR_OPS:
            raise RuleValidationError(
                f"prerequisites[{idx}].op must be one of {sorted(SUPPORTED_PATH_FACTOR_OPS)}"
            )

        result.append(PathFactorPrerequisite(threshold=float(threshold), op=op))
    return result


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


def _ensure_apt_stage(value: Any) -> str:
    if value is None:
        return DEFAULT_APT_STAGE
    if not isinstance(value, str):
        raise RuleValidationError("apt_stage must be a string")
    if value not in APT_STAGES:
        raise RuleValidationError(f"apt_stage must be one of {list(APT_STAGES)}")
    return value


def _apt_stage_to_stage(apt_stage: str) -> int:
    try:
        return APT_STAGES.index(apt_stage) + 1
    except ValueError:
        return DEFAULT_STAGE


def _stage_to_apt_stage(stage: int) -> str:
    idx = max(1, min(int(stage), len(APT_STAGES))) - 1
    return APT_STAGES[idx]


def _ensure_stage(value: Any) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int):
        raise RuleValidationError("stage must be an integer")
    if value < 1 or value > 7:
        raise RuleValidationError("stage must be in range [1, 7]")
    return value


def _ensure_cvss(value: Any) -> float | None:
    if value is None:
        return None
    if not isinstance(value, (int, float)):
        raise RuleValidationError("cvss must be a number")
    f = float(value)
    if f < 0.0 or f > 10.0:
        raise RuleValidationError("cvss must be in range [0, 10]")
    return f


def _ensure_optional_str(name: str, value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise RuleValidationError(f"{name} must be a string")
    return value


def infer_rule_stage(rule: Rule) -> int:
    """Infer paper-stage index for a rule when explicit stage is absent."""
    if isinstance(rule.stage, int) and 1 <= rule.stage <= 7:
        return rule.stage

    if isinstance(rule.apt_stage, str) and rule.apt_stage in APT_STAGES:
        return _apt_stage_to_stage(rule.apt_stage)

    event_type = None
    if isinstance(rule.event_predicate, dict):
        event_type = rule.event_predicate.get("event_type")

    text_values = [
        (event_type or "").lower(),
        (rule.technique or "").lower(),
        (rule.tactic or "").lower(),
    ]
    joined = " ".join(v for v in text_values if v)

    if "proc_to_proc" in joined or "file_to_proc" in joined:
        return 2
    if "proc_to_file" in joined or "proc_to_registry" in joined:
        return 3
    if "file_to_ip" in joined or "proc_to_ip" in joined:
        return 5
    return DEFAULT_STAGE


def infer_rule_cvss(rule: Rule) -> float:
    """Infer CVSS-like severity used by paper scoring."""
    raw = rule.cvss if rule.cvss is not None else rule.severity
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return 1.0
    return max(0.0, min(10.0, value))


def prerequisite_types(rule: Rule | None) -> set[str]:
    if rule is None:
        return set()

    types: set[str] = set()
    for prereq in rule.prerequisites:
        if isinstance(prereq, str):
            types.add(prereq)
    return types


def path_factor_prerequisites(rule: Rule | None) -> list[PathFactorPrerequisite]:
    if rule is None:
        return []
    return [p for p in rule.prerequisites if isinstance(p, PathFactorPrerequisite)]


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

        apt_stage_value = _ensure_apt_stage(item.get("apt_stage"))
        stage_value = _ensure_stage(item.get("stage"))
        if item.get("apt_stage") is None and stage_value is not None:
            apt_stage_value = _stage_to_apt_stage(stage_value)

        rules.append(
            Rule(
                rule_id=rule_id,
                name=name,
                source_types=_ensure_list_of_str("source_types", item.get("source_types")),
                target_types=_ensure_list_of_str("target_types", item.get("target_types")),
                prerequisites=_ensure_prerequisites(item.get("prerequisites")),
                event_predicate=_ensure_event_predicate(item.get("event_predicate")),
                severity=_ensure_severity(item.get("severity")),
                apt_stage=apt_stage_value,
                stage=stage_value,
                cvss=_ensure_cvss(item.get("cvss")),
                tactic=_ensure_optional_str("tactic", item.get("tactic")),
                technique=_ensure_optional_str("technique", item.get("technique")),
            )
        )

    scoring_alpha, has_scoring_alpha = _ensure_scoring_alpha(payload.get("scoring"))
    ruleset = RuleSet(rules=rules, scoring_alpha=scoring_alpha, has_scoring_alpha=has_scoring_alpha)
    validate_ruleset(ruleset)
    return ruleset
