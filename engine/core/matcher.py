from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from engine.core.graph import ProvenanceGraph
from engine.io.events import Event
from engine.rules.schema import RuleSet


@dataclass(slots=True)
class TTPMatch:
    """A matched rule instance against one or more events."""

    match_id: str
    rule_id: str
    event_ids: list[str] = field(default_factory=list)
    entities: list[str] = field(default_factory=list)
    bindings: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


class Matcher:
    """Placeholder matcher: no rules -> no matches."""

    @staticmethod
    def _entity_type(entity: str | None) -> str | None:
        if not entity:
            return None
        prefix = entity.split(":", 1)[0].lower()
        mapping = {
            "proc": "process",
            "reg": "registry",
        }
        return mapping.get(prefix, prefix)

    def match(self, graph: ProvenanceGraph, ruleset: RuleSet, events: list[Event]) -> list[TTPMatch]:
        if not ruleset.rules:
            return []

        matches: list[TTPMatch] = []
        serial = 1

        for rule in ruleset.rules:
            for event in events:
                ev_op = None
                if isinstance(event.raw, dict):
                    raw_op = event.raw.get("op")
                    if raw_op is not None:
                        ev_op = str(raw_op)

                ev_event_type = getattr(event, "event_type", None)
                if ev_event_type is None and isinstance(event.raw, dict):
                    raw_event_type = event.raw.get("event_type")
                    if raw_event_type is not None:
                        ev_event_type = str(raw_event_type)

                if rule.event_predicate:
                    expected_op = rule.event_predicate.get("op")
                    expected_event_type = rule.event_predicate.get("event_type")
                    if expected_op is not None and ev_op != expected_op:
                        continue
                    if expected_event_type is not None and ev_event_type != expected_event_type:
                        continue

                source_type = self._entity_type(event.subject)
                target_type = self._entity_type(event.object)
                allowed_source_types = {x.lower() for x in rule.source_types}
                allowed_target_types = {x.lower() for x in rule.target_types}
                if allowed_source_types and source_type not in allowed_source_types:
                    continue
                if allowed_target_types and target_type not in allowed_target_types:
                    continue

                entities = [x for x in (event.subject, event.object) if x]
                bindings: dict[str, str] = {}
                if event.subject:
                    bindings["subject"] = event.subject
                if event.object:
                    bindings["object"] = event.object
                matches.append(
                    TTPMatch(
                        match_id=f"m{serial}",
                        rule_id=rule.rule_id,
                        event_ids=[event.event_id],
                        entities=entities,
                        bindings=bindings,
                        metadata={"op": ev_op, "event_type": ev_event_type},
                    )
                )
                serial += 1

        return matches
