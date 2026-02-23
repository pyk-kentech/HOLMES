from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

from engine.core.graph import ProvenanceGraph
from engine.core.matcher import Matcher, TTPMatch
import engine.hsg.builder as hsg_builder
from engine.hsg.builder import HSG, HSGEdge, HSGNode, hsg_to_dict
from engine.hsg.prerequisite import is_path_factor_satisfied, is_prerequisite_satisfied
from engine.hsg.scorer import rank_hsg_scenarios
from engine.io.events import Event
from engine.noise.model import NoiseModel, get_benign_drop_ids
from engine.rules.schema import RuleSet, infer_rule_cvss, infer_rule_stage, path_factor_prerequisites, prerequisite_types


@dataclass(slots=True)
class StreamingStats:
    events: int = 0
    raw_matches: int = 0
    dropped_matches: int = 0
    by_signature: int = 0
    by_byte_volume: int = 0
    byte_volume_by_rule_id: dict[str, int] | None = None


class StreamingEngine:
    def __init__(
        self,
        ruleset: RuleSet,
        scoring_mode: str = "legacy",
        paper_weights: list[float] | None = None,
        paper_mode: str = "hybrid",
        alpha: float | None = None,
        noise_model: NoiseModel | None = None,
        noise_bytes_threshold: str = "p95",
    ) -> None:
        self.ruleset = ruleset
        self.scoring_mode = scoring_mode
        self.paper_weights = paper_weights
        self.paper_mode = paper_mode
        self.noise_model = noise_model
        self.noise_bytes_threshold = noise_bytes_threshold

        self.graph = ProvenanceGraph()
        self.matcher = Matcher()
        self.rule_by_id = {r.rule_id: r for r in ruleset.rules}
        self.rule_severity = {r.rule_id: r.severity for r in ruleset.rules}
        self.rule_stage = {r.rule_id: infer_rule_stage(r) for r in ruleset.rules}
        self.rule_cvss = {r.rule_id: infer_rule_cvss(r) for r in ruleset.rules}
        if ruleset.has_scoring_alpha:
            self.alpha = ruleset.scoring_alpha
        elif alpha is not None:
            self.alpha = float(alpha)
        else:
            self.alpha = 1.0

        self.events_by_id: dict[str, Event] = {}
        self.matches: list[TTPMatch] = []
        self.match_by_id: dict[str, TTPMatch] = {}
        self.hsg_nodes: dict[str, HSGNode] = {}
        self.hsg_edges: list[HSGEdge] = []
        self.seen_edges: set[tuple[str, str, str]] = set()

        # Pointer propagation MVP indexes.
        self.node_to_matches: dict[str, set[str]] = defaultdict(set)
        self.match_to_entities: dict[str, set[str]] = {}

        self._match_serial = 1
        self.stats = StreamingStats(byte_volume_by_rule_id={})
        self.top_scenarios: list[dict[str, Any]] = []

    def _next_match_id(self) -> str:
        mid = f"m{self._match_serial}"
        self._match_serial += 1
        return mid

    def _reid_match(self, m: TTPMatch) -> TTPMatch:
        return TTPMatch(
            match_id=self._next_match_id(),
            rule_id=m.rule_id,
            event_ids=list(m.event_ids),
            entities=list(m.entities),
            bindings=dict(m.bindings),
            metadata=dict(m.metadata),
        )

    def _candidate_match_ids(self, new_match: TTPMatch) -> set[str]:
        candidate_ids: set[str] = set()
        for entity in new_match.entities:
            reachable = self.graph.descendants(entity) | self.graph.ancestors(entity) | {entity}
            for node in reachable:
                candidate_ids |= self.node_to_matches.get(node, set())
        if not candidate_ids:
            candidate_ids = set(self.match_by_id.keys())
        return candidate_ids

    def _edge_for_pair(self, left: TTPMatch, right: TTPMatch) -> list[HSGEdge]:
        left_rule = self.rule_by_id.get(left.rule_id)
        right_rule = self.rule_by_id.get(right.rule_id)
        left_prereqs = prerequisite_types(left_rule)
        right_prereqs = prerequisite_types(right_rule)
        prereq_types = left_prereqs | right_prereqs

        built: list[HSGEdge] = []
        for relation in prereq_types:
            if relation == "graph_path" and (left.rule_id, right.rule_id) not in hsg_builder.GRAPH_PATH_ALLOWLIST:
                continue
            config = hsg_builder._resolve_prereq_config(relation, left.rule_id, right.rule_id)  # noqa: SLF001
            if not is_prerequisite_satisfied(self.graph, left, right, relation, config):
                continue
            edge_key = (left.match_id, right.match_id, relation)
            if edge_key in self.seen_edges:
                continue

            weight: float | None = None
            edge_path_factor: float | None = None
            edge_dependency_strength: float | None = None
            if relation == "graph_path" and config:
                from_binding = config.get("from_binding")
                to_binding = config.get("to_binding")
                from_entity = left.bindings.get(from_binding) if from_binding else None
                to_entity = right.bindings.get(to_binding) if to_binding else None
                if not from_entity or not to_entity:
                    continue
                path_factor_reqs = path_factor_prerequisites(left_rule) + path_factor_prerequisites(right_rule)
                if any(
                    not is_path_factor_satisfied(
                        self.graph,
                        from_entity,
                        to_entity,
                        prereq.threshold,
                        prereq.op,
                    )
                    for prereq in path_factor_reqs
                ):
                    continue
                dependency = self.graph.dependency_strength(from_entity, to_entity)
                edge_dependency_strength = dependency
                edge_path_factor = self.graph.path_factor(from_entity, to_entity)
                if self.paper_mode == "strict":
                    weight = edge_path_factor
                else:
                    weight = dependency * edge_path_factor

            self.seen_edges.add(edge_key)
            built.append(
                HSGEdge(
                    src=left.match_id,
                    dst=right.match_id,
                    relation=relation,
                    weight=weight,
                    path_factor=edge_path_factor,
                    dependency_strength=edge_dependency_strength,
                )
            )
        return built

    def _apply_noise_model(self, new_matches: list[TTPMatch]) -> list[TTPMatch]:
        if not self.noise_model or not new_matches:
            return new_matches
        drop_ids, noise_stats = get_benign_drop_ids(
            new_matches,
            rule_by_id=self.rule_by_id,
            model=self.noise_model,
            events_by_id=self.events_by_id,
            bytes_threshold=self.noise_bytes_threshold,
        )
        self.stats.by_signature += int(noise_stats.get("by_signature", 0))
        self.stats.by_byte_volume += int(noise_stats.get("by_byte_volume", 0))
        by_rule = noise_stats.get("byte_volume_by_rule_id", {})
        if isinstance(by_rule, dict) and self.stats.byte_volume_by_rule_id is not None:
            for rid, cnt in by_rule.items():
                self.stats.byte_volume_by_rule_id[rid] = self.stats.byte_volume_by_rule_id.get(rid, 0) + int(cnt)

        kept = [m for m in new_matches if m.match_id not in drop_ids]
        self.stats.dropped_matches += len(new_matches) - len(kept)
        return kept

    def _refresh_scores(self) -> None:
        self.top_scenarios = rank_hsg_scenarios(
            self.current_hsg(),
            scoring="weighted",
            rule_severity=self.rule_severity,
            alpha=self.alpha,
            top_k=3,
            score_mode=self.scoring_mode,
            rule_stage=self.rule_stage,
            rule_cvss=self.rule_cvss,
            paper_weights=self.paper_weights,
        )

    def process_event(self, event: Event) -> None:
        self.stats.events += 1
        self.events_by_id[event.event_id] = event
        self.graph.add_event(event)

        raw_matches = [self._reid_match(m) for m in self.matcher.match(self.graph, self.ruleset, [event])]
        self.stats.raw_matches += len(raw_matches)
        new_matches = self._apply_noise_model(raw_matches)

        for new_match in new_matches:
            candidate_ids = self._candidate_match_ids(new_match)
            for old_id in candidate_ids:
                old_match = self.match_by_id.get(old_id)
                if old_match is None:
                    continue
                self.hsg_edges.extend(self._edge_for_pair(old_match, new_match))

            self.matches.append(new_match)
            self.match_by_id[new_match.match_id] = new_match
            self.hsg_nodes[new_match.match_id] = HSGNode(
                match_id=new_match.match_id,
                rule_id=new_match.rule_id,
                event_ids=list(new_match.event_ids),
                entities=list(new_match.entities),
            )
            entities = set(new_match.entities)
            self.match_to_entities[new_match.match_id] = entities
            for entity in entities:
                self.node_to_matches[entity].add(new_match.match_id)

        self._refresh_scores()

    def current_hsg(self) -> HSG:
        return HSG(nodes=list(self.hsg_nodes.values()), edges=list(self.hsg_edges))

    def build_result(self) -> dict[str, Any]:
        hsg = self.current_hsg()
        noise_filter = {
            "before": {
                "matches": self.stats.raw_matches,
                "hsg_nodes": self.stats.raw_matches,
                "hsg_edges": len(hsg.edges),
            },
            "after": {
                "matches": len(self.matches),
                "hsg_nodes": len(hsg.nodes),
                "hsg_edges": len(hsg.edges),
            },
            "dropped": {
                "matches": self.stats.raw_matches - len(self.matches),
                "hsg_nodes": self.stats.raw_matches - len(hsg.nodes),
                "hsg_edges": 0,
            },
        }
        noise_filter["trained_noise"] = {
            "dropped_matches": self.stats.dropped_matches,
            "by_signature": self.stats.by_signature,
            "by_byte_volume": self.stats.by_byte_volume,
            "byte_volume_by_rule_id": self.stats.byte_volume_by_rule_id or {},
        }
        return {
            "summary": {
                "events": self.stats.events,
                "rules": len(self.ruleset.rules),
                "matches": len(self.matches),
                "hsg_nodes": len(hsg.nodes),
                "hsg_edges": len(hsg.edges),
                "noise_filter": noise_filter,
                "top_scenarios": self.top_scenarios,
            },
            "matches": [
                {
                    "match_id": m.match_id,
                    "rule_id": m.rule_id,
                    "event_ids": m.event_ids,
                    "entities": m.entities,
                    "bindings": m.bindings,
                    "metadata": m.metadata,
                }
                for m in self.matches
            ],
            "hsg": hsg_to_dict(hsg),
        }

    def write_snapshot(self, out_dir: str | Path) -> dict[str, Any]:
        p = Path(out_dir)
        p.mkdir(parents=True, exist_ok=True)
        result = self.build_result()
        (p / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        (p / "summary.json").write_text(json.dumps(result["summary"], indent=2), encoding="utf-8")
        (p / "matches.json").write_text(json.dumps(result["matches"], indent=2), encoding="utf-8")
        (p / "hsg.json").write_text(json.dumps(result["hsg"], indent=2), encoding="utf-8")
        return result
