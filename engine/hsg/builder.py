from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path

from engine.core.graph import ProvenanceGraph
from engine.core.matcher import TTPMatch
from engine.hsg.prerequisite import is_path_factor_satisfied, is_prerequisite_satisfied
from engine.rules.schema import RuleSet, path_factor_prerequisites, prerequisite_types

PREREQ_CONFIG = {
    "graph_path": {
        "default": {
            "from_binding": "object",
            "to_binding": "object",
            "min_strength": "0.0",
        },
        "by_right_rule_id": {},
        "by_pair": {},
    }
}
GRAPH_PATH_ALLOWLIST: set[tuple[str, str]] = {("TEST_PROC_TO_FILE", "TEST_FILE_TO_IP")}


@dataclass(slots=True)
class HSGNode:
    match_id: str
    rule_id: str
    event_ids: list[str] = field(default_factory=list)
    entities: list[str] = field(default_factory=list)


@dataclass(slots=True)
class HSGEdge:
    src: str
    dst: str
    relation: str
    weight: float | None = None
    path_factor: float | None = None
    dependency_strength: float | None = None


@dataclass(slots=True)
class HSG:
    nodes: list[HSGNode] = field(default_factory=list)
    edges: list[HSGEdge] = field(default_factory=list)


def _resolve_prereq_config(relation: str, left_rule_id: str, right_rule_id: str) -> dict | None:
    entry = PREREQ_CONFIG.get(relation)
    if not isinstance(entry, dict):
        return None

    # Backward-compatible shape: {"graph_path": {"from_binding": ..., ...}}
    if "from_binding" in entry and "to_binding" in entry:
        return entry

    pair_map = entry.get("by_pair", {})
    if isinstance(pair_map, dict):
        pair_cfg = pair_map.get(f"{left_rule_id}->{right_rule_id}")
        if isinstance(pair_cfg, dict):
            return pair_cfg

    right_map = entry.get("by_right_rule_id", {})
    if isinstance(right_map, dict):
        right_cfg = right_map.get(right_rule_id)
        if isinstance(right_cfg, dict):
            return right_cfg

    default_cfg = entry.get("default")
    if isinstance(default_cfg, dict):
        return default_cfg
    return None


def build_hsg(
    matches: list[TTPMatch],
    graph: ProvenanceGraph,
    ruleset: RuleSet,
    paper_mode: str = "hybrid",
) -> HSG:
    if paper_mode not in {"hybrid", "strict"}:
        raise ValueError("paper_mode must be 'hybrid' or 'strict'")

    rule_by_id = {rule.rule_id: rule for rule in ruleset.rules}

    nodes = [
        HSGNode(
            match_id=m.match_id,
            rule_id=m.rule_id,
            event_ids=list(m.event_ids),
            entities=list(m.entities),
        )
        for m in matches
    ]

    edges: list[HSGEdge] = []
    seen_edges: set[tuple[str, str, str]] = set()
    for i in range(len(matches)):
        for j in range(i + 1, len(matches)):
            left = matches[i]
            right = matches[j]
            left_rule = rule_by_id.get(left.rule_id)
            right_rule = rule_by_id.get(right.rule_id)
            left_prereqs = prerequisite_types(left_rule)
            right_prereqs = prerequisite_types(right_rule)
            prereq_types = left_prereqs | right_prereqs

            for relation in prereq_types:
                if relation == "graph_path" and (left.rule_id, right.rule_id) not in GRAPH_PATH_ALLOWLIST:
                    continue
                config = _resolve_prereq_config(relation, left.rule_id, right.rule_id)
                if is_prerequisite_satisfied(graph, left, right, relation, config):
                    edge_key = (left.match_id, right.match_id, relation)
                    if edge_key in seen_edges:
                        continue
                    weight: float | None = None
                    edge_path_factor: float | None = None
                    edge_dependency_strength: float | None = None
                    if relation == "graph_path" and config:
                        from_binding = config.get("from_binding")
                        to_binding = config.get("to_binding")
                        if from_binding and to_binding:
                            from_entity = left.bindings.get(from_binding)
                            to_entity = right.bindings.get(to_binding)
                            if from_entity and to_entity:
                                path_factor_reqs = path_factor_prerequisites(left_rule) + path_factor_prerequisites(right_rule)
                                if any(
                                    not is_path_factor_satisfied(
                                        graph,
                                        from_entity,
                                        to_entity,
                                        prereq.threshold,
                                        prereq.op,
                                    )
                                    for prereq in path_factor_reqs
                                ):
                                    continue
                                dependency = graph.dependency_strength(from_entity, to_entity)
                                edge_dependency_strength = dependency
                                edge_path_factor = graph.path_factor(from_entity, to_entity)
                                if paper_mode == "strict":
                                    weight = edge_path_factor
                                else:
                                    weight = dependency * edge_path_factor
                    seen_edges.add(edge_key)
                    edges.append(
                        HSGEdge(
                            src=left.match_id,
                            dst=right.match_id,
                            relation=relation,
                            weight=weight,
                            path_factor=edge_path_factor,
                            dependency_strength=edge_dependency_strength,
                        )
                    )

    return HSG(nodes=nodes, edges=edges)


def hsg_to_dict(hsg: HSG) -> dict:
    return {
        "nodes": [
            {
                "match_id": n.match_id,
                "rule_id": n.rule_id,
                "event_ids": n.event_ids,
                "entities": n.entities,
            }
            for n in hsg.nodes
        ],
        "edges": [
            (
                {
                    "src": e.src,
                    "dst": e.dst,
                    "relation": e.relation,
                    **({"weight": e.weight} if e.weight is not None else {}),
                    **({"path_factor": e.path_factor} if e.path_factor is not None else {}),
                    **({"dependency_strength": e.dependency_strength} if e.dependency_strength is not None else {}),
                }
            )
            for e in hsg.edges
        ],
    }


def dump_hsg_json(hsg: HSG, output_path: str | Path) -> None:
    p = Path(output_path)
    p.write_text(json.dumps(hsg_to_dict(hsg), indent=2), encoding="utf-8")
