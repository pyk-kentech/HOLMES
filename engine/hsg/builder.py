from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
import json
from pathlib import Path

from engine.core.graph import ProvenanceGraph
from engine.core.matcher import TTPMatch
from engine.hsg.prerequisite import is_path_factor_satisfied, is_prerequisite_satisfied
from engine.rules.schema import RuleSet, path_factor_prerequisites, prerequisite_types
import yaml

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
GRAPH_PATH_ALLOWLIST: set[tuple[str, str]] | None = None
SUPPORTED_PREREQ_POLICIES: set[str] = {"dst_only", "union"}


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


def _entity_prefix(entity: str | None) -> str:
    if not entity:
        return ""
    return entity.split(":", 1)[0].lower()


def _match_entities(match: TTPMatch) -> set[str]:
    entities = {e for e in match.entities if isinstance(e, str) and e}
    for value in match.bindings.values():
        if isinstance(value, str) and value:
            entities.add(value)
    return entities


def _prefix_overlap(left: TTPMatch, right: TTPMatch) -> bool:
    left_prefixes = {_entity_prefix(e) for e in _match_entities(left) if _entity_prefix(e)}
    right_prefixes = {_entity_prefix(e) for e in _match_entities(right) if _entity_prefix(e)}
    return bool(left_prefixes & right_prefixes)


def _reachable_quick_check(
    graph: ProvenanceGraph,
    left: TTPMatch,
    right: TTPMatch,
    descendants_cache: dict[str, set[str]],
) -> bool:
    for src in _match_entities(left):
        if not src:
            continue
        if src not in descendants_cache:
            descendants_cache[src] = graph.descendants(src)
        reachable = descendants_cache[src]
        for dst in _match_entities(right):
            if dst in reachable:
                return True
    return False


def is_graph_path_candidate(
    graph: ProvenanceGraph,
    left: TTPMatch,
    right: TTPMatch,
    descendants_cache: dict[str, set[str]] | None = None,
) -> bool:
    """
    Cheap pruning before expensive graph_path prerequisite evaluation.

    Keep candidate when either:
    - entity prefix overlap exists, or
    - directed reachability exists from left entities to right entities.
    """
    cache = descendants_cache if descendants_cache is not None else {}
    return _prefix_overlap(left, right) or _reachable_quick_check(graph, left, right, cache)


def load_graph_path_allowlist(path: str | Path | None) -> set[tuple[str, str]] | None:
    if path is None:
        return None
    raw = str(path).strip()
    if not raw or raw.lower() == "none":
        return None

    payload = yaml.safe_load(Path(raw).read_text(encoding="utf-8"))
    if payload is None:
        return set()
    if isinstance(payload, dict):
        payload = payload.get("allowlist", payload.get("pairs", payload))
    if not isinstance(payload, list):
        raise ValueError("graph-path allowlist file must contain a list")

    pairs: set[tuple[str, str]] = set()
    for item in payload:
        left = None
        right = None
        if isinstance(item, str):
            if "->" in item:
                left, right = item.split("->", 1)
            elif "," in item:
                left, right = item.split(",", 1)
        elif isinstance(item, list) and len(item) == 2:
            left, right = item[0], item[1]
        elif isinstance(item, dict):
            left = item.get("src") or item.get("left") or item.get("from")
            right = item.get("dst") or item.get("right") or item.get("to")
        if isinstance(left, str) and isinstance(right, str):
            pairs.add((left.strip(), right.strip()))
    return pairs


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


def prerequisite_relations_for_pair(
    left_rule,
    right_rule,
    prereq_policy: str,
) -> set[str]:
    if prereq_policy == "dst_only":
        return prerequisite_types(right_rule)
    if prereq_policy == "union":
        return prerequisite_types(left_rule) | prerequisite_types(right_rule)
    raise ValueError(f"Unsupported prereq_policy: {prereq_policy}")


def path_factor_prerequisites_for_pair(
    left_rule,
    right_rule,
    prereq_policy: str,
):
    if prereq_policy == "dst_only":
        return path_factor_prerequisites(right_rule)
    if prereq_policy == "union":
        return path_factor_prerequisites(left_rule) + path_factor_prerequisites(right_rule)
    raise ValueError(f"Unsupported prereq_policy: {prereq_policy}")


def build_hsg(
    matches: list[TTPMatch],
    graph: ProvenanceGraph,
    ruleset: RuleSet,
    paper_mode: str = "hybrid",
    prereq_policy: str = "union",
    graph_path_allowlist: set[tuple[str, str]] | None = None,
    max_graph_path_edges: int = 10000,
    max_graph_path_candidates_per_match: int = 200,
) -> HSG:
    if paper_mode not in {"hybrid", "strict"}:
        raise ValueError("paper_mode must be 'hybrid' or 'strict'")
    if prereq_policy not in SUPPORTED_PREREQ_POLICIES:
        raise ValueError("prereq_policy must be 'dst_only' or 'union'")
    if max_graph_path_edges < 0:
        raise ValueError("max_graph_path_edges must be >= 0")
    if max_graph_path_candidates_per_match < 0:
        raise ValueError("max_graph_path_candidates_per_match must be >= 0")

    rule_by_id = {rule.rule_id: rule for rule in ruleset.rules}
    allowlist = graph_path_allowlist if graph_path_allowlist is not None else GRAPH_PATH_ALLOWLIST

    nodes = [
        HSGNode(
            match_id=m.match_id,
            rule_id=m.rule_id,
            event_ids=list(m.event_ids),
            entities=list(m.entities),
        )
        for m in matches
    ]
    active_nodes: set[str] = set()
    for m in matches:
        rule = rule_by_id.get(m.rule_id)
        if rule is None or not getattr(rule, "prerequisites", []):
            active_nodes.add(m.match_id)

    edges: list[HSGEdge] = []
    seen_edges: set[tuple[str, str, str]] = set()
    descendants_cache: dict[str, set[str]] = {}
    graph_path_edges_count = 0
    graph_path_candidates_by_src: dict[str, int] = defaultdict(int)
    for i in range(len(matches)):
        for j in range(i + 1, len(matches)):
            left = matches[i]
            right = matches[j]
            left_rule = rule_by_id.get(left.rule_id)
            right_rule = rule_by_id.get(right.rule_id)
            prereq_types = prerequisite_relations_for_pair(left_rule, right_rule, prereq_policy)

            for relation in prereq_types:
                if relation == "graph_path":
                    if allowlist is not None and (left.rule_id, right.rule_id) not in allowlist:
                        continue
                    if graph_path_candidates_by_src[left.match_id] >= max_graph_path_candidates_per_match:
                        continue
                    if graph_path_edges_count >= max_graph_path_edges:
                        continue
                    if not is_graph_path_candidate(graph, left, right, descendants_cache):
                        continue
                    graph_path_candidates_by_src[left.match_id] += 1
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
                                path_factor_reqs = path_factor_prerequisites_for_pair(left_rule, right_rule, prereq_policy)
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
                    if relation == "graph_path":
                        graph_path_edges_count += 1
                    # Promote both endpoints once an inter-match prerequisite edge is satisfied.
                    active_nodes.add(left.match_id)
                    active_nodes.add(right.match_id)

    gated_nodes = [n for n in nodes if n.match_id in active_nodes]
    gated_edges = [e for e in edges if e.src in active_nodes and e.dst in active_nodes]
    return HSG(nodes=gated_nodes, edges=gated_edges)


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
