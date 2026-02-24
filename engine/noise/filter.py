from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from engine.core.graph import path_factor_passes
from engine.core.matcher import TTPMatch
from engine.hsg.builder import HSG, HSGEdge, HSGNode


@dataclass(slots=True)
class NoiseConfig:
    drop_rule_ids: set[str] = field(default_factory=set)
    drop_match_ids: set[str] = field(default_factory=set)
    drop_prerequisite_types: set[str] = field(default_factory=set)
    min_graph_path_weight: float = 0.0
    min_path_factor: float = 0.0
    path_factor_op: str = "ge"


def load_noise_config(path: str | Path) -> NoiseConfig:
    p = Path(path)
    if not p.exists():
        return NoiseConfig()

    text = p.read_text(encoding="utf-8")
    if not text.strip():
        return NoiseConfig()

    payload = yaml.safe_load(text)
    if payload is None:
        return NoiseConfig()
    if not isinstance(payload, dict):
        raise ValueError("noise config root must be a mapping")

    drop = payload.get("drop", payload)
    if not isinstance(drop, dict):
        raise ValueError("noise config 'drop' must be a mapping")

    rule_ids = (
        drop.get("drop_rule_ids")
        or drop.get("rule_ids")
        or drop.get("rule_id")
        or []
    )
    prerequisite_types = (
        drop.get("drop_prerequisite_types")
        or drop.get("prerequisite_types")
        or drop.get("prerequisite_type")
        or []
    )
    min_graph_path_weight = payload.get("min_graph_path_weight", drop.get("min_graph_path_weight", 0.0))
    min_path_factor = payload.get("min_path_factor", drop.get("min_path_factor", 0.0))
    path_factor_op = str(payload.get("path_factor_op", drop.get("path_factor_op", "ge"))).lower()
    if not isinstance(rule_ids, list) or any(not isinstance(x, str) for x in rule_ids):
        raise ValueError("noise.rule_id must be list[str]")
    if not isinstance(prerequisite_types, list) or any(not isinstance(x, str) for x in prerequisite_types):
        raise ValueError("noise.prerequisite_type must be list[str]")
    if not isinstance(min_graph_path_weight, (int, float)):
        raise ValueError("noise.min_graph_path_weight must be a number")
    if not isinstance(min_path_factor, (int, float)):
        raise ValueError("noise.min_path_factor must be a number")
    if path_factor_op not in {"ge", "le"}:
        raise ValueError("noise.path_factor_op must be 'ge' or 'le'")

    return NoiseConfig(
        drop_rule_ids=set(rule_ids),
        drop_prerequisite_types=set(prerequisite_types),
        min_graph_path_weight=float(min_graph_path_weight),
        min_path_factor=float(min_path_factor),
        path_factor_op=str(path_factor_op),
    )


def filter_matches(matches: list[TTPMatch], config: NoiseConfig) -> list[TTPMatch]:
    if not config.drop_rule_ids and not config.drop_match_ids:
        return list(matches)
    return [m for m in matches if m.rule_id not in config.drop_rule_ids and m.match_id not in config.drop_match_ids]


def filter_hsg(hsg: HSG, config: NoiseConfig) -> HSG:
    edges = [
        e
        for e in hsg.edges
        if e.relation not in config.drop_prerequisite_types
        and (
            e.relation != "graph_path"
            or (
                float(e.weight or 0.0) >= config.min_graph_path_weight
                and path_factor_passes(e.path_factor, config.min_path_factor, config.path_factor_op)
            )
        )
    ]
    return HSG(nodes=list(hsg.nodes), edges=edges)


def apply_noise_filter(
    matches_before: list[TTPMatch],
    hsg_before: HSG,
    config: NoiseConfig,
) -> tuple[list[TTPMatch], HSG]:
    matches_after = filter_matches(matches_before, config)
    keep_ids = {m.match_id for m in matches_after}

    nodes_after: list[HSGNode] = [n for n in hsg_before.nodes if n.match_id in keep_ids]
    edges_subset: list[HSGEdge] = [
        e
        for e in hsg_before.edges
        if e.src in keep_ids
        and e.dst in keep_ids
    ]
    hsg_after = filter_hsg(HSG(nodes=nodes_after, edges=edges_subset), config)
    return matches_after, hsg_after


def build_noise_counts(before_matches: int, before_nodes: int, before_edges: int, after_matches: int, after_nodes: int, after_edges: int) -> dict:
    return {
        "before": {"matches": before_matches, "hsg_nodes": before_nodes, "hsg_edges": before_edges},
        "after": {"matches": after_matches, "hsg_nodes": after_nodes, "hsg_edges": after_edges},
        "dropped": {
            "matches": before_matches - after_matches,
            "hsg_nodes": before_nodes - after_nodes,
            "hsg_edges": before_edges - after_edges,
        },
    }
