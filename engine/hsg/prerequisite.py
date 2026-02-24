from __future__ import annotations

from engine.core.graph import ProvenanceGraph, path_factor_passes
from engine.core.matcher import TTPMatch


def is_path_factor_satisfied(
    graph: ProvenanceGraph,
    src_entity: str,
    dst_entity: str,
    threshold: float,
    op: str = ">=",
) -> bool:
    pf = graph.path_factor(src_entity, dst_entity)
    if pf is None:
        return False
    if op == ">=":
        return path_factor_passes(pf, threshold, "ge")
    if op == "<=":
        return path_factor_passes(pf, threshold, "le")
    if op == ">":
        return pf > threshold
    if op == "<":
        return pf < threshold
    raise ValueError(f"Unsupported path_factor op: {op}")


def is_prerequisite_satisfied(
    graph: ProvenanceGraph,
    left: TTPMatch,
    right: TTPMatch,
    prerequisite_type: str,
    prerequisite_config: dict[str, str] | None = None,
) -> bool:
    """Evaluate one prerequisite relation between two matches."""
    if prerequisite_type == "shared_entity":
        for key in set(left.bindings) & set(right.bindings):
            if left.bindings[key] == right.bindings[key]:
                return True
        return False

    if prerequisite_type == "graph_path":
        if prerequisite_config is None:
            raise ValueError("graph_path requires prerequisite_config with from_binding/to_binding")

        from_binding = prerequisite_config.get("from_binding")
        to_binding = prerequisite_config.get("to_binding")
        if not from_binding or not to_binding:
            raise ValueError("graph_path requires from_binding and to_binding")

        from_entity = left.bindings.get(from_binding)
        to_entity = right.bindings.get(to_binding)
        if not from_entity or not to_entity:
            return False

        strength = graph.dependency_strength(from_entity, to_entity)
        if strength <= 0.0:
            return False
        min_strength = float(prerequisite_config.get("min_strength", 0.0))
        return strength >= min_strength

    raise ValueError(f"Unsupported prerequisite_type: {prerequisite_type}")
