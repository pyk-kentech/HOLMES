from __future__ import annotations

from collections import defaultdict, deque

from engine.hsg.builder import HSG


def _connected_components(hsg: HSG) -> list[set[str]]:
    node_ids = {n.match_id for n in hsg.nodes}
    if not node_ids:
        return []

    adj: dict[str, set[str]] = defaultdict(set)
    for edge in hsg.edges:
        adj[edge.src].add(edge.dst)
        adj[edge.dst].add(edge.src)

    seen: set[str] = set()
    components: list[set[str]] = []
    for root in node_ids:
        if root in seen:
            continue
        queue: deque[str] = deque([root])
        comp: set[str] = set()
        seen.add(root)
        while queue:
            cur = queue.popleft()
            comp.add(cur)
            for nxt in adj.get(cur, set()):
                if nxt in seen:
                    continue
                seen.add(nxt)
                queue.append(nxt)
        components.append(comp)
    return components


def _score_component(
    node_ids: set[str],
    edge_count: int,
    edge_score: float,
    rule_id_by_match: dict[str, str],
    scoring: str,
    rule_severity: dict[str, float] | None,
    alpha: float,
) -> float:
    sev = rule_severity or {}
    if scoring == "structure":
        return float(len(node_ids)) + 0.5 * float(edge_count)
    if scoring == "severity":
        return float(sum(sev.get(rule_id_by_match[mid], 1.0) for mid in node_ids))
    if scoring == "weighted":
        node_score = float(sum(sev.get(rule_id_by_match[mid], 1.0) for mid in node_ids))
        return node_score + float(alpha) * float(edge_score)
    raise ValueError(f"Unsupported scoring mode: {scoring}")


def rank_hsg_scenarios(
    hsg: HSG,
    scoring: str = "weighted",
    rule_severity: dict[str, float] | None = None,
    alpha: float = 1.0,
    top_k: int = 3,
) -> list[dict[str, float | int]]:
    """
    Build scenario scores from HSG connected components and return top-ranked ones.

    scoring:
      - structure: nodes_count + 0.5 * edges_count
      - severity: sum of node rule severities
      - weighted: sum(rule severities in component) + alpha * sum(edge.weight in component)
    """
    components = _connected_components(hsg)
    rule_id_by_match = {n.match_id: n.rule_id for n in hsg.nodes}

    scenarios: list[dict[str, float | int]] = []
    for comp in components:
        component_edges = [e for e in hsg.edges if e.src in comp and e.dst in comp]
        edge_count = len(component_edges)
        edge_score = sum(float(e.weight) for e in component_edges if e.weight is not None)
        score = _score_component(comp, edge_count, edge_score, rule_id_by_match, scoring, rule_severity, alpha)
        scenarios.append({"score": score, "nodes": len(comp), "edges": edge_count})

    scenarios.sort(key=lambda x: (float(x["score"]), int(x["nodes"]), int(x["edges"])), reverse=True)
    scenarios = scenarios[:top_k]
    while len(scenarios) < top_k:
        scenarios.append({"score": 0.0, "nodes": 0, "edges": 0})
    return scenarios
