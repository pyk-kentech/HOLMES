from __future__ import annotations

from collections import defaultdict, deque

from engine.hsg.builder import HSG
from engine.rules.schema import APT_STAGES


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


def _to_cvss_severity(value: float | str | None) -> float:
    if value is None:
        return 0.0
    if isinstance(value, str):
        mapping = {
            "low": 2.0,
            "medium": 6.0,
            "high": 8.0,
            "critical": 10.0,
        }
        return float(mapping.get(value.lower(), 0.0))
    return float(value)


def _build_threat_tuple(
    node_ids: set[str],
    rule_id_by_match: dict[str, str],
    rule_cvss: dict[str, float | str] | None,
    rule_stage: dict[str, int] | None,
    rule_severity: dict[str, float | str] | None = None,
) -> list[float]:
    cvss_by_rule = rule_cvss or {}
    sev_by_rule = rule_severity or {}
    stages = rule_stage or {}

    t = [0.0] * len(APT_STAGES)
    for mid in node_ids:
        rule_id = rule_id_by_match[mid]
        stage = int(stages.get(rule_id, 1))
        idx = max(1, min(stage, len(APT_STAGES))) - 1
        raw_score = cvss_by_rule.get(rule_id)
        if raw_score is None:
            raw_score = sev_by_rule.get(rule_id, 1.0)
        score = _to_cvss_severity(raw_score)
        if score > t[idx]:
            t[idx] = score
    return t


def _paper_score_from_tuple(threat_tuple: list[float], paper_weights: list[float] | None) -> float:
    weights = list(paper_weights) if paper_weights is not None else [1.0] * len(APT_STAGES)
    if len(weights) != len(APT_STAGES):
        raise ValueError("paper_weights must contain exactly 7 floats")

    score = 1.0
    for s_i, w_i in zip(threat_tuple, weights):
        x = max(0.0, min(10.0, float(s_i)))
        base = 1.0 + (x / 10.0)
        score *= base**float(w_i)
    return float(score)


def rank_hsg_scenarios(
    hsg: HSG,
    scoring: str = "weighted",
    rule_severity: dict[str, float] | None = None,
    alpha: float = 1.0,
    top_k: int = 3,
    score_mode: str = "legacy",
    rule_stage: dict[str, int] | None = None,
    rule_cvss: dict[str, float | str] | None = None,
    paper_weights: list[float] | None = None,
) -> list[dict[str, float | int | list[float]]]:
    """
    Build scenario scores from HSG connected components and return top-ranked ones.

    scoring:
      - structure: nodes_count + 0.5 * edges_count
      - severity: sum of node rule severities
      - weighted: sum(rule severities in component) + alpha * sum(edge.weight in component)
    """
    if score_mode not in {"legacy", "paper"}:
        raise ValueError("score_mode must be 'legacy' or 'paper'")

    components = _connected_components(hsg)
    rule_id_by_match = {n.match_id: n.rule_id for n in hsg.nodes}

    scenarios: list[dict[str, float | int | list[float]]] = []
    for comp in components:
        component_edges = [e for e in hsg.edges if e.src in comp and e.dst in comp]
        edge_count = len(component_edges)
        edge_score = sum(float(e.weight) for e in component_edges if e.weight is not None)
        score_legacy = _score_component(comp, edge_count, edge_score, rule_id_by_match, scoring, rule_severity, alpha)
        threat_tuple = _build_threat_tuple(comp, rule_id_by_match, rule_cvss, rule_stage, rule_severity)
        score_paper = _paper_score_from_tuple(threat_tuple, paper_weights)
        score = score_paper if score_mode == "paper" else score_legacy
        scenarios.append(
            {
                "score": float(score),
                "score_legacy": float(score_legacy),
                "score_paper": float(score_paper),
                "threat_tuple": threat_tuple,
                "nodes": len(comp),
                "edges": edge_count,
            }
        )

    scenarios.sort(key=lambda x: (float(x["score"]), int(x["nodes"]), int(x["edges"])), reverse=True)
    scenarios = scenarios[:top_k]
    while len(scenarios) < top_k:
        score_legacy = 0.0
        score_paper = 1.0
        score = score_paper if score_mode == "paper" else score_legacy
        scenarios.append(
            {
                "score": score,
                "score_legacy": score_legacy,
                "score_paper": score_paper,
                "threat_tuple": [0.0] * len(APT_STAGES),
                "nodes": 0,
                "edges": 0,
            }
        )
    return scenarios
