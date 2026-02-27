from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field

from engine.core.graph import EdgeType


@dataclass(slots=True)
class NodeMapper:
    match_ids: set[str] = field(default_factory=set)
    match_ids_by_rule: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    earliest_seq_by_rule: dict[str, int] = field(default_factory=dict)
    # match_id -> origin_node_id -> min data-flow hops
    hops_by_match_origin: dict[str, dict[str, int]] = field(default_factory=lambda: defaultdict(dict))


class OnlineIndex:
    """
    Incremental mapper/index for online prerequisite checks.

    - edge propagate: src mapper -> dst mapper (DATA_FLOW and VERSION_TRANSITION)
    - O(1) checks: required_ttp in node mapper, earliest sequence lookup
    - O(k) retrieval: candidate upstream match ids from mapper buckets
    """

    def __init__(self) -> None:
        self._node_mapper: dict[str, NodeMapper] = {}
        # Explicit adjacency cache for propagation engine.
        self.out_edges: dict[str, list[tuple[str, EdgeType | str]]] = defaultdict(list)
        self._out_edge_set: dict[str, set[tuple[str, EdgeType | str]]] = defaultdict(set)
        self._local_matches: dict[str, set[str]] = defaultdict(set)
        self._local_matches_by_rule: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))

    def _mapper(self, node_id: str) -> NodeMapper:
        mapper = self._node_mapper.get(node_id)
        if mapper is None:
            mapper = NodeMapper()
            self._node_mapper[node_id] = mapper
        return mapper

    def _merge_match_from_src(
        self,
        dst: NodeMapper,
        src: NodeMapper,
        match_id: str,
        edge_cost: int,
    ) -> bool:
        changed = False
        if match_id not in src.match_ids:
            return False

        if match_id not in dst.match_ids:
            dst.match_ids.add(match_id)
            changed = True

        for rule_id, src_ids in src.match_ids_by_rule.items():
            if match_id not in src_ids:
                continue
            dst_ids = dst.match_ids_by_rule[rule_id]
            if match_id not in dst_ids:
                dst_ids.add(match_id)
                changed = True
            src_earliest = src.earliest_seq_by_rule.get(rule_id)
            if src_earliest is None:
                continue
            prev = dst.earliest_seq_by_rule.get(rule_id)
            if prev is None or src_earliest < prev:
                dst.earliest_seq_by_rule[rule_id] = src_earliest
                changed = True

        src_origins = src.hops_by_match_origin.get(match_id, {})
        if src_origins:
            dst_origins = dst.hops_by_match_origin[match_id]
            for origin_node_id, src_hops in src_origins.items():
                cand = int(src_hops) + int(edge_cost)
                prev = dst_origins.get(origin_node_id)
                if prev is None or cand < prev:
                    dst_origins[origin_node_id] = cand
                    changed = True
        return changed

    def _propagate_delta(self, start_node_id: str, delta_match_ids: set[str]) -> None:
        if not delta_match_ids:
            return
        q: deque[tuple[str, set[str]]] = deque([(start_node_id, set(delta_match_ids))])
        while q:
            src_node_id, delta = q.popleft()
            src_mapper = self._mapper(src_node_id)
            for dst_node_id, edge_type in self.out_edges.get(src_node_id, []):
                if edge_type == EdgeType.DATA_FLOW:
                    edge_cost = 1
                elif edge_type == EdgeType.VERSION_TRANSITION:
                    edge_cost = 0
                else:
                    continue
                dst_mapper = self._mapper(dst_node_id)
                changed_for_dst: set[str] = set()
                for match_id in delta:
                    if self._merge_match_from_src(dst_mapper, src_mapper, match_id, edge_cost=edge_cost):
                        changed_for_dst.add(match_id)
                if changed_for_dst:
                    q.append((dst_node_id, changed_for_dst))

    def on_edge_added(self, src_node_id: str, dst_node_id: str, edge_type: EdgeType | str) -> None:
        if isinstance(edge_type, EdgeType):
            et = edge_type
        else:
            raw = str(edge_type).strip().lower()
            if raw in {EdgeType.DATA_FLOW.value, "data_flow"}:
                et = EdgeType.DATA_FLOW
            elif raw in {EdgeType.VERSION_TRANSITION.value, "version_transition", "prev_version"}:
                et = EdgeType.VERSION_TRANSITION
            else:
                et = raw
        edge_tuple = (dst_node_id, et)
        if edge_tuple not in self._out_edge_set[src_node_id]:
            self._out_edge_set[src_node_id].add(edge_tuple)
            self.out_edges[src_node_id].append(edge_tuple)

        # Trigger #1: edge add must immediately merge/propagate existing mapper of src.
        src_mapper = self._mapper(src_node_id)
        self._propagate_delta(src_node_id, set(src_mapper.match_ids))

    def on_match_added(
        self,
        node_id: str,
        ttp_id: str,
        sequence: int,
        rule_id: str | None = None,
        origin_node_id: str | None = None,
    ) -> None:
        effective_rule_id = rule_id if rule_id is not None else ttp_id
        self._local_matches[node_id].add(ttp_id)
        self._local_matches_by_rule[node_id][effective_rule_id].add(ttp_id)

        mapper = self._mapper(node_id)
        changed = False
        if ttp_id not in mapper.match_ids:
            mapper.match_ids.add(ttp_id)
            mapper.match_ids_by_rule[effective_rule_id].add(ttp_id)
            changed = True
        origin = origin_node_id if origin_node_id is not None else node_id
        prev_hops = mapper.hops_by_match_origin[ttp_id].get(origin)
        if prev_hops is None or 0 < prev_hops:
            mapper.hops_by_match_origin[ttp_id][origin] = 0
            changed = True
        prev = mapper.earliest_seq_by_rule.get(effective_rule_id)
        if prev is None or sequence < prev:
            mapper.earliest_seq_by_rule[effective_rule_id] = sequence
            changed = True

        # Trigger #2: match add must immediately propagate mapper delta along existing edges.
        if changed:
            self._propagate_delta(node_id, {ttp_id})

    # Backward-compat wrappers
    def on_edge(self, src_node_id: str, dst_node_id: str, edge_cost: int) -> None:
        edge_type = EdgeType.DATA_FLOW if int(edge_cost) > 0 else EdgeType.VERSION_TRANSITION
        self.on_edge_added(src_node_id, dst_node_id, edge_type=edge_type)

    def register_local_match(
        self,
        node_id: str,
        match_id: str,
        rule_id: str,
        sequence: int,
        origin_node_id: str | None = None,
    ) -> None:
        self.on_match_added(
            node_id=node_id,
            ttp_id=match_id,
            rule_id=rule_id,
            sequence=sequence,
            origin_node_id=origin_node_id,
        )

    def mapper_contains_rule(self, node_id: str, rule_id: str) -> bool:
        mapper = self._node_mapper.get(node_id)
        if mapper is None:
            return False
        return bool(mapper.match_ids_by_rule.get(rule_id))

    def mapper_match_ids(self, node_id: str, rule_ids: set[str] | None = None) -> set[str]:
        mapper = self._node_mapper.get(node_id)
        if mapper is None:
            return set()
        if not rule_ids:
            return set(mapper.match_ids)
        out: set[str] = set()
        for rid in rule_ids:
            out |= mapper.match_ids_by_rule.get(rid, set())
        return out

    def mapper_contains_match(self, node_id: str, match_id: str, origin_node_id: str | None = None) -> bool:
        mapper = self._node_mapper.get(node_id)
        if mapper is None:
            return False
        if match_id not in mapper.match_ids:
            return False
        if origin_node_id is None:
            return True
        return origin_node_id in mapper.hops_by_match_origin.get(match_id, {})

    def mapper_min_hops(self, node_id: str, match_id: str, origin_node_id: str | None = None) -> int | None:
        mapper = self._node_mapper.get(node_id)
        if mapper is None:
            return None
        by_origin = mapper.hops_by_match_origin.get(match_id)
        if not by_origin:
            return None
        if origin_node_id is not None:
            return by_origin.get(origin_node_id)
        return min(by_origin.values())

    def mapper_earliest_seq(self, node_id: str, rule_id: str) -> int | None:
        mapper = self._node_mapper.get(node_id)
        if mapper is None:
            return None
        return mapper.earliest_seq_by_rule.get(rule_id)

    def local_match_ids(self, node_id: str, rule_ids: set[str] | None = None) -> set[str]:
        if not rule_ids:
            return set(self._local_matches.get(node_id, set()))
        out: set[str] = set()
        by_rule = self._local_matches_by_rule.get(node_id, {})
        for rid in rule_ids:
            out |= by_rule.get(rid, set())
        return out
