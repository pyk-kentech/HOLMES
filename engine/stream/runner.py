from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

from engine.core.graph import Edge, ProvenanceGraph
from engine.core.matcher import Matcher, TTPMatch
import engine.hsg.builder as hsg_builder
from engine.hsg.builder import HSG, HSGEdge, HSGNode, hsg_to_dict
from engine.hsg.online_index import OnlineIndex
from engine.hsg.paper_exact import IncrementalPaperExactScorer
from engine.hsg.scorer import rank_hsg_scenarios
from engine.io.events import Event
from engine.noise.filter import NoiseConfig, apply_noise_filter
from engine.noise.model import NoiseModel, get_benign_drop_ids
from engine.rules.schema import APT_STAGES, RuleSet, infer_rule_cvss, infer_rule_stage


@dataclass(slots=True)
class StreamingStats:
    events: int = 0
    raw_matches: int = 0
    dropped_matches: int = 0
    by_signature: int = 0
    by_byte_volume: int = 0
    byte_volume_by_rule_id: dict[str, int] | None = None
    candidate_pairs_considered: int = 0


class StreamingEngine:
    def __init__(
        self,
        ruleset: RuleSet,
        scoring_mode: str = "legacy",
        paper_weights: list[float] | None = None,
        tau: float | None = None,
        paper_mode: str = "hybrid",
        prereq_policy: str = "union",
        alpha: float | None = None,
        noise_model: NoiseModel | None = None,
        noise_bytes_threshold: str = "p95",
        noise_signature_min_ratio: float = 0.1,
        graph_path_allowlist: set[tuple[str, str]] | None = None,
        max_graph_path_edges: int = 10000,
        max_graph_path_candidates_per_match: int = 200,
        use_online_prereq: bool = True,
        resolved_effective_config: dict[str, Any] | None = None,
        global_refine_mode: str = "off",
        global_refine_every: int = 1000,
    ) -> None:
        self.ruleset = ruleset
        self.scoring_mode = scoring_mode
        self.paper_weights = list(paper_weights) if paper_weights is not None else [1.0] * 7
        self.tau = float(tau) if tau is not None else None
        self.paper_mode = paper_mode
        if prereq_policy not in hsg_builder.SUPPORTED_PREREQ_POLICIES:
            raise ValueError("prereq_policy must be 'dst_only' or 'union'")
        self.prereq_policy = prereq_policy
        self.noise_model = noise_model
        self.noise_bytes_threshold = noise_bytes_threshold
        self.noise_signature_min_ratio = max(0.0, min(1.0, float(noise_signature_min_ratio)))
        self.graph_path_allowlist = graph_path_allowlist
        self.max_graph_path_edges = max_graph_path_edges
        self.max_graph_path_candidates_per_match = max_graph_path_candidates_per_match
        self.use_online_prereq = bool(use_online_prereq)
        if global_refine_mode not in {"off", "snapshot", "every_n_events"}:
            raise ValueError("global_refine_mode must be one of: off, snapshot, every_n_events")
        self.global_refine_mode = global_refine_mode
        self.global_refine_every = max(1, int(global_refine_every))
        self.global_refine_ran_at_snapshots_count = 0
        self.global_refine_ran_at_events_count = 0
        self._events_processed = 0
        if resolved_effective_config is None:
            is_paper_like = scoring_mode in {"paper", "paper_exact"}
            default_path_thres = 3.0 if is_paper_like else 0.0
            default_path_factor_op = "le" if is_paper_like else "ge"
            self.resolved_effective_config = {
                "path_thres": default_path_thres,
                "path_factor_op": default_path_factor_op,
                "scoring": scoring_mode,
                "paper_mode": paper_mode,
                "paper_weights": list(self.paper_weights),
            }
            if self.tau is not None:
                self.resolved_effective_config["tau"] = self.tau
        else:
            self.resolved_effective_config = dict(resolved_effective_config)

        self.graph = ProvenanceGraph()
        self.online_index = OnlineIndex()
        self.graph.register_edge_hook(self._on_graph_edge)
        self.matcher = Matcher()
        self.rule_by_id = {r.rule_id: r for r in ruleset.rules}
        self.rule_order = {r.rule_id: i for i, r in enumerate(ruleset.rules)}
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
        self._graph_path_edges_count = 0
        self._graph_path_candidates_by_src: dict[str, int] = defaultdict(int)
        self._descendants_cache: dict[str, set[str]] = {}

        # Legacy indexes kept for output shaping.
        self.node_to_matches: dict[str, set[str]] = defaultdict(set)
        self.match_to_entities: dict[str, set[str]] = {}

        self._match_serial = 1
        self.stats = StreamingStats(byte_volume_by_rule_id={})
        self.top_scenarios: list[dict[str, Any]] = []
        self._noise_before_override: dict[str, int] | None = None
        self.paper_exact = (
            IncrementalPaperExactScorer(weights=self.paper_weights, tau=self.tau)
            if self.scoring_mode == "paper_exact"
            else None
        )

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
            subject_node_id=m.subject_node_id,
            object_node_id=m.object_node_id,
            sequence=m.sequence,
            attributes=dict(m.attributes),
        )

    def _on_graph_edge(self, edge: Edge) -> None:
        self.online_index.on_edge_added(edge.src, edge.dst, edge.edge_type)

    @staticmethod
    def _shared_node_id(left: TTPMatch, right: TTPMatch) -> str | None:
        left_nodes = {left.subject_node_id, left.object_node_id}
        right_nodes = {right.subject_node_id, right.object_node_id}
        common = {x for x in (left_nodes & right_nodes) if x}
        if not common:
            return None
        return sorted(common)[0]

    @staticmethod
    def _node_for_binding(match: TTPMatch, binding: str | None) -> str | None:
        if binding == "subject":
            return match.subject_node_id
        if binding == "object":
            return match.object_node_id
        return None

    def _edge_for_pair_online(self, left: TTPMatch, right: TTPMatch) -> list[HSGEdge]:
        left_rule = self.rule_by_id.get(left.rule_id)
        right_rule = self.rule_by_id.get(right.rule_id)
        prereq_types = hsg_builder.prerequisite_relations_for_pair(left_rule, right_rule, self.prereq_policy)

        built: list[HSGEdge] = []
        for relation in prereq_types:
            if relation not in {"graph_path", "shared_entity"}:
                continue
            edge_key = (left.match_id, right.match_id, relation)
            if edge_key in self.seen_edges:
                continue

            weight: float | None = None
            edge_path_factor: float | None = None
            edge_dependency_strength: float | None = None
            if relation == "graph_path":
                if self._graph_path_edges_count >= self.max_graph_path_edges:
                    continue
                allowlist = self.graph_path_allowlist if self.graph_path_allowlist is not None else hsg_builder.GRAPH_PATH_ALLOWLIST
                if allowlist is not None and (left.rule_id, right.rule_id) not in allowlist:
                    continue
                cfg = hsg_builder._resolve_prereq_config(relation, left.rule_id, right.rule_id)  # noqa: SLF001
                if not cfg:
                    continue
                from_binding = cfg.get("from_binding")
                to_binding = cfg.get("to_binding")
                from_node = self._node_for_binding(left, from_binding)
                to_node = self._node_for_binding(right, to_binding)
                if not from_node or not to_node:
                    continue
                if not self.online_index.mapper_contains_match(to_node, left.match_id, origin_node_id=from_node):
                    continue
                hops = self.online_index.mapper_min_hops(to_node, left.match_id, origin_node_id=from_node)
                if hops is None:
                    continue
                dependency = 1.0 / (1.0 + float(hops))
                edge_dependency_strength = dependency
                edge_pf = 1.0
                edge_path_factor = float(edge_pf)
                if self.paper_mode == "strict":
                    weight = edge_path_factor
                else:
                    weight = dependency * edge_path_factor
            elif relation == "shared_entity":
                shared = self._shared_node_id(left, right)
                if not shared:
                    continue

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
            if relation == "graph_path":
                self._graph_path_edges_count += 1
        return built

    def _edge_for_pair_legacy(self, left: TTPMatch, right: TTPMatch) -> list[HSGEdge]:
        left_rule = self.rule_by_id.get(left.rule_id)
        right_rule = self.rule_by_id.get(right.rule_id)
        prereq_types = hsg_builder.prerequisite_relations_for_pair(left_rule, right_rule, self.prereq_policy)

        built: list[HSGEdge] = []
        for relation in prereq_types:
            if relation == "graph_path":
                allowlist = self.graph_path_allowlist if self.graph_path_allowlist is not None else hsg_builder.GRAPH_PATH_ALLOWLIST
                if allowlist is not None and (left.rule_id, right.rule_id) not in allowlist:
                    continue
                if self._graph_path_candidates_by_src[left.match_id] >= self.max_graph_path_candidates_per_match:
                    continue
                if self._graph_path_edges_count >= self.max_graph_path_edges:
                    continue
                if not hsg_builder.is_graph_path_candidate(self.graph, left, right, self._descendants_cache):
                    continue
                self._graph_path_candidates_by_src[left.match_id] += 1

            edge_key = (left.match_id, right.match_id, relation)
            if edge_key in self.seen_edges:
                continue

            config = hsg_builder._resolve_prereq_config(relation, left.rule_id, right.rule_id)  # noqa: SLF001
            if not hsg_builder.is_prerequisite_satisfied(self.graph, left, right, relation, config):
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
                        pf_reqs = hsg_builder.path_factor_prerequisites_for_pair(left_rule, right_rule, self.prereq_policy)
                        if pf_reqs and any(
                            not hsg_builder.is_path_factor_satisfied(
                                self.graph,
                                from_entity,
                                to_entity,
                                prereq.threshold,
                                prereq.op,
                            )
                            for prereq in pf_reqs
                        ):
                            continue
                        dependency = self.graph.dependency_strength(from_entity, to_entity)
                        edge_dependency_strength = dependency
                        edge_pf = self.graph.path_factor_for_edge(from_entity, to_entity)
                        if edge_pf is None:
                            continue
                        edge_path_factor = float(edge_pf)
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
            if relation == "graph_path":
                self._graph_path_edges_count += 1
        return built

    def _required_ttp_ids(self, rule_id: str) -> set[str]:
        rule = self.rule_by_id.get(rule_id)
        if rule is None:
            return set()
        raw = getattr(rule, "required_ttp_ids", None)
        if isinstance(raw, list):
            return {x for x in raw if isinstance(x, str)}
        return set()

    def _candidate_antecedents_for_graph_path(self, new_match: TTPMatch) -> set[str]:
        ids: set[str] = set()
        for node_id in (new_match.subject_node_id, new_match.object_node_id):
            if not node_id:
                continue
            ids |= self.online_index.mapper_match_ids(node_id)
        return ids

    def _candidate_antecedents_for_shared_entity(self, new_match: TTPMatch) -> set[str]:
        ids: set[str] = set()
        for node_id in (new_match.subject_node_id, new_match.object_node_id):
            if not node_id:
                continue
            ids |= self.online_index.local_match_ids(node_id)
        return ids

    def _prereq_satisfied_online(self, new_match: TTPMatch) -> tuple[bool, set[str]]:
        rule = self.rule_by_id.get(new_match.rule_id)
        if rule is None:
            return False, set()

        prereq_types = hsg_builder.prerequisite_types(rule)
        required_ttp_ids = self._required_ttp_ids(new_match.rule_id)
        antecedents: set[str] = set()

        # previous-ttp prerequisite via mapper O(1)
        for required in required_ttp_ids:
            if not new_match.object_node_id or not self.online_index.mapper_contains_rule(new_match.object_node_id, required):
                return False, set()

        # graph_path prerequisite via mapper lookup only (no graph traversal)
        if "graph_path" in prereq_types:
            antecedents |= self._candidate_antecedents_for_graph_path(new_match)
            if not antecedents:
                return False, set()

        # shared_entity prerequisite via local node index only
        if "shared_entity" in prereq_types:
            local = self._candidate_antecedents_for_shared_entity(new_match)
            if not local:
                return False, set()
            antecedents |= local

        # time-order prerequisite (if required_ttp_ids configured) via earliest seq O(1)
        for required in required_ttp_ids:
            if not new_match.object_node_id:
                return False, set()
            earliest = self.online_index.mapper_earliest_seq(new_match.object_node_id, required)
            if earliest is None:
                return False, set()
            if new_match.sequence is not None and earliest >= new_match.sequence:
                return False, set()

        return True, antecedents

    def _apply_noise_model(self, new_matches: list[TTPMatch]) -> list[TTPMatch]:
        if not self.noise_model or not new_matches:
            return new_matches
        drop_ids, noise_stats = get_benign_drop_ids(
            new_matches,
            rule_by_id=self.rule_by_id,
            model=self.noise_model,
            events_by_id=self.events_by_id,
            bytes_threshold=self.noise_bytes_threshold,
            signature_min_ratio=self.noise_signature_min_ratio,
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
        if self.scoring_mode == "paper_exact" and self.paper_exact is not None:
            state = self.paper_exact.state
            stage_severity = {APT_STAGES[i]: float(state.stage_severity[i]) for i in range(len(APT_STAGES))}
            scenario = {
                "score": float(state.score),
                "score_legacy": 0.0,
                "score_paper": float(state.score),
                "score_paper_exact": float(state.score),
                "score_paper_exact_log": float(state.log_score),
                "threat_tuple": list(state.stage_severity),
                "threat_tuple_exact": list(state.stage_severity),
                "stage_severity": stage_severity,
                "stage_severity_exact": stage_severity,
                "paper_weights": list(self.paper_weights),
                "nodes": len(self.hsg_nodes),
                "edges": len(self.hsg_edges),
            }
            self.top_scenarios = [scenario]
            while len(self.top_scenarios) < 3:
                self.top_scenarios.append(
                    {
                        "score": 0.0,
                        "score_legacy": 0.0,
                        "score_paper": 1.0,
                        "score_paper_exact": 1.0,
                        "score_paper_exact_log": 0.0,
                        "threat_tuple": [1.0] * len(APT_STAGES),
                        "threat_tuple_exact": [1.0] * len(APT_STAGES),
                        "stage_severity": {APT_STAGES[i]: 1.0 for i in range(len(APT_STAGES))},
                        "stage_severity_exact": {APT_STAGES[i]: 1.0 for i in range(len(APT_STAGES))},
                        "paper_weights": list(self.paper_weights),
                        "nodes": 0,
                        "edges": 0,
                    }
                )
            return
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
        node_info = self.graph.add_event(event)
        if node_info is None:
            return

        raw_matches = [self._reid_match(m) for m in self.matcher.match(self.graph, self.ruleset, [event])]
        self.stats.raw_matches += len(raw_matches)
        new_matches = self._apply_noise_model(raw_matches)

        for new_match in new_matches:
            new_match.subject_node_id = node_info.get("subject_node_id")
            new_match.object_node_id = node_info.get("object_node_id")
            new_match.sequence = self.stats.events
            new_match.attributes = {"subject_node_id": new_match.subject_node_id, "object_node_id": new_match.object_node_id}

            if self.use_online_prereq:
                old_matches = list(self.match_by_id.values())
                satisfied, antecedents = self._prereq_satisfied_online(new_match)
                rule = self.rule_by_id.get(new_match.rule_id)
                has_prereq = bool(rule and hsg_builder.prerequisite_types(rule))
                if has_prereq and not satisfied:
                    continue
                for old_id in antecedents:
                    old_match = self.match_by_id.get(old_id)
                    if old_match is None:
                        continue
                    self.stats.candidate_pairs_considered += 1
                    self.hsg_edges.extend(self._edge_for_pair_online(old_match, new_match))
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
            for node_id in (new_match.subject_node_id, new_match.object_node_id):
                if node_id:
                    self.online_index.on_match_added(
                        node_id=node_id,
                        ttp_id=new_match.match_id,
                        rule_id=new_match.rule_id,
                        sequence=int(new_match.sequence or self.stats.events),
                        origin_node_id=node_id,
                    )
            if self.paper_exact is not None:
                self.paper_exact.update(
                    stage=int(self.rule_stage.get(new_match.rule_id, 1)),
                    raw_severity=self.rule_cvss.get(new_match.rule_id, self.rule_severity.get(new_match.rule_id, 1.0)),
                    event_time=event.ts,
                    sequence=new_match.sequence,
                )

        if not self.use_online_prereq:
            ordered_matches = sorted(
                self.matches,
                key=lambda m: (
                    int(self.rule_order.get(m.rule_id, 10**9)),
                    int(m.sequence or 0),
                    m.match_id,
                ),
            )
            remap: dict[str, str] = {}
            for i, m in enumerate(ordered_matches, start=1):
                new_id = f"m{i}"
                remap[m.match_id] = new_id
            for m in ordered_matches:
                m.match_id = remap[m.match_id]
            self.matches = ordered_matches
            self.match_by_id = {m.match_id: m for m in ordered_matches}
            hsg = hsg_builder.build_hsg(
                ordered_matches,
                self.graph,
                self.ruleset,
                paper_mode=self.paper_mode,
                prereq_policy=self.prereq_policy,
                graph_path_allowlist=self.graph_path_allowlist,
                max_graph_path_edges=self.max_graph_path_edges,
                max_graph_path_candidates_per_match=self.max_graph_path_candidates_per_match,
            )
            self.hsg_nodes = {n.match_id: n for n in hsg.nodes}
            self.hsg_edges = list(hsg.edges)
            self.seen_edges = {(e.src, e.dst, e.relation) for e in self.hsg_edges}
            self._graph_path_edges_count = len([e for e in self.hsg_edges if e.relation == "graph_path"])

        self._refresh_scores()
        self._events_processed += 1
        if self.global_refine_mode == "every_n_events" and self._events_processed % self.global_refine_every == 0:
            self._maybe_global_refine("periodic")

    def current_hsg(self) -> HSG:
        return HSG(nodes=list(self.hsg_nodes.values()), edges=list(self.hsg_edges))

    def _replace_state_from_filtered(
        self,
        matches_after: list[TTPMatch],
        hsg_after: HSG,
        *,
        before_matches: int | None = None,
        before_nodes: int | None = None,
        before_edges: int | None = None,
    ) -> None:
        if before_matches is not None and before_nodes is not None and before_edges is not None:
            self._noise_before_override = {
                "matches": int(before_matches),
                "hsg_nodes": int(before_nodes),
                "hsg_edges": int(before_edges),
            }
        self.matches = list(matches_after)
        self.match_by_id = {m.match_id: m for m in self.matches}
        self.hsg_nodes = {n.match_id: n for n in hsg_after.nodes}
        self.hsg_edges = list(hsg_after.edges)
        self.seen_edges = {(e.src, e.dst, e.relation) for e in self.hsg_edges}

        self.node_to_matches = defaultdict(set)
        self.match_to_entities = {}
        for m in self.matches:
            entities = set(m.entities)
            self.match_to_entities[m.match_id] = entities
            for entity in entities:
                self.node_to_matches[entity].add(m.match_id)

        self._graph_path_edges_count = len([e for e in self.hsg_edges if e.relation == "graph_path"])
        # Rebuild online index from current graph + kept matches.
        self.online_index = OnlineIndex()
        for edge in self.graph.edges:
            self.online_index.on_edge_added(edge.src, edge.dst, edge.edge_type)
        for m in self.matches:
            for node_id in (m.subject_node_id, m.object_node_id):
                if node_id:
                    self.online_index.on_match_added(
                        node_id=node_id,
                        ttp_id=m.match_id,
                        rule_id=m.rule_id,
                        sequence=int(m.sequence or 0),
                        origin_node_id=node_id,
                    )

    def _maybe_global_refine(self, trigger: str) -> None:
        if self.global_refine_mode == "off":
            return
        if trigger == "snapshot" and self.global_refine_mode != "snapshot":
            return
        if trigger == "periodic" and self.global_refine_mode != "every_n_events":
            return

        current_hsg = self.current_hsg()
        noise_config = NoiseConfig(
            min_graph_path_weight=0.0,
            min_path_factor=float(self.resolved_effective_config.get("path_thres", 0.0)),
            path_factor_op=str(self.resolved_effective_config.get("path_factor_op", "ge")),
        )
        if self.noise_model and self.matches:
            drop_ids, _ = get_benign_drop_ids(
                self.matches,
                rule_by_id=self.rule_by_id,
                model=self.noise_model,
                events_by_id=self.events_by_id,
                bytes_threshold=self.noise_bytes_threshold,
                signature_min_ratio=self.noise_signature_min_ratio,
            )
            noise_config.drop_match_ids = set(drop_ids)

        matches_after, hsg_after = apply_noise_filter(self.matches, current_hsg, noise_config)
        self._replace_state_from_filtered(matches_after, hsg_after)
        self._refresh_scores()

        if trigger == "snapshot":
            self.global_refine_ran_at_snapshots_count += 1
        elif trigger == "periodic":
            self.global_refine_ran_at_events_count += 1

    def build_result(self) -> dict[str, Any]:
        hsg = self.current_hsg()
        before_counts = self._noise_before_override or {
            "matches": self.stats.raw_matches,
            "hsg_nodes": self.stats.raw_matches,
            "hsg_edges": len(hsg.edges),
        }
        noise_filter = {
            "before": before_counts,
            "after": {
                "matches": len(self.matches),
                "hsg_nodes": len(hsg.nodes),
                "hsg_edges": len(hsg.edges),
            },
            "dropped": {
                "matches": int(before_counts["matches"]) - len(self.matches),
                "hsg_nodes": int(before_counts["hsg_nodes"]) - len(hsg.nodes),
                "hsg_edges": int(before_counts["hsg_edges"]) - len(hsg.edges),
            },
        }
        legacy_snapshot_mode = (self.scoring_mode == "legacy" and not self.use_online_prereq)
        include_trained_noise = (
            (not legacy_snapshot_mode)
            or self.noise_model is not None
            or self.stats.dropped_matches > 0
            or self.stats.by_signature > 0
            or self.stats.by_byte_volume > 0
        )
        if include_trained_noise:
            noise_filter["trained_noise"] = {
                "dropped_matches": self.stats.dropped_matches,
                "by_signature": self.stats.by_signature,
                "by_byte_volume": self.stats.by_byte_volume,
                "byte_volume_by_rule_id": self.stats.byte_volume_by_rule_id or {},
            }
        top1 = self.top_scenarios[0] if self.top_scenarios else {}
        paper_exact_state = self.paper_exact.state if self.paper_exact is not None else None
        paper_scoring = {
            "threat_tuple": top1.get("threat_tuple", []),
            "stage_severity": top1.get("stage_severity", {}),
            "paper_weights": top1.get("paper_weights", self.resolved_effective_config.get("paper_weights", [1.0] * 7)),
            "score_paper": top1.get("score_paper", top1.get("score_paper_exact", 1.0)),
        }
        if not legacy_snapshot_mode:
            paper_scoring["score_paper_exact"] = top1.get("score_paper_exact", top1.get("score_paper", 1.0))
            paper_scoring["score_paper_exact_log"] = top1.get("score_paper_exact_log", 0.0)
            paper_scoring["tau"] = self.tau
            paper_scoring["tau_log"] = None if self.tau is None else self.paper_exact.log_tau if self.paper_exact is not None else None
        if paper_exact_state is not None:
            paper_scoring["stage_earliest_detection_time"] = {
                APT_STAGES[i]: paper_exact_state.stage_earliest_detection_time[i] for i in range(len(APT_STAGES))
            }
            paper_scoring["stage_earliest_detection_sequence"] = {
                APT_STAGES[i]: paper_exact_state.stage_earliest_detection_sequence[i] for i in range(len(APT_STAGES))
            }
            paper_scoring["apt_detected"] = bool(paper_exact_state.detected)
            paper_scoring["first_detection_time"] = paper_exact_state.first_detection_time
            paper_scoring["first_detection_sequence"] = paper_exact_state.first_detection_sequence
            paper_scoring["first_detection_score"] = paper_exact_state.first_detection_score
            paper_scoring["first_detection_log_score"] = paper_exact_state.first_detection_log_score
            paper_scoring["first_detection_tuple_snapshot"] = paper_exact_state.first_detection_tuple_snapshot
            paper_scoring["first_detection_contributing_stages"] = [
                {"stage_index": i, "stage_name": APT_STAGES[i - 1]} for i in paper_exact_state.first_detection_contributing_stages
            ]
        summary: dict[str, Any] = {
            "events": self.stats.events,
            "rules": len(self.ruleset.rules),
            "matches": len(self.matches),
            "hsg_nodes": len(hsg.nodes),
            "hsg_edges": len(hsg.edges),
            "noise_filter": noise_filter,
            "resolved_effective_config": self.resolved_effective_config,
            "paper_scoring": paper_scoring,
            "top_scenarios": self.top_scenarios,
        }
        if not legacy_snapshot_mode:
            summary["online_index"] = {"candidate_pairs_considered": self.stats.candidate_pairs_considered}
            summary["streaming"] = {
                "global_refine": {
                    "mode": self.global_refine_mode,
                    "every": self.global_refine_every,
                    "ran_at_snapshots_count": self.global_refine_ran_at_snapshots_count,
                    "ran_at_events_count": self.global_refine_ran_at_events_count,
                }
            }
        matches_out = []
        for m in self.matches:
            row = {
                "match_id": m.match_id,
                "rule_id": m.rule_id,
                "event_ids": m.event_ids,
                "entities": m.entities,
                "bindings": m.bindings,
                "metadata": m.metadata,
            }
            if not legacy_snapshot_mode:
                row["subject_node_id"] = m.subject_node_id
                row["object_node_id"] = m.object_node_id
                row["sequence"] = m.sequence
                row["attributes"] = m.attributes
            matches_out.append(row)
        return {"summary": summary, "matches": matches_out, "hsg": hsg_to_dict(hsg)}

    def write_snapshot(self, out_dir: str | Path) -> dict[str, Any]:
        p = Path(out_dir)
        p.mkdir(parents=True, exist_ok=True)
        self._maybe_global_refine("snapshot")
        result = self.build_result()
        (p / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        (p / "summary.json").write_text(json.dumps(result["summary"], indent=2), encoding="utf-8")
        (p / "matches.json").write_text(json.dumps(result["matches"], indent=2), encoding="utf-8")
        (p / "hsg.json").write_text(json.dumps(result["hsg"], indent=2), encoding="utf-8")
        return result
