from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Iterable

from engine.io.events import Event


def path_factor_passes(pf: float | None, threshold: float, op: str = "ge") -> bool:
    """
    Compare path_factor threshold with consistent semantics across pipeline modules.

    - pf is None or pf <= 0.0 -> fail
    - op == "ge": pf >= threshold
    - op == "le": pf <= threshold
    """
    if pf is None:
        return False
    try:
        pf_value = float(pf)
        th_value = float(threshold)
    except (TypeError, ValueError):
        return False

    if pf_value <= 0.0:
        return False
    if op == "ge":
        return pf_value >= th_value
    if op == "le":
        return pf_value <= th_value
    raise ValueError(f"Unsupported path_factor op: {op}")


@dataclass(slots=True)
class VersionedNode:
    node_id: str
    entity_id: str
    version: int
    created_at: int


class EdgeType(str, Enum):
    DATA_FLOW = "data_flow"
    VERSION_TRANSITION = "version_transition"


@dataclass(slots=True)
class Edge:
    src: str
    dst: str
    event_id: str
    event_type: str
    ts: str | None
    edge_type: EdgeType = EdgeType.DATA_FLOW
    relation: str = "flow"
    src_entity: str | None = None
    dst_entity: str | None = None


class ProvenanceGraph:
    """
    Directed provenance graph with node versioning.

    External API remains entity-id based for compatibility, while internal reachability
    and edge storage operate on versioned nodes.
    """

    def __init__(self) -> None:
        # Backward-compatible entity index.
        self.nodes: set[str] = set()
        # Backward-compatible union adjacency for callers that inspect `adj`.
        self.adj: dict[str, set[str]] = defaultdict(set)
        self.rev_adj: dict[str, set[str]] = defaultdict(set)
        # Internal typed adjacency (required for version-transition cost semantics).
        self.adj_data_flow: dict[str, set[str]] = defaultdict(set)
        self.rev_adj_data_flow: dict[str, set[str]] = defaultdict(set)
        self.adj_version_transition: dict[str, set[str]] = defaultdict(set)
        self.rev_adj_version_transition: dict[str, set[str]] = defaultdict(set)
        self.edges: list[Edge] = []
        self.version_nodes: dict[str, VersionedNode] = {}
        self.entity_versions: dict[str, list[str]] = defaultdict(list)
        self.current_version: dict[str, str] = {}
        self._version_counter: dict[str, int] = defaultdict(int)
        self._creation_tick: int = 0
        self.process_parents: dict[str, set[str]] = defaultdict(set)
        self._process_ancestor_cache: dict[str, set[str]] = {}
        self._path_factor_cache: dict[str, dict[str, float]] = {}
        self._edge_hooks: list[Callable[[Edge], None]] = []
        # Incremental summaries (delta-propagated on edge addition):
        # - ancestors_by_node[n]: all ancestors (inclusive) of n
        # - min_dist_from_ancestor[n][a]: shortest weighted distance a -> n
        #   where DATA_FLOW=1 and VERSION_TRANSITION=0
        self._ancestors_by_node: dict[str, set[str]] = {}
        self._min_dist_from_ancestor: dict[str, dict[str, int]] = {}

    def register_edge_hook(self, hook: Callable[[Edge], None]) -> None:
        self._edge_hooks.append(hook)

    @staticmethod
    def _flow_direction(event: Event) -> tuple[str, str]:
        """Resolve information-flow edge direction by operation type."""
        op = event.event_type.lower()

        if op in {"write", "fork", "connect", "send"}:
            return event.subject, event.object
        if op in {"read", "exec", "recv"}:
            return event.object, event.subject

        # Fallback for unknown/custom operations: keep declared order.
        return event.subject, event.object

    @staticmethod
    def _is_truthy(value: object) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value != 0
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "y", "on"}
        return False

    def _entities_requiring_new_version(self, event: Event) -> set[str]:
        """
        Taint propagation rule (explicit):
        1) write/modify/send   -> object version++
        2) read/recv           -> subject version++
        3) exec/privilege chg  -> process(subject) version++
        4) subject/object may both change in one event (independent bumps)
           via explicit raw flags: subject_state_change/object_state_change.
        """
        if not event.subject or not event.object:
            return set()

        op = event.event_type.lower()
        changed: set[str] = set()

        if op in {"write", "modify", "send", "proc_to_file", "proc_to_registry", "proc_to_ip", "file_to_ip"}:
            changed.add(event.object)
        if op in {"read", "recv", "file_to_proc"}:
            changed.add(event.subject)
        if op in {"exec", "execute", "setuid", "setgid", "privilege_change", "privilege_escalation"}:
            if self._is_process_node(event.subject):
                changed.add(event.subject)

        raw = event.raw if isinstance(event.raw, dict) else {}
        if self._is_truthy(raw.get("subject_state_change")):
            changed.add(event.subject)
        if self._is_truthy(raw.get("object_state_change")):
            changed.add(event.object)

        # Safety fallback for unknown/custom operations: mutate object state so flow
        # edges remain forward in version-time and the internal graph stays acyclic.
        if not changed:
            changed.add(event.object)
        return changed

    def _next_tick(self) -> int:
        self._creation_tick += 1
        return self._creation_tick

    def _node_meta(self, node_id: str) -> VersionedNode:
        return self.version_nodes[node_id]

    def _node_entity(self, node_id: str) -> str:
        return self.version_nodes[node_id].entity_id

    def _new_version_node(self, entity_id: str) -> str:
        next_version = self._version_counter[entity_id] + 1
        self._version_counter[entity_id] = next_version
        node_id = f"{entity_id}#v{next_version}"
        node = VersionedNode(
            node_id=node_id,
            entity_id=entity_id,
            version=next_version,
            created_at=self._next_tick(),
        )
        self.version_nodes[node_id] = node
        self.entity_versions[entity_id].append(node_id)
        self.nodes.add(entity_id)
        self._ancestors_by_node[node_id] = {node_id}
        self._min_dist_from_ancestor[node_id] = {node_id: 0}
        return node_id

    def _ensure_entity(self, entity_id: str) -> str:
        cur = self.current_version.get(entity_id)
        if cur is not None:
            return cur
        node_id = self._new_version_node(entity_id)
        self.current_version[entity_id] = node_id
        return node_id

    def _link_version_edge(
        self,
        src_node: str,
        dst_node: str,
        event: Event,
        edge_type: EdgeType,
        relation: str,
    ) -> None:
        src_meta = self._node_meta(src_node)
        dst_meta = self._node_meta(dst_node)
        if src_meta.created_at >= dst_meta.created_at:
            raise ValueError("Versioned DAG invariant violated: non-forward edge creation attempted")

        if edge_type == EdgeType.DATA_FLOW:
            self.adj_data_flow[src_node].add(dst_node)
            self.rev_adj_data_flow[dst_node].add(src_node)
        elif edge_type == EdgeType.VERSION_TRANSITION:
            self.adj_version_transition[src_node].add(dst_node)
            self.rev_adj_version_transition[dst_node].add(src_node)
        else:
            raise ValueError(f"Unsupported edge_type: {edge_type}")

        # Union adjacency for backward compatibility.
        self.adj[src_node].add(dst_node)
        self.rev_adj[dst_node].add(src_node)
        self.edges.append(
            Edge(
                src=src_node,
                dst=dst_node,
                event_id=event.event_id,
                event_type=event.event_type,
                ts=event.ts,
                edge_type=edge_type,
                relation=relation,
                src_entity=src_meta.entity_id,
                dst_entity=dst_meta.entity_id,
            )
        )
        emitted = self.edges[-1]
        self._propagate_ancestor_distance_delta(src_node, dst_node, edge_type)
        for hook in self._edge_hooks:
            hook(emitted)

    def _propagate_ancestor_distance_delta(self, src_node: str, dst_node: str, edge_type: EdgeType) -> None:
        edge_cost = self._edge_cost(edge_type)
        src_dist = self._min_dist_from_ancestor.get(src_node, {})
        if not src_dist:
            return

        # Queue items: (source, destination, edge_cost, delta_from_source)
        q: deque[tuple[str, str, int, dict[str, int]]] = deque([(src_node, dst_node, edge_cost, dict(src_dist))])
        while q:
            _src, cur_dst, cur_cost, delta = q.popleft()
            dst_dist = self._min_dist_from_ancestor.setdefault(cur_dst, {cur_dst: 0})
            dst_anc = self._ancestors_by_node.setdefault(cur_dst, {cur_dst})

            changed_delta: dict[str, int] = {}
            for anc, anc_to_src in delta.items():
                cand = int(anc_to_src) + int(cur_cost)
                prev = dst_dist.get(anc)
                if prev is None or cand < prev:
                    dst_dist[anc] = cand
                    dst_anc.add(anc)
                    changed_delta[anc] = cand

            if not changed_delta:
                continue

            for nxt, nxt_type in self._iter_neighbors(cur_dst):
                nxt_cost = self._edge_cost(nxt_type)
                q.append((cur_dst, nxt, nxt_cost, changed_delta))

    def _bump_entity(self, entity_id: str, event: Event) -> str:
        prev = self._ensure_entity(entity_id)
        new_node = self._new_version_node(entity_id)
        self.current_version[entity_id] = new_node
        self._link_version_edge(
            prev,
            new_node,
            event,
            edge_type=EdgeType.VERSION_TRANSITION,
            relation="prev_version",
        )
        return new_node

    def _all_versions(self, entity_id: str) -> list[str]:
        return list(self.entity_versions.get(entity_id, []))

    def _resolve_query_nodes(self, token: str) -> list[str]:
        if token in self.version_nodes:
            return [token]
        if token in self.nodes:
            return self._all_versions(token)
        return []

    def _iter_neighbors(self, node_id: str) -> Iterable[tuple[str, EdgeType]]:
        for nxt in self.adj_data_flow.get(node_id, set()):
            yield nxt, EdgeType.DATA_FLOW
        for nxt in self.adj_version_transition.get(node_id, set()):
            yield nxt, EdgeType.VERSION_TRANSITION

    def _iter_prev(self, node_id: str) -> Iterable[str]:
        for prev in self.rev_adj_data_flow.get(node_id, set()):
            yield prev
        for prev in self.rev_adj_version_transition.get(node_id, set()):
            yield prev

    @staticmethod
    def _edge_cost(edge_type: EdgeType) -> int:
        return 0 if edge_type == EdgeType.VERSION_TRANSITION else 1

    def _bfs_desc_version(self, starts: list[str]) -> set[str]:
        if not starts:
            return set()
        seen: set[str] = set(starts)
        q: deque[str] = deque(starts)
        while q:
            cur = q.popleft()
            for nxt, _edge_type in self._iter_neighbors(cur):
                if nxt in seen:
                    continue
                seen.add(nxt)
                q.append(nxt)
        return seen

    def _bfs_anc_version(self, starts: list[str]) -> set[str]:
        if not starts:
            return set()
        seen: set[str] = set(starts)
        q: deque[str] = deque(starts)
        while q:
            cur = q.popleft()
            for prev in self._iter_prev(cur):
                if prev in seen:
                    continue
                seen.add(prev)
                q.append(prev)
        return seen

    def _shortest_version_path(self, src: str, dst: str) -> list[str] | None:
        starts = self._resolve_query_nodes(src)
        targets = set(self._resolve_query_nodes(dst))
        if not starts or not targets:
            return None

        q: deque[str] = deque(starts)
        parent: dict[str, str | None] = {s: None for s in starts}
        hit: str | None = None
        while q and hit is None:
            cur = q.popleft()
            if cur in targets:
                hit = cur
                break
            for nxt in self._iter_neighbors(cur):
                node = nxt[0]
                if node in parent:
                    continue
                parent[node] = cur
                q.append(node)

        if hit is None:
            return None

        out: list[str] = []
        cur: str | None = hit
        while cur is not None:
            out.append(cur)
            cur = parent.get(cur)
        out.reverse()
        return out

    def _shortest_version_distance(self, src: str, dst: str) -> int | None:
        starts = self._resolve_query_nodes(src)
        targets = set(self._resolve_query_nodes(dst))
        if not starts or not targets:
            return None
        best: int | None = None
        for t in targets:
            t_dist = self._min_dist_from_ancestor.get(t, {})
            for s in starts:
                d = t_dist.get(s)
                if d is None:
                    continue
                if best is None or int(d) < best:
                    best = int(d)
        return best

    def add_event(self, event: Event) -> dict[str, str] | None:
        """
        Add event-derived edges and return endpoint version-node ids.

        Return shape:
        {
          "flow_src_version": "<entity#vN>",
          "flow_dst_version": "<entity#vM>",
        }
        """
        if not event.subject or not event.object:
            return None

        src_entity, dst_entity = self._flow_direction(event)
        self._ensure_entity(src_entity)
        self._ensure_entity(dst_entity)

        pre_src = self.current_version[src_entity]
        pre_dst = self.current_version[dst_entity]

        changed_entities = self._entities_requiring_new_version(event)
        # Enforce receiver-post-state modeling so all flow edges stay forward in version-time.
        if dst_entity not in changed_entities:
            changed_entities.add(dst_entity)

        post_by_entity: dict[str, str] = {}
        for entity_id in sorted(changed_entities):
            post_by_entity[entity_id] = self._bump_entity(entity_id, event)

        flow_src = pre_src
        flow_dst = post_by_entity.get(dst_entity, pre_dst)
        self._link_version_edge(
            flow_src,
            flow_dst,
            event,
            edge_type=EdgeType.DATA_FLOW,
            relation="flow",
        )
        self._path_factor_cache.clear()

        # Process lineage relation for common-ancestor checks.
        if event.event_type.lower() in {"proc_to_proc", "fork"} and self._is_process_node(event.subject) and self._is_process_node(event.object):
            self.process_parents[event.object].add(event.subject)
            self._process_ancestor_cache.clear()
        return {
            "flow_src_version": flow_src,
            "flow_dst_version": flow_dst,
            "subject_node_id": self.current_version[event.subject],
            "object_node_id": self.current_version[event.object],
        }

    def add_events(self, events: Iterable[Event]) -> None:
        for event in events:
            self.add_event(event)

    def has_path(self, src: str, dst: str) -> bool:
        return self.path(src, dst) is not None

    def descendants(self, node: str) -> set[str]:
        """Entity-level reachability projection from all versions of entity `node`."""
        if node not in self.nodes:
            return set()
        version_seen = self._bfs_desc_version(self._all_versions(node))
        return {self._node_entity(v) for v in version_seen}

    def ancestors(self, node: str) -> set[str]:
        """Entity-level reverse reachability projection to all versions of entity `node`."""
        if node not in self.nodes:
            return set()
        version_seen = self._bfs_anc_version(self._all_versions(node))
        return {self._node_entity(v) for v in version_seen}

    def shortest_path_len(self, src: str, dst: str) -> int | None:
        """
        Return shortest directed path length between entity ids over versioned DAG.

        - If no src -> dst path exists, returns None.
        - If src == dst and the node exists, returns 0.
        """
        if src == dst:
            return 0 if src in self.nodes or src in self.version_nodes else None
        return self._shortest_version_distance(src, dst)

    def attenuation(self, distance: int) -> float:
        """Paper-style distance attenuation over weighted DAG distance."""
        d = max(0, int(distance))
        return 1.0 / (1.0 + float(d))

    def ac(self, x: str, y: str) -> set[str]:
        """AC(x,y): set of common ancestors over resolved version nodes."""
        x_nodes = self._resolve_query_nodes(x)
        y_nodes = self._resolve_query_nodes(y)
        if not x_nodes or not y_nodes:
            return set()
        anc_x: set[str] = set()
        anc_y: set[str] = set()
        for xn in x_nodes:
            anc_x |= self._ancestors_by_node.get(xn, set())
        for yn in y_nodes:
            anc_y |= self._ancestors_by_node.get(yn, set())
        return anc_x & anc_y

    def ac_min(self, x: str, y: str) -> set[str]:
        """
        AC_min(x,y): common ancestors that are not ancestors of another common ancestor.
        """
        common = self.ac(x, y)
        if not common:
            return set()
        result = set(common)
        common_list = list(common)
        for a in common_list:
            for b in common_list:
                if a == b:
                    continue
                # Remove 'a' when 'a' is ancestor of another common ancestor 'b'.
                if a in self._ancestors_by_node.get(b, set()):
                    result.discard(a)
                    break
        return result

    def dependency_strength(self, src: str, dst: str) -> float:
        """
        dependency_strength(x,y) = attenuation(distance(x,y)).
        """
        path_len = self.shortest_path_len(src, dst)
        if path_len is None:
            return 0.0
        return self.attenuation(path_len)

    @staticmethod
    def _is_process_node(node: str | None) -> bool:
        if not node:
            return False
        return node.split(":", 1)[0].lower() == "proc"

    def _process_ancestors(self, process_node: str) -> set[str]:
        if process_node in self._process_ancestor_cache:
            return self._process_ancestor_cache[process_node]

        ancestors: set[str] = {process_node}
        q: deque[str] = deque([process_node])
        while q:
            cur = q.popleft()
            for parent in self.process_parents.get(cur, set()):
                if parent in ancestors:
                    continue
                ancestors.add(parent)
                q.append(parent)
        self._process_ancestor_cache[process_node] = ancestors
        return ancestors

    def _has_common_ancestor(self, process_a: str, process_b: str) -> bool:
        return bool(self._process_ancestors(process_a) & self._process_ancestors(process_b))

    def _paper_path_factor_map(self, src: str) -> dict[str, float]:
        """
        Paper-faithful incremental propagation (MVP):
        - pf(src, src) = 1
        - transition u -> v:
            * if v is non-process: no increment
            * if v is process and src/v share common ancestor: no increment
            * else increment by 1
        - multi-path case uses min accumulated value.
        """
        if src not in self.nodes:
            return {}

        # Dijkstra on non-negative edge costs (0/1) to realize min over multiple flows.
        import heapq

        starts = self._all_versions(src)
        best: dict[str, float] = {}
        heap: list[tuple[float, str]] = []
        for s in starts:
            best[s] = 1.0
            heap.append((1.0, s))
        heapq.heapify(heap)

        while heap:
            cur_pf, cur = heapq.heappop(heap)
            if cur_pf > best.get(cur, float("inf")):
                continue

            for nxt, edge_type in self._iter_neighbors(cur):
                inc = 0.0
                nxt_entity = self._node_entity(nxt)
                if edge_type == EdgeType.DATA_FLOW and self._is_process_node(nxt_entity):
                    if not (self._is_process_node(src) and self._has_common_ancestor(src, nxt_entity)):
                        inc = 1.0
                cand = cur_pf + inc
                if cand < best.get(nxt, float("inf")):
                    best[nxt] = cand
                    heapq.heappush(heap, (cand, nxt))
        out: dict[str, float] = {}
        for node_id, pf in best.items():
            entity = self._node_entity(node_id)
            prev = out.get(entity)
            if prev is None or pf < prev:
                out[entity] = pf
        return out

    def path_factor_legacy_mac(self, src: str, dst: str) -> float:
        """
        Legacy B5/B6 approximation retained for compatibility experiments.
        """
        cut_size = self.min_vertex_cut_size(src, dst)
        if cut_size is None:
            return 0.0
        return 1.0 / (1.0 + max(cut_size, 1))

    def min_vertex_cut_size(self, src: str, dst: str) -> int | None:
        """
        Return minimum number of intermediate vertices needed to disconnect src -> dst.

        - Directed cut, src/dst are excluded from removable vertices.
        - If no src -> dst path exists, returns None.
        """
        if not self.has_path(src, dst):
            return None
        if src == dst:
            return 0

        sub_nodes = self.descendants(src) & self.ancestors(dst)
        if src not in sub_nodes or dst not in sub_nodes:
            return None
        nodes = list(sub_nodes)
        inf = float("inf")
        entity_adj = self._entity_adjacency()

        capacity: dict[str, dict[str, float]] = defaultdict(dict)

        def add_edge(u: str, v: str, cap: float) -> None:
            capacity[u][v] = capacity[u].get(v, 0.0) + cap
            capacity[v].setdefault(u, 0.0)

        # Node splitting: vin -> vout with vertex capacity (1 for intermediates, inf for src/dst).
        for v in nodes:
            vin = f"{v}#in"
            vout = f"{v}#out"
            node_cap = inf if v in {src, dst} else 1.0
            add_edge(vin, vout, node_cap)

        # Original directed edge u -> v becomes u_out -> v_in with infinite capacity.
        for u in nodes:
            nbrs = entity_adj.get(u, set())
            for v in nbrs:
                if v not in sub_nodes:
                    continue
                add_edge(f"{u}#out", f"{v}#in", inf)

        source = f"{src}#out"
        sink = f"{dst}#in"

        # Edmonds-Karp max-flow for unit/infinite capacities on small/medium graphs.
        flow = 0.0
        while True:
            parent: dict[str, str | None] = {source: None}
            q: deque[str] = deque([source])
            while q and sink not in parent:
                cur = q.popleft()
                for nxt, cap in capacity[cur].items():
                    if cap > 0 and nxt not in parent:
                        parent[nxt] = cur
                        q.append(nxt)

            if sink not in parent:
                break

            path_cap = inf
            v = sink
            while parent[v] is not None:
                u = parent[v]
                path_cap = min(path_cap, capacity[u][v])
                v = u

            v = sink
            while parent[v] is not None:
                u = parent[v]
                capacity[u][v] -= path_cap
                capacity[v][u] += path_cap
                v = u

            flow += path_cap

        if flow == inf:
            # If only src/dst (non-removable) can cut, treat as strongest controllability.
            return 0
        return int(flow)

    def path_factor(self, src: str, dst: str) -> float | None:
        # Version-node query compatibility: AC_min-based value.
        if src in self.version_nodes or dst in self.version_nodes:
            ac_min_set = self.ac_min(src, dst)
            if not ac_min_set:
                return None
            return 1.0 / float(len(ac_min_set))

        # Entity-level paper path-factor compatibility.
        pf_map = self._paper_path_factor_map(src)
        val = pf_map.get(dst)
        if val is None:
            return None
        return float(val)

    def path_factor_for_edge(self, src: str, dst: str) -> float | None:
        """
        Return path_factor normalized for graph_path edge serialization.

        - Unreachable is normalized to None.
        """
        return self.path_factor(src, dst)

    def path(self, src: str, dst: str) -> list[str] | None:
        """Return one shortest path from src to dst if it exists."""
        if src not in self.nodes or dst not in self.nodes:
            return None
        if src == dst:
            return [src]

        version_path = self._shortest_version_path(src, dst)
        if version_path is None:
            return None

        projected: list[str] = []
        for node_id in version_path:
            entity = self._node_entity(node_id)
            if not projected or projected[-1] != entity:
                projected.append(entity)
        return projected

    def _entity_adjacency(self) -> dict[str, set[str]]:
        adj: dict[str, set[str]] = defaultdict(set)
        for u, nbrs in self.adj_data_flow.items():
            src_entity = self._node_entity(u)
            for v in nbrs:
                dst_entity = self._node_entity(v)
                if src_entity == dst_entity:
                    continue
                adj[src_entity].add(dst_entity)
        return adj

    def is_dag(self) -> bool:
        """Check acyclicity of the internal versioned graph."""
        try:
            self.topological_sort_version_nodes()
            return True
        except ValueError:
            return False

    def topological_sort_version_nodes(self) -> list[str]:
        indeg: dict[str, int] = {nid: 0 for nid in self.version_nodes}
        for src, nbrs in self.adj.items():
            _ = src
            for dst in nbrs:
                indeg[dst] = indeg.get(dst, 0) + 1
        q: deque[str] = deque([nid for nid, d in indeg.items() if d == 0])
        out: list[str] = []
        while q:
            cur = q.popleft()
            out.append(cur)
            for nxt in self.adj.get(cur, set()):
                indeg[nxt] -= 1
                if indeg[nxt] == 0:
                    q.append(nxt)
        if len(out) != len(indeg):
            raise ValueError("Versioned provenance graph contains a cycle")
        return out
