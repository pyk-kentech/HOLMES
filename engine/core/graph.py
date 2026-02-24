from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Iterable

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
class Edge:
    src: str
    dst: str
    event_id: str
    event_type: str
    ts: str | None


class ProvenanceGraph:
    """Directed provenance graph built from normalized events."""

    def __init__(self) -> None:
        self.nodes: set[str] = set()
        self.adj: dict[str, set[str]] = defaultdict(set)
        self.edges: list[Edge] = []
        self.process_parents: dict[str, set[str]] = defaultdict(set)
        self._process_ancestor_cache: dict[str, set[str]] = {}
        self._path_factor_cache: dict[str, dict[str, float]] = {}

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

    def add_event(self, event: Event) -> None:
        """Add subject/object relation from an event as a directed edge."""
        if not event.subject or not event.object:
            return

        src, dst = self._flow_direction(event)
        self.nodes.add(event.subject)
        self.nodes.add(event.object)
        self.adj[src].add(dst)
        self._path_factor_cache.clear()

        # Process lineage relation for common-ancestor checks.
        if event.event_type.lower() in {"proc_to_proc", "fork"} and self._is_process_node(event.subject) and self._is_process_node(event.object):
            self.process_parents[event.object].add(event.subject)
            self._process_ancestor_cache.clear()

        self.edges.append(
            Edge(
                src=src,
                dst=dst,
                event_id=event.event_id,
                event_type=event.event_type,
                ts=event.ts,
            )
        )

    def add_events(self, events: Iterable[Event]) -> None:
        for event in events:
            self.add_event(event)

    def has_path(self, src: str, dst: str) -> bool:
        return self.path(src, dst) is not None

    def descendants(self, node: str) -> set[str]:
        """Return directed-reachability set from node, including node itself when present."""
        if node not in self.nodes:
            return set()
        seen: set[str] = {node}
        q: deque[str] = deque([node])
        while q:
            cur = q.popleft()
            for nxt in self.adj.get(cur, set()):
                if nxt in seen:
                    continue
                seen.add(nxt)
                q.append(nxt)
        return seen

    def ancestors(self, node: str) -> set[str]:
        """Return nodes that can reach node (directed), including node itself when present."""
        if node not in self.nodes:
            return set()
        rev_adj: dict[str, set[str]] = defaultdict(set)
        for u, nbrs in self.adj.items():
            for v in nbrs:
                rev_adj[v].add(u)

        seen: set[str] = {node}
        q: deque[str] = deque([node])
        while q:
            cur = q.popleft()
            for prev in rev_adj.get(cur, set()):
                if prev in seen:
                    continue
                seen.add(prev)
                q.append(prev)
        return seen

    def shortest_path_len(self, src: str, dst: str) -> int | None:
        """
        Return shortest directed path length in edge count using BFS.

        - If no src -> dst path exists, returns None.
        - If src == dst and the node exists, returns 0.
        """
        p = self.path(src, dst)
        if p is None:
            return None
        return max(len(p) - 1, 0)

    def dependency_strength(self, src: str, dst: str) -> float:
        """
        Directed dependency strength with shortest-path attenuation.

        Spec:
        - no src -> dst path: 0.0
        - shortest_path_len == L (edge count): 1.0 / (1.0 + L)
        - one-hop path: 0.5, two-hop path: 1/3
        - src == dst (existing node): shortest_path_len=0 => strength=1.0
        """
        path_len = self.shortest_path_len(src, dst)
        if path_len is None:
            return 0.0
        return 1.0 / (1.0 + path_len)

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

        best: dict[str, float] = {src: 1.0}
        heap: list[tuple[float, str]] = [(1.0, src)]

        while heap:
            cur_pf, cur = heapq.heappop(heap)
            if cur_pf > best.get(cur, float("inf")):
                continue

            for nxt in self.adj.get(cur, set()):
                inc = 0.0
                if self._is_process_node(nxt):
                    if not (self._is_process_node(src) and self._has_common_ancestor(src, nxt)):
                        inc = 1.0
                cand = cur_pf + inc
                if cand < best.get(nxt, float("inf")):
                    best[nxt] = cand
                    heapq.heappush(heap, (cand, nxt))
        return best

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
            nbrs = self.adj.get(u, set())
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

    def path_factor(self, src: str, dst: str) -> float:
        """
        Paper-faithful path factor (default):
        - pf(src, src) = 1
        - no path from src to dst => 0.0
        - process-node transitions without common ancestor with src increase pf by 1
        - non-process transitions keep pf unchanged
        - multi-path uses minimum pf among reachable flows
        """
        if src not in self.nodes or dst not in self.nodes:
            return 0.0
        if src == dst:
            return 1.0

        if src not in self._path_factor_cache:
            self._path_factor_cache[src] = self._paper_path_factor_map(src)
        return self._path_factor_cache[src].get(dst, 0.0)

    def path(self, src: str, dst: str) -> list[str] | None:
        """Return one shortest path from src to dst if it exists."""
        if src not in self.nodes or dst not in self.nodes:
            return None
        if src == dst:
            return [src]

        queue: deque[str] = deque([src])
        parent: dict[str, str | None] = {src: None}

        while queue:
            cur = queue.popleft()
            for nxt in self.adj.get(cur, set()):
                if nxt in parent:
                    continue
                parent[nxt] = cur
                if nxt == dst:
                    rev_path = [dst]
                    node = cur
                    while node is not None:
                        rev_path.append(node)
                        node = parent[node]
                    rev_path.reverse()
                    return rev_path
                queue.append(nxt)

        return None
