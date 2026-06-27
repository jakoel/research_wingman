"""
Phase 1 — Call graph extraction.

Builds an annotated DAG from the idasql server and caches it to
call_graph.json.  Downstream phases read the cache; they never query
idasql directly for graph structure.

Node annotations
----------------
  basic_block_count     — cyclomatic complexity proxy (bb_count - 1)
  caller_count          — how many distinct functions call this one
  callee_addresses      — internal function addresses called by this one
  dangerous_sink_calls  — names of dangerous imported APIs called
  input_reachable       — true if reachable via BFS from input-API callers
  string_refs           — string literals referenced
  import_refs           — imported API names referenced
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field

from .idasql_client import IdaSQLClient, IdaSQLError


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class CallNode:
    address: int
    name: str
    size_bytes: int
    basic_block_count: int
    caller_count: int = 0
    callee_addresses: list[int] = field(default_factory=list)
    dangerous_sink_calls: list[str] = field(default_factory=list)
    input_reachable: bool = False
    string_refs: list[str] = field(default_factory=list)
    import_refs: list[str] = field(default_factory=list)


class CallGraph:
    def __init__(
        self,
        nodes: dict[int, CallNode],
        edges: list[tuple[int, int]],
    ) -> None:
        self.nodes = nodes                 # address -> CallNode
        self.edges = edges                 # [(caller, callee), ...]
        self._callees_map: dict[int, list[int]] = {}
        self._callers_map: dict[int, list[int]] = {}
        for caller, callee in edges:
            self._callees_map.setdefault(caller, []).append(callee)
            self._callers_map.setdefault(callee, []).append(caller)

    def callees_of(self, addr: int) -> list[int]:
        return self._callees_map.get(addr, [])

    def callers_of(self, addr: int) -> list[int]:
        return self._callers_map.get(addr, [])

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "nodes": {str(a): asdict(n) for a, n in self.nodes.items()},
            "edges": [[c, e] for c, e in self.edges],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "CallGraph":
        nodes = {int(k): CallNode(**v) for k, v in data["nodes"].items()}
        edges = [(int(c), int(e)) for c, e in data["edges"]]
        return cls(nodes, edges)

    def save(self, path: str) -> None:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f)
        os.replace(tmp, path)

    @classmethod
    def load(cls, path: str) -> "CallGraph":
        with open(path, "r", encoding="utf-8") as f:
            return cls.from_dict(json.load(f))


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

class CallGraphBuilder:
    """
    Queries idasql to build a fully-annotated CallGraph.
    Uses a dedicated timeout (graph.timeout_seconds) since aggregate
    queries over large binaries can take several minutes.
    """

    def __init__(self, db: IdaSQLClient, config: dict) -> None:
        self._db = db
        self._sinks: set[str] = set(
            config.get("graph", {}).get("dangerous_sinks", _DEFAULT_SINKS)
        )
        self._input_apis: set[str] = set(
            config.get("graph", {}).get("input_sink_apis", _DEFAULT_INPUT_APIS)
        )

    def build(self) -> CallGraph:
        print("[call_graph] Fetching all functions…")
        nodes = self._fetch_nodes()
        if not nodes:
            print("[call_graph] WARNING: no functions found in idasql")
            return CallGraph({}, [])

        print(f"[call_graph] {len(nodes)} functions — fetching call edges…")
        edges = self._fetch_edges(set(nodes))
        print(f"[call_graph] {len(edges)} internal call edges")

        self._annotate_caller_counts(nodes, edges)
        self._annotate_callee_lists(nodes, edges)

        print("[call_graph] Annotating dangerous-sink calls…")
        self._annotate_dangerous_sinks(nodes)

        print("[call_graph] Annotating import refs…")
        self._annotate_import_refs(nodes)

        print("[call_graph] Annotating string refs…")
        self._annotate_string_refs(nodes)

        print("[call_graph] Annotating basic-block counts…")
        self._annotate_basic_blocks(nodes)

        print("[call_graph] Computing input-reachability…")
        self._annotate_input_reachable(nodes, edges)

        return CallGraph(nodes, edges)

    # ------------------------------------------------------------------
    # Node fetch
    # ------------------------------------------------------------------

    def _fetch_nodes(self) -> dict[int, CallNode]:
        try:
            rows = self._db.query(
                "SELECT address, name, size, end_ea FROM funcs"
            )
        except IdaSQLError as e:
            print(f"[call_graph] ERROR fetching functions: {e}")
            return {}
        nodes: dict[int, CallNode] = {}
        for row in rows:
            addr = _to_int(row.get("address"))
            if addr is None:
                continue
            nodes[addr] = CallNode(
                address=addr,
                name=str(row.get("name") or f"sub_{addr:X}"),
                size_bytes=_to_int(row.get("size")) or 0,
                basic_block_count=0,
            )
        return nodes

    # ------------------------------------------------------------------
    # Edge fetch
    # ------------------------------------------------------------------

    def _fetch_edges(self, func_addrs: set[int]) -> list[tuple[int, int]]:
        edges = self._edges_via_instructions(func_addrs)
        if edges is None:
            print("[call_graph] instructions table unavailable — using range join (slower)…")
            edges = self._edges_via_range(func_addrs) or []
        return edges

    def _edges_via_instructions(
        self, func_addrs: set[int]
    ) -> list[tuple[int, int]] | None:
        try:
            rows = self._db.query("""
                SELECT DISTINCT i.func_addr AS caller, x.to_ea AS callee
                FROM xrefs x
                JOIN instructions i ON i.address = x.from_ea
                JOIN funcs f ON f.address = x.to_ea
                WHERE x.is_code = 1
                  AND i.func_addr IS NOT NULL
                  AND i.func_addr != x.to_ea
            """)
            return _rows_to_edges(rows, func_addrs)
        except IdaSQLError:
            return None

    def _edges_via_range(
        self, func_addrs: set[int]
    ) -> list[tuple[int, int]]:
        try:
            rows = self._db.query("""
                SELECT DISTINCT f1.address AS caller, f2.address AS callee
                FROM funcs f1
                JOIN xrefs x ON x.from_ea >= f1.address
                              AND x.from_ea < f1.end_ea
                JOIN funcs f2 ON f2.address = x.to_ea
                WHERE x.is_code = 1
                  AND f1.address != f2.address
            """)
            return _rows_to_edges(rows, func_addrs)
        except IdaSQLError as e:
            print(f"[call_graph] ERROR fetching edges via range join: {e}")
            return []

    # ------------------------------------------------------------------
    # Annotations
    # ------------------------------------------------------------------

    def _annotate_caller_counts(
        self, nodes: dict[int, CallNode], edges: list[tuple[int, int]]
    ) -> None:
        for _, callee in edges:
            if callee in nodes:
                nodes[callee].caller_count += 1

    def _annotate_callee_lists(
        self, nodes: dict[int, CallNode], edges: list[tuple[int, int]]
    ) -> None:
        for caller, callee in edges:
            if caller in nodes:
                nodes[caller].callee_addresses.append(callee)
        for node in nodes.values():
            node.callee_addresses = list(dict.fromkeys(node.callee_addresses))

    def _annotate_dangerous_sinks(self, nodes: dict[int, CallNode]) -> None:
        if not self._sinks:
            return
        sink_sql = ", ".join(f"'{s}'" for s in self._sinks)
        try:
            rows = self._db.query(f"""
                SELECT DISTINCT i.func_addr, imp.name AS sink_name
                FROM imports imp
                JOIN xrefs x ON x.to_ea = imp.address
                JOIN instructions i ON i.address = x.from_ea
                WHERE imp.name IN ({sink_sql})
                  AND x.is_code = 1
                  AND i.func_addr IS NOT NULL
            """)
            for row in rows:
                addr = _to_int(row.get("func_addr"))
                sink = str(row.get("sink_name") or "")
                if addr in nodes and sink:
                    nodes[addr].dangerous_sink_calls.append(sink)
        except IdaSQLError:
            pass
        for node in nodes.values():
            node.dangerous_sink_calls = list(dict.fromkeys(node.dangerous_sink_calls))

    def _annotate_import_refs(self, nodes: dict[int, CallNode]) -> None:
        try:
            rows = self._db.query("""
                SELECT i.func_addr, imp.name, imp.module
                FROM imports imp
                JOIN xrefs x ON x.to_ea = imp.address
                JOIN instructions i ON i.address = x.from_ea
                WHERE x.is_code = 1
                  AND i.func_addr IS NOT NULL
            """)
            for row in rows:
                addr = _to_int(row.get("func_addr"))
                name = str(row.get("name") or "")
                module = str(row.get("module") or "")
                if addr in nodes and name:
                    ref = f"{module}!{name}" if module else name
                    nodes[addr].import_refs.append(ref)
        except IdaSQLError:
            pass
        for node in nodes.values():
            node.import_refs = list(dict.fromkeys(node.import_refs[:20]))

    def _annotate_string_refs(self, nodes: dict[int, CallNode]) -> None:
        try:
            rows = self._db.query("""
                SELECT i.func_addr, s.content
                FROM strings s
                JOIN xrefs x ON x.to_ea = s.address
                JOIN instructions i ON i.address = x.from_ea
                WHERE i.func_addr IS NOT NULL
            """)
            for row in rows:
                addr = _to_int(row.get("func_addr"))
                content = str(row.get("content") or "")
                if addr in nodes and len(content.strip()) >= 2:
                    nodes[addr].string_refs.append(content.strip())
        except IdaSQLError:
            pass
        for node in nodes.values():
            node.string_refs = list(dict.fromkeys(node.string_refs[:20]))

    def _annotate_basic_blocks(self, nodes: dict[int, CallNode]) -> None:
        try:
            rows = self._db.query(
                "SELECT func_ea, COUNT(*) AS n FROM blocks GROUP BY func_ea"
            )
            for row in rows:
                addr = _to_int(row.get("func_ea"))
                n = _to_int(row.get("n") or row.get("COUNT(*)")) or 0
                if addr in nodes:
                    nodes[addr].basic_block_count = n
        except IdaSQLError:
            pass

    def _annotate_input_reachable(
        self, nodes: dict[int, CallNode], edges: list[tuple[int, int]]
    ) -> None:
        if not self._input_apis:
            return

        api_sql = ", ".join(f"'{a}'" for a in self._input_apis)
        seeds: set[int] = set()
        try:
            rows = self._db.query(f"""
                SELECT DISTINCT i.func_addr
                FROM imports imp
                JOIN xrefs x ON x.to_ea = imp.address
                JOIN instructions i ON i.address = x.from_ea
                WHERE imp.name IN ({api_sql})
                  AND x.is_code = 1
                  AND i.func_addr IS NOT NULL
            """)
            for row in rows:
                addr = _to_int(next(iter(row.values()), None))
                if addr in nodes:
                    seeds.add(addr)
        except IdaSQLError:
            return

        if not seeds:
            return

        # BFS forward (callee direction): mark everything called by input-reading
        # functions as potentially processing user-controlled data.
        callees_map: dict[int, list[int]] = {}
        for caller, callee in edges:
            callees_map.setdefault(caller, []).append(callee)

        visited: set[int] = set()
        queue = list(seeds)
        while queue:
            addr = queue.pop()
            if addr in visited:
                continue
            visited.add(addr)
            if addr in nodes:
                nodes[addr].input_reachable = True
            for callee in callees_map.get(addr, []):
                if callee not in visited:
                    queue.append(callee)

        print(f"[call_graph] {len(visited)} functions marked input-reachable")


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def load_or_build(
    db: IdaSQLClient,
    config: dict,
    cache_path: str,
    force_rebuild: bool = False,
) -> CallGraph:
    """
    Load the call graph from cache if available; otherwise build and cache it.
    Pass force_rebuild=True (or --rebuild-graph CLI flag) to discard the cache.
    """
    if not force_rebuild and os.path.exists(cache_path):
        print(f"[call_graph] Loading cached graph from {cache_path}…")
        try:
            g = CallGraph.load(cache_path)
            print(
                f"[call_graph] Loaded {len(g.nodes)} nodes, "
                f"{len(g.edges)} edges from cache"
            )
            return g
        except Exception as e:
            print(f"[call_graph] Cache invalid ({e}) — rebuilding…")

    # Build with a longer timeout than standard idasql queries
    graph_timeout = int(config.get("graph", {}).get("timeout_seconds", 300))
    graph_config = {
        **config,
        "idasql": {**config["idasql"], "timeout_seconds": graph_timeout},
    }
    graph_db = IdaSQLClient(graph_config)

    graph = CallGraphBuilder(graph_db, config).build()
    graph.save(cache_path)
    print(
        f"[call_graph] Graph saved to {cache_path} "
        f"({len(graph.nodes)} nodes, {len(graph.edges)} edges)"
    )
    return graph


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _to_int(v) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _rows_to_edges(
    rows: list[dict], func_addrs: set[int]
) -> list[tuple[int, int]]:
    seen: set[tuple[int, int]] = set()
    edges = []
    for row in rows:
        caller = _to_int(row.get("caller") or row.get("caller_addr"))
        callee = _to_int(row.get("callee") or row.get("callee_addr"))
        if caller is None or callee is None:
            continue
        if caller not in func_addrs or callee not in func_addrs:
            continue
        pair = (caller, callee)
        if pair not in seen:
            seen.add(pair)
            edges.append(pair)
    return edges


# ---------------------------------------------------------------------------
# Defaults (overridable in config.json)
# ---------------------------------------------------------------------------

_DEFAULT_SINKS = [
    "memcpy", "memmove", "strcpy", "strcat", "sprintf", "vsprintf",
    "gets", "recv", "recvfrom", "read", "malloc", "realloc", "free",
]

_DEFAULT_INPUT_APIS = [
    "recv", "recvfrom", "read", "fgets", "fread",
    "WSARecv", "ReadFile", "getchar", "scanf", "fscanf",
]
