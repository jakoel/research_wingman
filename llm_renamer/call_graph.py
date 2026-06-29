"""
Phase 1 — Call graph extraction.

Builds an annotated DAG directly from the open IDA database using the
IDA Python API and caches it to call_graph.json.  Downstream phases read
the cache; they do not re-query IDA for graph structure.

All IDA modules are imported lazily inside methods (must be called after
idapro.open_database()).
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field

from .idapro_client import FunctionContextExtractor


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
        self.nodes = nodes
        self.edges = edges
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
    Builds a fully-annotated CallGraph from the open IDA database.

    Shares the import/string caches from the FunctionContextExtractor so
    they are built only once across Phase 1 and Phase 3.
    """

    def __init__(self, extractor: FunctionContextExtractor, config: dict) -> None:
        self._ext = extractor
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
            print("[call_graph] WARNING: no functions found")
            return CallGraph({}, [])

        func_addrs = set(nodes)
        print(f"[call_graph] {len(nodes)} functions — collecting edges and annotations…")
        edges = self._single_pass(nodes, func_addrs)
        print(f"[call_graph] {len(edges)} internal call edges")

        self._annotate_caller_counts(nodes, edges)
        self._annotate_callee_lists(nodes, edges)

        print("[call_graph] Annotating basic-block counts…")
        self._annotate_basic_blocks(nodes)

        print("[call_graph] Computing input-reachability…")
        self._annotate_input_reachable(nodes, edges)

        return CallGraph(nodes, edges)

    # ------------------------------------------------------------------
    # Node fetch
    # ------------------------------------------------------------------

    def _fetch_nodes(self) -> dict[int, CallNode]:
        import idautils, idc, ida_funcs
        nodes: dict[int, CallNode] = {}
        for ea in idautils.Functions():
            func = ida_funcs.get_func(ea)
            nodes[ea] = CallNode(
                address=ea,
                name=idc.get_func_name(ea) or f"sub_{ea:X}",
                size_bytes=(func.end_ea - func.start_ea) if func else 0,
                basic_block_count=0,
            )
        return nodes

    # ------------------------------------------------------------------
    # Single-pass annotation
    # ------------------------------------------------------------------

    def _single_pass(
        self,
        nodes: dict[int, CallNode],
        func_addrs: set[int],
    ) -> list[tuple[int, int]]:
        """
        One pass over all instructions to collect:
          - internal call edges
          - per-function import refs and dangerous-sink calls
          - per-function string refs

        Reuses the extractor's caches so _build_import_cache and
        _build_string_cache are not called again in Phase 3.
        """
        import idautils
        import_map = self._ext._import_map()
        string_map = self._ext._string_map()

        seen_edges: set[tuple[int, int]] = set()
        edges: list[tuple[int, int]] = []

        for caller_ea in func_addrs:
            node = nodes[caller_ea]
            seen_imports: set[int] = set()
            seen_strings: set[int] = set()

            for item in idautils.FuncItems(caller_ea):
                for xref in idautils.XrefsFrom(item, 0):
                    to = xref.to

                    if xref.iscode:
                        if to != caller_ea and to in func_addrs:
                            pair = (caller_ea, to)
                            if pair not in seen_edges:
                                seen_edges.add(pair)
                                edges.append(pair)
                        elif to in import_map and to not in seen_imports:
                            seen_imports.add(to)
                            module, name = import_map[to]
                            ref = f"{module}!{name}" if module else name
                            node.import_refs.append(ref)
                            if name in self._sinks:
                                node.dangerous_sink_calls.append(name)
                    else:
                        if to in string_map and to not in seen_strings:
                            seen_strings.add(to)
                            node.string_refs.append(string_map[to])

        for node in nodes.values():
            node.import_refs = list(dict.fromkeys(node.import_refs[:20]))
            node.dangerous_sink_calls = list(dict.fromkeys(node.dangerous_sink_calls))
            node.string_refs = list(dict.fromkeys(node.string_refs[:20]))

        return edges

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

    def _annotate_basic_blocks(self, nodes: dict[int, CallNode]) -> None:
        import ida_funcs, ida_gdl
        for ea, node in nodes.items():
            func = ida_funcs.get_func(ea)
            if func:
                try:
                    node.basic_block_count = sum(1 for _ in ida_gdl.FlowChart(func))
                except Exception:
                    pass

    def _annotate_input_reachable(
        self, nodes: dict[int, CallNode], edges: list[tuple[int, int]]
    ) -> None:
        if not self._input_apis:
            return

        # Seed: any function that directly calls a known input-ingestion API.
        seeds: set[int] = set()
        for addr, node in nodes.items():
            for ref in node.import_refs:
                # ref format is "module!name" or just "name"
                api_name = ref.split("!")[-1]
                if api_name in self._input_apis:
                    seeds.add(addr)
                    break

        if not seeds:
            return

        # BFS forward (callee direction) from seeds.
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
    extractor: FunctionContextExtractor,
    config: dict,
    cache_path: str,
    force_rebuild: bool = False,
) -> CallGraph:
    """
    Load the call graph from cache if available; otherwise build it via the
    IDA Python API and write the cache.  Pass force_rebuild=True (or
    --rebuild-graph) to discard the cache.
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

    graph = CallGraphBuilder(extractor, config).build()
    graph.save(cache_path)
    print(
        f"[call_graph] Graph saved to {cache_path} "
        f"({len(graph.nodes)} nodes, {len(graph.edges)} edges)"
    )
    return graph


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
