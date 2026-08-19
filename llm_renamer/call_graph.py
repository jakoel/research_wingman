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
    constant_operands: list[int] = field(default_factory=list)


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
# Constant-operand extraction
# ---------------------------------------------------------------------------

# Values at or below this magnitude are near-universal (loop increments, null
# checks, small struct offsets) and would swamp the signal if tracked -- this
# is meant to catch changed buffer sizes / thresholds / bitmasks / magic
# numbers, the class of thing that actually indicates a patched logic change
# (e.g. a changed allocation-size constant, `352 * a2` -> `a2 << 9`), not
# every literal in the function.
_CONST_MIN_ABS = 16
_INT64_MASK = (1 << 64) - 1
_INT64_SIGN_BIT = 1 << 63


def _to_signed64(value: int) -> int:
    """`idc.get_operand_value` doesn't consistently sign-extend -- a small
    negative immediate like -1 or -512 in a 64-bit-mode instruction can come
    back as the raw unsigned 64-bit encoding (18446744073709551615,
    18446744073709551104) instead of -1/-512. Confirmed live 2026-08-11
    against real clfs.sys functions: without this, those slipped straight
    past the `_CONST_MIN_ABS` magnitude filter (abs() of a huge unsigned
    value is still huge) as if they were large, meaningful constants, when
    they're actually tiny near-universal ones that should be filtered out
    same as any other small value."""
    value &= _INT64_MASK
    if value & _INT64_SIGN_BIT:
        value -= 1 << 64
    return value


def _extract_constants(ea: int) -> list[int]:
    """Immediate operands at one instruction address, excluding anything IDA
    has already resolved to a symbolic address/offset reference (`is_off` --
    e.g. `mov rax, offset g_SomeGlobal`; these trivially differ between two
    builds due to relocation/section-layout, not a logic change) and anything
    at or below `_CONST_MIN_ABS`. Deliberately narrow to `o_imm` (literal
    immediates used directly in comparisons/arithmetic/bitmasks) rather than
    displacement/memory operands, which are compiler-arbitrary (stack offsets,
    struct-field offsets can shift on a recompile with zero logic change)."""
    import idc, ida_bytes
    out: list[int] = []
    flags = idc.get_full_flags(ea)
    for n in range(8):  # generous upper bound on operand count; extra slots are o_void, skipped below
        if idc.get_operand_type(ea, n) != idc.o_imm:
            continue
        if ida_bytes.is_off(flags, n):
            continue
        value = _to_signed64(idc.get_operand_value(ea, n))
        if abs(value) > _CONST_MIN_ABS:
            out.append(value)
    return out


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
        graph_cfg = config.get("graph", {})
        self._sinks: set[str] = set(
            graph_cfg.get("dangerous_sinks", _DEFAULT_SINKS)
        )
        self._input_apis: set[str] = set(
            graph_cfg.get("input_sink_apis", _DEFAULT_INPUT_APIS)
        )
        self._max_import_refs = int(graph_cfg.get("max_import_refs_per_node", 20))
        self._max_string_refs = int(graph_cfg.get("max_string_refs_per_node", 20))
        self._max_constant_operands = int(graph_cfg.get("max_constant_operands_per_node", 64))
        # Detected inline during _single_pass, BEFORE node.import_refs gets
        # capped -- same reasoning as dangerous_sink_calls (collected there
        # unconditionally too): a function calling >max_import_refs distinct
        # imports, where the real input-ingestion API happens to sit past
        # the cap in address order, must not silently lose its
        # input_reachable seed status. Confirmed real 2026-08-16.
        self._input_seeds: set[int] = set()

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
                node.constant_operands.extend(_extract_constants(item))
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
                            if name in self._input_apis:
                                self._input_seeds.add(caller_ea)
                    else:
                        if to in string_map and to not in seen_strings:
                            seen_strings.add(to)
                            node.string_refs.append(string_map[to])

        for node in nodes.values():
            node.import_refs = list(dict.fromkeys(node.import_refs[:self._max_import_refs]))
            node.dangerous_sink_calls = list(dict.fromkeys(node.dangerous_sink_calls))
            node.string_refs = list(dict.fromkeys(node.string_refs[:self._max_string_refs]))
            # Sorted+capped for a stable, bounded field: a diff tool only needs
            # to know THAT the constant set differs between old/patched, not
            # every constant in a huge function -- see autopair.classify.
            node.constant_operands = sorted(set(node.constant_operands))[:self._max_constant_operands]

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

        # Seeds detected inline in _single_pass, before import_refs was
        # capped -- see __init__'s comment on self._input_seeds. NOT
        # re-derived from node.import_refs here (that field can be
        # truncated for a high-fanout function, which would silently drop
        # a real seed).
        seeds = self._input_seeds
        if not seeds:
            return

        # DFS forward (callee direction) from seeds -- queue.pop() below is
        # LIFO. Traversal order doesn't matter for this boolean reachability
        # flag (the final visited set is identical either way), but call it
        # what it is in case depth-limiting is ever added here later.
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
    IDA Python API and write the cache.  Pass force_rebuild=True (what
    `research_wingman.py map <db> --build` does) to discard the cache.
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


def update_cached_names(cache_path: str, renames: dict[int, str]) -> None:
    """
    Patch the cached graph's node names in place after `apply` renames
    functions in the database.

    The cache only records names as of the last full `map --build`, so without
    this every function you rename goes stale in the cache and reads back as
    `sub_...` in every map view, search (`--find`), and the unnamed filter that
    feeds `--suspicious`/`--top`. Rather than make each of those consumers
    reconcile against the KB, keep the cache itself correct for applied
    renames -- the graph *structure* (edges, sinks, bb counts) is untouched by
    a rename, only the names change, so a targeted name patch is exact.

    Best-effort: a failure here never matters to correctness (the rename is
    already safely in the database and the KB), it just leaves the cache stale
    as before, so all errors are swallowed.
    """
    if not renames or not os.path.exists(cache_path):
        return
    try:
        graph = CallGraph.load(cache_path)
        changed = False
        for addr, name in renames.items():
            node = graph.nodes.get(addr)
            if node is not None and name and node.name != name:
                node.name = name
                changed = True
        if changed:
            graph.save(cache_path)
    except Exception:
        pass


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
