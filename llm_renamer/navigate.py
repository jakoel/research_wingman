"""
Graph navigation — the map layer.

Everything here runs against the cached call graph. No LLM calls, no open IDA
database. This is what a researcher browses to decide *where* to spend LLM
calls, which is the expensive part.

The graph already carries per-function annotations built during the single
instruction pass: dangerous sink calls, input reachability, referenced strings
and imports, caller counts. Those are the triage signal.
"""

from __future__ import annotations

from collections import deque

from .call_graph import CallGraph, CallNode
from .scorer import depth_from_leaves, score_node

# Names IDA gives to things that start execution.
_ENTRY_NAMES = (
    "main", "wmain", "winmain", "wwinmain", "dllmain",
    "start", "_start", "tlscallback", "dllentrypoint", "entry",
)


# ---------------------------------------------------------------------------
# Selection primitives
# ---------------------------------------------------------------------------

def descendants(graph: CallGraph, addr: int, depth: int = 2) -> list[int]:
    """`addr` plus everything it calls, up to `depth` hops down."""
    return _bfs(graph, addr, depth, graph.callees_of)


def ancestors(graph: CallGraph, addr: int, depth: int = 2) -> list[int]:
    """`addr` plus everything that calls it, up to `depth` hops up."""
    return _bfs(graph, addr, depth, graph.callers_of)


def _bfs(graph: CallGraph, start: int, depth: int, neighbours) -> list[int]:
    seen = {start}
    order = [start]
    frontier = deque([(start, 0)])
    while frontier:
        node, d = frontier.popleft()
        if d >= depth:
            continue
        for nxt in neighbours(node):
            if nxt in seen or nxt not in graph.nodes:
                continue
            seen.add(nxt)
            order.append(nxt)
            frontier.append((nxt, d + 1))
    return order


def shortest_path(graph: CallGraph, src: int, dst: int,
                  max_depth: int = 24) -> list[int]:
    """Shortest call path src → dst, or [] if there isn't one."""
    if src == dst:
        return [src]
    prev: dict[int, int] = {src: src}
    frontier = deque([(src, 0)])
    while frontier:
        node, d = frontier.popleft()
        if d >= max_depth:
            continue
        for nxt in graph.callees_of(node):
            if nxt in prev or nxt not in graph.nodes:
                continue
            prev[nxt] = node
            if nxt == dst:
                return _rebuild(prev, src, dst)
            frontier.append((nxt, d + 1))
    return []


def _rebuild(prev: dict[int, int], src: int, dst: int) -> list[int]:
    path = [dst]
    while path[-1] != src:
        path.append(prev[path[-1]])
    path.reverse()
    return path


def paths_between(graph: CallGraph, src: int, dst: int,
                  max_depth: int = 12, max_paths: int = 10) -> list[list[int]]:
    """
    Up to `max_paths` distinct call paths src → dst, shortest first.
    Bounded on purpose: a dense graph has effectively unlimited paths.
    """
    results: list[list[int]] = []
    stack = [(src, [src])]
    while stack and len(results) < max_paths:
        node, path = stack.pop(0)
        if len(path) > max_depth:
            continue
        for nxt in graph.callees_of(node):
            if nxt in path or nxt not in graph.nodes:
                continue
            if nxt == dst:
                results.append(path + [nxt])
                if len(results) >= max_paths:
                    break
            else:
                stack.append((nxt, path + [nxt]))
    return results


# ---------------------------------------------------------------------------
# Landmarks
# ---------------------------------------------------------------------------

def entry_points(graph: CallGraph) -> list[int]:
    """
    Where execution plausibly starts: recognisable entry names first, then
    anything nothing else calls.
    """
    named, orphans = [], []
    for addr, node in graph.nodes.items():
        lowered = node.name.lower().lstrip("_")
        if any(lowered.startswith(n) for n in _ENTRY_NAMES):
            named.append(addr)
        elif node.caller_count == 0:
            orphans.append(addr)
    named.sort(key=lambda a: graph.nodes[a].name)
    orphans.sort(key=lambda a: -graph.nodes[a].size_bytes)
    return named + orphans


def sink_callers(graph: CallGraph) -> list[int]:
    """Functions that call a dangerous sink directly."""
    return [a for a, n in graph.nodes.items() if n.dangerous_sink_calls]


def input_reachable(graph: CallGraph) -> list[int]:
    return [a for a, n in graph.nodes.items() if n.input_reachable]


def paths_to_sinks(graph: CallGraph, config: dict, *, limit: int = 15,
                   start: int | None = None) -> list[list[int]]:
    """
    Shortest path from an entry point (or `start`) down to each of the
    highest-scoring sink-calling functions. This is the "how does attacker
    data reach memcpy" view.
    """
    sources = [start] if start is not None else entry_points(graph)[:12]
    if not sources:
        return []

    ranked = sorted(
        sink_callers(graph),
        key=lambda a: score_node(graph.nodes[a], config),
        reverse=True,
    )

    paths: list[list[int]] = []
    for sink in ranked:
        if len(paths) >= limit:
            break
        for src in sources:
            path = shortest_path(graph, src, sink)
            if path and len(path) > 1:
                paths.append(path)
                break
    return paths


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------

def find(graph: CallGraph, query: str, limit: int = 40) -> dict[str, list[int]]:
    """
    Search the cached graph annotations. Returns matches grouped by what
    matched: function name, referenced string, or imported API.
    """
    q = query.strip().lower()
    hits: dict[str, list[int]] = {"name": [], "string": [], "import": []}
    if not q:
        return hits

    # A bare address is a direct lookup.
    if q.startswith("0x"):
        try:
            addr = int(q, 16)
            if addr in graph.nodes:
                hits["name"].append(addr)
                return hits
        except ValueError:
            pass

    for addr, node in graph.nodes.items():
        if q in node.name.lower():
            hits["name"].append(addr)
        elif any(q in s.lower() for s in node.string_refs):
            hits["string"].append(addr)
        elif any(q in i.lower() for i in node.import_refs):
            hits["import"].append(addr)

    for key in hits:
        hits[key] = hits[key][:limit]
    return hits


def top_scored(graph: CallGraph, config: dict, n: int = 50) -> list[int]:
    """The n highest-scoring functions — the default 'what should I look at'."""
    depths = depth_from_leaves(graph)
    ranked = sorted(
        graph.nodes,
        key=lambda a: score_node(graph.nodes[a], config) + float(depths.get(a, 0)),
        reverse=True,
    )
    return ranked[:n]


def unnamed_only(graph: CallGraph, addresses: list[int], config: dict) -> list[int]:
    """Filter a selection down to still-auto-named functions."""
    prefixes = tuple(config["policy"]["auto_generated_prefixes"])
    return [a for a in addresses
            if a in graph.nodes and graph.nodes[a].name.startswith(prefixes)]


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def describe(graph: CallGraph, addr: int, config: dict | None = None) -> str:
    """One dense line about a function, from graph data only."""
    node = graph.nodes.get(addr)
    if node is None:
        return f"0x{addr:X}  (not in graph)"
    flags = []
    if node.input_reachable:
        flags.append("INPUT")
    if node.dangerous_sink_calls:
        flags.append("SINK:" + ",".join(node.dangerous_sink_calls[:3]))
    score = f"{score_node(node, config):>5.1f}" if config else "     "
    return (f"  0x{addr:<12X} {node.name[:34]:<34} {score}  "
            f"callers={node.caller_count:<5} bb={node.basic_block_count:<4} "
            f"{' '.join(flags)}")


def describe_path(graph: CallGraph, path: list[int]) -> str:
    return "\n".join(
        f"    {'  ' * i}{'└─ ' if i else ''}"
        f"0x{a:X}  {graph.nodes[a].name if a in graph.nodes else '?'}"
        + (f"   [{','.join(graph.nodes[a].dangerous_sink_calls[:2])}]"
           if a in graph.nodes and graph.nodes[a].dangerous_sink_calls else "")
        for i, a in enumerate(path)
    )
