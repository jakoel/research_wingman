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

from .call_graph import CallGraph
from .scorer import depth_from_leaves, score_node

# Names IDA gives to things that start execution.
_ENTRY_NAMES = (
    "main", "wmain", "winmain", "wwinmain", "dllmain",
    "start", "_start", "tlscallback", "dllentrypoint", "entry",
)


# ---------------------------------------------------------------------------
# Selection primitives
# ---------------------------------------------------------------------------

def descendants(graph: CallGraph, addr: int, depth: int | None = 2) -> list[int]:
    """`addr` plus everything it calls, up to `depth` hops down.

    `depth=None` walks all the way to true leaves (cycle-safe via `seen`).
    """
    return _bfs(graph, addr, depth, graph.callees_of)


def _bfs(graph: CallGraph, start: int, depth: int | None, neighbours) -> list[int]:
    seen = {start}
    order = [start]
    frontier = deque([(start, 0)])
    while frontier:
        node, d = frontier.popleft()
        if depth is not None and d >= depth:
            continue
        for nxt in neighbours(node):
            if nxt in seen or nxt not in graph.nodes:
                continue
            seen.add(nxt)
            order.append(nxt)
            frontier.append((nxt, d + 1))
    return order


def full_subtree(graph: CallGraph, addrs: list[int]) -> list[int]:
    """
    `addrs` plus the FULL callee subtree of each, down to true leaves.

    This is the project's standard scope-expansion pattern, used everywhere a
    scope selects a set of "targets": `-f`, `--top N`. Never hand the LLM a
    target whose real dependencies aren't
    also in scope to be analyzed first, leaves-first (`build_worklist`
    already orders any selection bottom-up) -- a target analyzed against bare,
    unsummarized callee names instead of real summaries measurably hurts
    confidence and grounding, exactly the failure mode a partial one-hop
    expansion (the previous approach here) still left open for anything
    beyond the immediate neighbours.

    Callers are handled separately (`prompts.build_user_prompt` injects KB
    summaries for whichever direct callers are already analyzed) rather than
    walked upward here -- this function is specifically the *downward*, to-
    the-leaves half of the pattern.
    """
    expanded = list(addrs)
    seen = set(addrs)
    for a in addrs:
        for d in descendants(graph, a, depth=None):
            if d not in seen:
                seen.add(d)
                expanded.append(d)
    return expanded


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

    # Depth term included to match top_scored()/build_worklist()'s own
    # "score" formula -- score_node() alone is a different, incomplete
    # ranking (confirmed real 2026-08-16: this used to silently diverge
    # from what "score" means everywhere else in the tool).
    depths = depth_from_leaves(graph)
    ranked = sorted(
        sink_callers(graph),
        key=lambda a: score_node(graph.nodes[a], config) + float(depths.get(a, 0)),
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
    """Filter a selection down to analysis candidates (still-unnamed `sub_`)."""
    prefixes = tuple(config["policy"].get("analysis_candidate_prefixes", ["sub_"]))
    return [a for a in addresses
            if a in graph.nodes and graph.nodes[a].name.startswith(prefixes)]


def resolve_one(
    graph: CallGraph | None, name: str, extractor=None, config: dict | None = None,
    workspace=None,
) -> int | None:
    """
    Turn typed input (a name or `0xADDR`) into an address: hex-parse,
    exact-match, partial-match, then an extractor/KB fallback chain.
    """
    if name.lower().startswith("0x"):
        try:
            return int(name, 16)
        except ValueError:
            pass
    if graph is not None:
        exact = [a for a, n in graph.nodes.items() if n.name == name]
        if exact:
            return exact[0]
        partial = [a for a, n in graph.nodes.items() if name.lower() in n.name.lower()]
        if len(partial) == 1:
            return partial[0]
        if len(partial) > 1:
            print(f"  {name!r} matches {len(partial)} functions — showing the first 10:")
            for a in partial[:10]:
                print(describe(graph, a, config))
            return None
    if extractor is not None:
        rows = extractor.get_functions_by_name([name])
        if rows:
            return int(rows[0]["address"])
    if workspace is not None:
        addr = _resolve_via_kb(workspace, name)
        if addr is not None:
            return addr
    print(f"  Not found: {name!r}")
    return None


def _resolve_via_kb(workspace, name: str) -> int | None:
    """
    Fall back to the knowledge base's new_name -> address mapping.

    The cached call graph only knows each function's name as of the last
    `map --build`; anything renamed and applied since then is invisible to
    it, and `map` commands never open IDA (no extractor fallback either) --
    so without this, a function becomes unfindable by name the moment you
    rename it. The KB is updated the instant `apply` runs and needs no IDA
    session to query.
    """
    import os
    if not os.path.exists(workspace.kb):
        return None
    from .kb import KnowledgeBase
    kb = KnowledgeBase(workspace.kb)
    try:
        matches = [r for r in kb.get_all() if r.get("new_name") == name]
        if len(matches) == 1:
            try:
                return int(matches[0]["address"], 16)
            except (TypeError, ValueError):
                return None
        if len(matches) > 1:
            print(f"  {name!r} matches {len(matches)} applied renames — be more specific.")
        return None
    finally:
        kb.close()


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def describe(graph: CallGraph, addr: int, config: dict | None = None,
             name_override: str | None = None,
             depths: dict[int, int] | None = None) -> str:
    """One dense line about a function.

    `name_override` lets a caller show the function's *current* name (from the
    knowledge base) instead of the graph's cached one -- the cached graph only
    knows names as of the last `map --build`, so without this a function you've
    already renamed still displays as `sub_...` in every map view, which reads
    as the tool having forgotten what you just did.

    `depths` (from `scorer.depth_from_leaves`) adds the depth-from-nearest-leaf
    term to the displayed score, matching what `top_scored`/`build_worklist`
    actually rank by -- omitted here (falls back to depth-excluded), the
    printed score can be non-monotonic against a "Top N by score" view's own
    sort order (confirmed real 2026-08-16: describe() and top_scored() used
    to compute genuinely different formulas for the same "score").
    """
    node = graph.nodes.get(addr)
    if node is None:
        return f"0x{addr:X}  (not in graph)"
    flags = []
    if node.input_reachable:
        flags.append("INPUT")
    if node.dangerous_sink_calls:
        flags.append("SINK:" + ",".join(node.dangerous_sink_calls[:3]))
    if config:
        total = score_node(node, config) + float((depths or {}).get(addr, 0))
        score = f"{total:>5.1f}"
    else:
        score = "     "
    display_name = name_override or node.name
    return (f"  0x{addr:<12X} {display_name[:34]:<34} {score}  "
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
