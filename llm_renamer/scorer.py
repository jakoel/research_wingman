"""
Phase 2 — Function scoring and bottom-up traversal ordering.

score(f) = depth_from_nearest_leaf(f)
         + sink_bonus           if f calls any dangerous sink
         + input_bonus          if f is input_reachable
         + complexity_bonus     if cyclomatic complexity <= threshold
         + xref_focus_score(f)  signed weight based on caller_count

Higher score = processed earlier (higher LLM priority).

build_worklist() applies Kahn's topological sort so callees are always
processed before their callers (bottom-up), using score as the tiebreaker
among equally-ready nodes.
"""

from __future__ import annotations

import heapq

from .call_graph import CallGraph, CallNode


# ---------------------------------------------------------------------------
# Per-node score
# ---------------------------------------------------------------------------

def score_node(node: CallNode, config: dict) -> float:
    cfg = config.get("scoring", {})
    score = 0.0

    if node.dangerous_sink_calls:
        score += float(cfg.get("sink_bonus", 3))

    if node.input_reachable:
        score += float(cfg.get("input_reachable_bonus", 5))

    # cyclomatic complexity approximation: bb_count - 1
    cc = max(0, node.basic_block_count - 1)
    if cc <= int(cfg.get("low_complexity_threshold", 5)):
        score += float(cfg.get("low_complexity_bonus", 2))

    score += _xref_focus_score(node.caller_count, cfg)

    return score


def _xref_focus_score(caller_count: int, cfg: dict) -> float:
    """
    Translate caller_count into a signed priority bonus.

    Functions called from very few places are unique code paths where bugs
    live; functions called from many places are utility code and should be
    deprioritized without being excluded.
    """
    t = cfg.get("xref_focus_thresholds", {})
    focused_max        = int(t.get("focused_max",          3))
    focused_bonus      = float(t.get("focused_bonus",      4))
    moderate_max       = int(t.get("moderate_max",         10))
    moderate_bonus     = float(t.get("moderate_bonus",     1))
    utility_min        = int(t.get("utility_min",          51))
    utility_penalty    = float(t.get("utility_penalty",    2))
    heavy_min          = int(t.get("heavy_utility_min",    201))
    heavy_penalty      = float(t.get("heavy_utility_penalty", 5))

    if caller_count <= focused_max:
        return focused_bonus
    if caller_count <= moderate_max:
        return moderate_bonus
    if caller_count < utility_min:
        return 0.0
    if caller_count < heavy_min:
        return -utility_penalty
    return -heavy_penalty


# ---------------------------------------------------------------------------
# Depth from nearest leaf
# ---------------------------------------------------------------------------

def depth_from_leaves(graph: CallGraph) -> dict[int, int]:
    """
    Compute the depth of each node from its nearest leaf (bottom-up distance).
    Leaf = a node with no callees that are also in the graph.
    Returns {address: depth}.
    """
    depths: dict[int, int] = {}

    # Leaves start at depth 0
    for addr in graph.nodes:
        if not graph.callees_of(addr):
            depths[addr] = 0

    # Iterative upward propagation
    changed = True
    while changed:
        changed = False
        for addr in graph.nodes:
            if addr in depths:
                continue
            callee_depths = [
                depths[c] for c in graph.callees_of(addr) if c in depths
            ]
            if callee_depths:
                depths[addr] = min(callee_depths) + 1
                changed = True

    # Nodes in cycles fall back to depth 0
    for addr in graph.nodes:
        depths.setdefault(addr, 0)

    return depths


# ---------------------------------------------------------------------------
# Worklist construction
# ---------------------------------------------------------------------------

def build_worklist(graph: CallGraph, config: dict) -> list[int]:
    """
    Return function addresses in bottom-up, score-weighted processing order.

    Kahn's topological sort on the call graph, where "in-degree" counts
    unprocessed callees (so leaves become ready first).  Among equally-ready
    nodes, highest score is processed first.

    Functions involved in cycles are appended after all acyclic nodes,
    sorted by score descending.
    """
    if not graph.nodes:
        return []

    depths = depth_from_leaves(graph)
    scores: dict[int, float] = {
        addr: score_node(node, config) + float(depths.get(addr, 0))
        for addr, node in graph.nodes.items()
    }

    # In-degree = number of callees that are also in the graph
    in_degree: dict[int, int] = {
        addr: sum(1 for c in graph.callees_of(addr) if c in graph.nodes)
        for addr in graph.nodes
    }

    # Max-heap via negated score (heapq is a min-heap)
    ready: list[tuple[float, int]] = [
        (-scores.get(addr, 0), addr)
        for addr, deg in in_degree.items()
        if deg == 0
    ]
    heapq.heapify(ready)

    result: list[int] = []
    processed: set[int] = set()

    while ready:
        _, addr = heapq.heappop(ready)
        if addr in processed:
            continue
        result.append(addr)
        processed.add(addr)

        for caller in graph.callers_of(addr):
            if caller not in in_degree:
                continue
            in_degree[caller] -= 1
            if in_degree[caller] == 0:
                heapq.heappush(ready, (-scores.get(caller, 0), caller))

    # Append cycle members by score descending
    remaining = sorted(
        (addr for addr in graph.nodes if addr not in processed),
        key=lambda a: scores.get(a, 0),
        reverse=True,
    )
    result.extend(remaining)

    return result


# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------

def score_report(graph: CallGraph, config: dict, top_n: int = 20) -> list[dict]:
    """Return the top_n highest-scoring functions for diagnostic output."""
    depths = depth_from_leaves(graph)
    rows = []
    for addr, node in graph.nodes.items():
        base = score_node(node, config)
        total = base + float(depths.get(addr, 0))
        rows.append({
            "address":        f"0x{addr:X}",
            "name":           node.name,
            "score":          round(total, 1),
            "caller_count":   node.caller_count,
            "input_reachable": node.input_reachable,
            "sinks":          node.dangerous_sink_calls,
            "depth":          depths.get(addr, 0),
        })
    rows.sort(key=lambda r: r["score"], reverse=True)
    return rows[:top_n]
