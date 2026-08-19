"""
Phase 2 — Function scoring and bottom-up traversal ordering.

score(f) = depth_from_nearest_leaf(f)
         + sink_bonus            if f calls any dangerous sink
         + input_bonus           if f is input_reachable
         + low_complexity_bonus  if cyclomatic complexity <= low_complexity_threshold
         + high_complexity_bonus if cc >= high_complexity_threshold AND caller_count
                                  <= high_complexity_caller_max (mutually exclusive
                                  with low_complexity_bonus -- see note below)
         + xref_focus_score(f)   signed weight based on caller_count

Higher score = processed earlier (higher LLM priority).

`high_complexity_bonus` (added 2026-08-13, live-tested on a statically-linked
MIPS malware sample): before this, complexity only ever added score for
*small* functions, so a large, rarely-called function had nothing to
counterbalance the caller-count bonus a tiny wrapper gets just as easily --
`--suspicious`'s free ranking never surfaced the sample's actual C2-setup
function (57 basic blocks, 0 direct callers -- reached only through indirect
dispatch) above dozens of trivial 1-2-block syscall-wrapper functions that
happened to also have few callers. A function that's both substantial AND
rarely called directly is a stronger "worth a human/LLM look" signal than
either trait alone, not a weaker one. Deliberately gated on low caller count
too, not size alone -- a large function called from everywhere (e.g. a bundled
vfprintf implementation) is exactly the shared-utility case xref_focus_score
already deprioritizes, and size alone would fight that signal instead of
reinforcing it.

`sink_bonus`/`input_reachable_bonus` are import-name-driven (see
`call_graph.py`'s `dangerous_sinks`/`input_sink_apis`) and structurally
cannot fire on a statically-linked binary with no import table -- confirmed
on the same sample, which showed 0 sinks and 0 input-reachable functions
despite calling memcpy-equivalents and reading network input throughout.
Not fixed here: recognizing sinks from raw syscall numbers instead of import
names would need per-architecture instruction decoding, and a first look at
this sample showed raw syscalls aren't even a useful signal on their own --
the noise (errno/status-wrapper glue) uses them exactly as much as the real
logic does. `mapview.overview()` now says so explicitly when a graph shows
zero sinks and zero input-reachable functions, rather than leaving "0" to
read as "nothing dangerous here."

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
    elif (cc >= int(cfg.get("high_complexity_threshold", 20))
          and node.caller_count <= int(cfg.get("high_complexity_caller_max", 3))):
        # Substantial AND rarely called directly -- the C2-setup-function
        # shape (see module docstring), not the tiny-wrapper shape the low
        # branch above already rewards. `elif` is deliberate: a function
        # can't be both small and large, so these stay mutually exclusive.
        score += float(cfg.get("high_complexity_bonus", 3))

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

    Any node that never reaches in-degree 0 -- because it's *in* a call-graph
    cycle, or merely *downstream of* one anywhere in its dependency chain --
    is left over by the main loop. Those are ordered by strongly-connected
    component (see `_bottom_up_sccs`): components are still placed
    callees-before-callers wherever that's possible, and only members of the
    same true cycle fall back to score as a tiebreak, which is the
    theoretical floor -- no linear order can respect every edge inside a
    genuine cycle. A flat score sort across the whole leftover set (the
    previous approach) doesn't have this guarantee: a function can be
    swept into the leftover set purely by depending on something cyclic
    without being cyclic itself, and score alone can then place it before
    its own real callee -- verified on a real 949-function graph, ~8.5% of
    functions (81) fell into the old undifferentiated bucket, all 75 of
    that graph's ordering violations had both endpoints in it.
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

    # Leftover nodes: order by strongly-connected component, not raw score.
    remaining = set(graph.nodes) - processed
    for component in _bottom_up_sccs(graph, remaining):
        component.sort(key=lambda a: scores.get(a, 0), reverse=True)
        result.extend(component)

    return result


def _bottom_up_sccs(graph: CallGraph, node_set: set[int]) -> list[list[int]]:
    """
    Strongly-connected components of `node_set`, in callees-before-callers
    order: if some node in component A calls a node in component B (and B
    doesn't call back into A -- otherwise they'd be the same component),
    A's component is returned after B's.

    Kosaraju's algorithm, iterative (949 nodes is comfortably inside
    Python's default recursion limit, but there's no reason to depend on
    that holding for a much larger binary). Two DFS passes:
      1. DFS via callees_of, recording finish order.
      2. DFS via callers_of (the transpose), visiting in reverse finish
         order; each tree found is one SCC. Kosaraju's guarantees this
         visits caller-side components before the callee-side components
         they depend on -- the opposite of what we want -- so the final
         list of components is reversed before returning.
    """
    visited: set[int] = set()
    finish_order: list[int] = []
    for start in node_set:
        if start in visited:
            continue
        visited.add(start)
        stack = [(start, iter(c for c in graph.callees_of(start) if c in node_set))]
        while stack:
            node, it = stack[-1]
            nxt = next((c for c in it if c not in visited), None)
            if nxt is None:
                finish_order.append(node)
                stack.pop()
            else:
                visited.add(nxt)
                stack.append((nxt, iter(c for c in graph.callees_of(nxt) if c in node_set)))

    visited2: set[int] = set()
    sccs: list[list[int]] = []
    for start in reversed(finish_order):
        if start in visited2:
            continue
        visited2.add(start)
        component = [start]
        stack = [start]
        while stack:
            node = stack.pop()
            for nxt in graph.callers_of(node):
                if nxt in node_set and nxt not in visited2:
                    visited2.add(nxt)
                    component.append(nxt)
                    stack.append(nxt)
        sccs.append(component)

    sccs.reverse()
    return sccs
