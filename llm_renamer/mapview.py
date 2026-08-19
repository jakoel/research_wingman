"""
Rendering for the map layer.

Every view here reads the cached call graph (and the knowledge base, when a
function has already been analyzed). None of it opens IDA or calls the LLM, so
it is instant and free — this is where a researcher decides what is worth
spending LLM calls on.
"""

from __future__ import annotations

import os

from . import navigate
from .call_graph import CallGraph
from .kb import KnowledgeBase, addr_to_hex
from .scorer import depth_from_leaves
from .workspace import Workspace

_SEP = "─" * 76


def load_graph(workspace: Workspace) -> CallGraph | None:
    if not workspace.has_graph():
        print(f"[wingman] No call graph yet for {os.path.basename(workspace.db_path)}.")
        print("[wingman] Build it once (needs IDA, takes minutes):  "
              f"research_wingman.py map {os.path.basename(workspace.db_path)} --build")
        return None
    return CallGraph.load(workspace.call_graph)


def _kb_map(workspace: Workspace, addresses) -> dict[str, dict]:
    """Analyzed KB rows for these addresses, keyed by hex address."""
    if not os.path.exists(workspace.kb):
        return {}
    kb = KnowledgeBase(workspace.kb)
    try:
        rows = kb._by_addresses(list(addresses))
    finally:
        kb.close()
    return {r["address"]: r for r in rows}


def _line(graph: CallGraph, addr: int, config: dict, known: dict,
          depths: dict[int, int] | None = None) -> str:
    entry = known.get(addr_to_hex(addr))
    # Show the current (KB) name on the primary line when we have one, so a
    # map view reflects what you've learned rather than the stale graph name.
    name_override = None
    if entry:
        name_override = entry.get("new_name") or entry.get("old_name") or None
    out = navigate.describe(graph, addr, config, name_override=name_override,
                            depths=depths)
    if entry:
        if entry.get("security_relevant"):
            out += " [SEC]"   # triage marker, doubles as a scan cue in lists
        summary = (entry.get("summary") or "").strip()
        if summary:
            out += f"\n{'':>17}{summary}"
    return out


def _render(graph: CallGraph, addresses, config: dict,
            workspace: Workspace, title: str, limit: int = 40) -> None:
    addresses = list(addresses)[:limit]
    known = _kb_map(workspace, addresses)
    # Computed once per render call, not per line -- depth_from_leaves walks
    # the whole graph, so per-line would be O(n^2) over a large map view.
    # Needed so the printed score matches what top_scored() actually sorted
    # by (see navigate.describe's docstring).
    depths = depth_from_leaves(graph)
    print(f"\n{title}")
    print(_SEP)
    if not addresses:
        print("  (nothing)")
    for addr in addresses:
        print(_line(graph, addr, config, known, depths=depths))
    print(_SEP)
    print(f"  {len(addresses)} shown")


# ---------------------------------------------------------------------------
# Views
# ---------------------------------------------------------------------------

def overview(graph: CallGraph, config: dict, workspace: Workspace) -> None:
    """The landing page: how big is this thing and where are the landmarks."""
    nodes = graph.nodes
    prefixes = tuple(config["policy"]["auto_generated_prefixes"])
    unnamed = sum(1 for n in nodes.values() if n.name.startswith(prefixes))
    entries = navigate.entry_points(graph)
    sinks = navigate.sink_callers(graph)
    inputs = navigate.input_reachable(graph)

    analyzed = 0
    if os.path.exists(workspace.kb):
        kb = KnowledgeBase(workspace.kb)
        analyzed = kb.stats()["analyzed"]
        kb.close()

    print(f"\n  {os.path.basename(workspace.db_path)}")
    print(_SEP)
    print(f"  Functions          : {len(nodes)}")
    print(f"  Still auto-named   : {unnamed}")
    print(f"  Analyzed so far    : {analyzed}")
    print(_SEP)
    print(f"  Entry points       : {len(entries)}")
    print(f"  Call a memory sink : {len(sinks)}")
    print(f"  Input-reachable    : {len(inputs)}")
    if not sinks and not inputs and not any(n.import_refs for n in nodes.values()):
        print("  NOTE: no imports at all were recognized -- this looks "
              "statically linked. Sink/input-reachable scoring is import-name-\n"
              "        driven and cannot see anything on a binary like this, "
              "so those 0s mean \"undetectable\", not \"absent\". --suspicious\n"
              "        still works (structure-based), but treat it as the "
              "only free signal available, not confirmation nothing's dangerous.")
    print(_SEP)

    known = _kb_map(workspace, entries[:10])
    print("\n  Entry points:")
    for addr in entries[:10]:
        print(_line(graph, addr, config, known))

    print("\n  Most-referenced imports:")
    counts: dict[str, int] = {}
    for node in nodes.values():
        for imp in node.import_refs:
            counts[imp] = counts.get(imp, 0) + 1
    for imp, n in sorted(counts.items(), key=lambda kv: -kv[1])[:12]:
        print(f"    {n:>5}×  {imp}")
    print()


def suspicious(graph: CallGraph, config: dict, workspace: Workspace,
               top: int = 25, unnamed_only: bool = False) -> list[int]:
    pool_multiplier = int(config.get("scoring", {}).get("candidate_pool_multiplier", 3))
    addresses = navigate.top_scored(graph, config, top * pool_multiplier)
    if unnamed_only:
        addresses = navigate.unnamed_only(graph, addresses, config)
    addresses = addresses[:top]
    _render(graph, addresses, config, workspace,
            f"Top {len(addresses)} by score "
            f"(focused xrefs · memory sinks · input-reachable)", limit=top)
    return addresses


def find(graph: CallGraph, config: dict, workspace: Workspace,
         query: str) -> list[int]:
    hits = navigate.find(graph, query)
    total = sum(len(v) for v in hits.values())
    print(f'\nMatches for "{query}"')
    print(_SEP)
    if not total:
        print("  (nothing found in names, strings or imports)")
        print(_SEP)
        return []

    found: list[int] = []
    for kind, label in (("name", "function name"),
                        ("string", "referenced string"),
                        ("import", "imported API")):
        if not hits[kind]:
            continue
        print(f"\n  ── by {label} ──")
        known = _kb_map(workspace, hits[kind])
        for addr in hits[kind]:
            print(_line(graph, addr, config, known))
            found.append(addr)
    print(_SEP)
    print(f"  {len(found)} match(es)")
    return found


def explore(graph: CallGraph, config: dict, workspace: Workspace,
            addr: int) -> None:
    """Everything the graph knows about one function, plus its neighbours."""
    node = graph.nodes.get(addr)
    if node is None:
        print(f"[wingman] 0x{addr:X} is not in the call graph.")
        return

    callers = graph.callers_of(addr)
    callees = graph.callees_of(addr)
    known = _kb_map(workspace, [addr] + callers + callees)

    self_entry = known.get(addr_to_hex(addr))
    header_name = (self_entry.get("new_name") or self_entry.get("old_name")
                   if self_entry else None) or node.name
    print(f"\n  0x{addr:X}  {header_name}")
    print(_SEP)
    print(f"  Size {node.size_bytes} bytes · {node.basic_block_count} basic blocks "
          f"· {node.caller_count} caller(s)")
    if node.input_reachable:
        print("  Reachable from an input source")
    if node.dangerous_sink_calls:
        print(f"  Calls memory sinks: {', '.join(node.dangerous_sink_calls)}")
    if node.import_refs:
        print(f"  Imports: {', '.join(node.import_refs[:10])}")
    if node.string_refs:
        print("  Strings:")
        for s in node.string_refs[:8]:
            print(f"    {s[:70]!r}")

    entry = known.get(addr_to_hex(addr))
    if entry:
        print(_SEP)
        print(f"  Analyzed: {entry.get('new_name') or entry.get('old_name')}"
              f"{' [SECURITY]' if entry.get('security_relevant') else ''}")
        print(f"  {entry.get('summary') or ''}")
        for b in (entry.get("interesting_behaviors") or [])[:5]:
            print(f"    • {b}")

    print(_SEP)
    print(f"  Called by ({len(callers)}):")
    for c in callers[:15]:
        print(_line(graph, c, config, known))
    print(f"\n  Calls ({len(callees)}):")
    for c in callees[:15]:
        print(_line(graph, c, config, known))
    print(_SEP)


def show_paths(graph: CallGraph, paths: list[list[int]], title: str) -> None:
    print(f"\n{title}")
    print(_SEP)
    if not paths:
        print("  (no path found)")
    for i, path in enumerate(paths, 1):
        print(f"\n  Path {i}  ({len(path)} functions)")
        print(navigate.describe_path(graph, path))
    print(_SEP)
    if paths:
        distinct = len({a for p in paths for a in p})
        print(f"  {len(paths)} path(s), {distinct} distinct function(s)")
