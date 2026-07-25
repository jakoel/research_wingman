"""
Reading the knowledge base: semantic search, reports and call chains.

Nothing here opens the IDA database — it all runs against the workspace, so
`rh ask` and `rh status` are fast and need no IDA licence seat.
"""

from __future__ import annotations

import os

from .kb import KnowledgeBase
from .workspace import Workspace

_SEP = "─" * 72


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------

def _fmt_entry(rank: int, entry: dict, score: float | None = None) -> str:
    name = entry.get("new_name") or entry.get("old_name") or "?"
    addr = entry.get("address", "?")
    conf = float(entry.get("confidence") or 0.0)
    sec = " [SECURITY]" if entry.get("security_relevant") else ""
    sim = f"  sim={score:.3f}" if score is not None else ""
    lines = [f"  #{rank:>3}  {addr:<14} {name:<40} conf={conf:.2f}{sec}{sim}"]
    if entry.get("summary"):
        lines.append(f"         {entry['summary']}")
    for b in (entry.get("interesting_behaviors") or [])[:3]:
        lines.append(f"         • {b}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Index management
# ---------------------------------------------------------------------------

def _load_embedder(config: dict, workspace: Workspace, kb: KnowledgeBase,
                   force_reindex: bool = False):
    """
    Return a ready Embedder, building or refreshing the index if it is missing
    or has fallen behind the knowledge base. Returns None if unavailable.
    """
    try:
        from .embedder import Embedder, EmbedderUnavailable
    except ImportError:
        return None

    try:
        embedder = Embedder(config, workspace.faiss)
    except Exception:
        print("[rh] Semantic search unavailable (pip install faiss-cpu numpy).")
        return None

    summaries = kb.stats()["with_summary"]
    indexed = workspace.index_size()

    if force_reindex or indexed == 0 or indexed < summaries:
        if summaries == 0:
            return None
        why = "rebuilding" if force_reindex else (
            "building" if indexed == 0 else f"stale ({indexed} of {summaries})"
        )
        print(f"[rh] Semantic index {why} — embedding {summaries} summaries…")
        try:
            embedder.build_index(kb.get_all_for_embedding())
        except EmbedderUnavailable as e:
            print(f"[rh] Could not build index: {e}")
            return None
        return embedder if embedder.is_ready() else None

    return embedder if embedder.load() else None


def build_index(config: dict, workspace: Workspace) -> None:
    """Force a full index rebuild."""
    kb = KnowledgeBase(workspace.kb)
    _load_embedder(config, workspace, kb, force_reindex=True)
    kb.close()


# ---------------------------------------------------------------------------
# Query modes
# ---------------------------------------------------------------------------

def semantic_query(kb, embedder, query_text: str, top_k: int,
                   security_only: bool) -> None:
    from .embedder import EmbedderUnavailable

    print(f'\nQuery: "{query_text}"')
    print(_SEP)
    try:
        results = embedder.search(query_text, top_k=top_k * 2)
    except EmbedderUnavailable as e:
        print(f"[rh] Semantic search failed ({e}) — ranking by confidence.")
        confidence_query(kb, top_k, security_only)
        return

    shown = 0
    for addr, sim in results:
        entry = kb.get(addr)
        if entry is None:
            continue
        if security_only and not entry.get("security_relevant"):
            continue
        shown += 1
        print(_fmt_entry(shown, entry, score=sim))
        if shown >= top_k:
            break

    print(_SEP)
    print(f"  {shown} result(s).")


def confidence_query(kb: KnowledgeBase, top_k: int, security_only: bool) -> None:
    if security_only:
        entries = kb.search_by_security()
    else:
        entries = kb.get_all_analyzed()
        entries.sort(key=lambda e: float(e.get("confidence") or 0), reverse=True)

    entries = entries[:top_k]
    print(_SEP)
    for i, entry in enumerate(entries, 1):
        print(_fmt_entry(i, entry))
    print(_SEP)
    print(f"  {len(entries)} result(s).")


def chain(kb: KnowledgeBase, addr: str) -> None:
    print(f"\nCall chain for {addr}:")
    print(_SEP)
    entries = kb.get_call_chain(addr, depth=4)
    if not entries:
        print("  (no call chain data — run a full analysis to build the graph)")
    for e in entries:
        name = e.get("new_name") or e.get("old_name") or "?"
        conf = float(e.get("confidence") or 0.0)
        sec = " [SECURITY]" if e.get("security_relevant") else ""
        print(f"    {e.get('address', '?'):<14} {name:<36} conf={conf:.2f}{sec}")
        if e.get("summary"):
            print(f"               {e['summary']}")
    print(_SEP)


def security_report(kb: KnowledgeBase) -> None:
    entries = kb.search_by_security()
    print(f"\nSecurity-relevant functions ({len(entries)}):")
    print(_SEP)
    for i, entry in enumerate(entries, 1):
        print(_fmt_entry(i, entry))
        print()
    print(_SEP)


def score_report(config: dict, workspace: Workspace, top_n: int = 30) -> None:
    from .call_graph import CallGraph
    from .scorer import score_report as compute_scores

    if not workspace.has_graph():
        print(f"[rh] No call graph at {workspace.call_graph}")
        print("[rh] Run a full analysis (without --quick) to build it.")
        return

    graph = CallGraph.load(workspace.call_graph)
    rows = compute_scores(graph, config, top_n=top_n)
    print(f"\nTop {len(rows)} functions by score:")
    print(_SEP)
    print(f"  {'Address':<14} {'Score':>6}  {'Callers':>7}  "
          f"{'Input':>5}  {'Sinks':<20}  Name")
    print(_SEP)
    for r in rows:
        sinks = ", ".join(r["sinks"][:2]) if r["sinks"] else ""
        inp = "yes" if r["input_reachable"] else "no"
        print(f"  {r['address']:<14} {r['score']:>6.1f}  {r['caller_count']:>7}  "
              f"{inp:>5}  {sinks:<20}  {r['name']}")
    print(_SEP)


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

def status(config: dict, workspace: Workspace) -> None:
    """What has been done for this database, and what to run next."""
    print(f"\n  Database  : {workspace.db_path}")
    print(f"  Workspace : {workspace.dir}")
    print(_SEP)

    name = os.path.basename(workspace.db_path)
    if not os.path.exists(workspace.kb):
        print("  No analysis yet.\n")
        print(f"  Next:  rh menu {name}            interactive session\n"
              f"         rh map {name}             look around first (free)\n")
        return

    kb = KnowledgeBase(workspace.kb)
    s = kb.stats()
    kb.close()

    graph_state = "cached" if workspace.has_graph() else "not built"
    indexed = workspace.index_size()
    if indexed == 0:
        index_state = "not built"
    elif indexed < s["with_summary"]:
        index_state = f"stale ({indexed} of {s['with_summary']})"
    else:
        index_state = f"{indexed} vectors"

    print(f"  Analyzed        : {s['analyzed']}")
    print(f"    approved      : {s['approved']}")
    print(f"    rejected      : {s['rejected']}")
    print(f"  Refined         : {s['refined']}")
    print(f"  Security-flagged: {s['security']}")
    print(_SEP)
    print(f"  Applied to DB   : {s['applied']}")
    print(f"  Ready to apply  : {s['pending_apply']}")
    print(_SEP)
    print(f"  Call graph      : {graph_state}")
    print(f"  Semantic index  : {index_state}")
    print(_SEP)

    print("  Next:")
    if s["pending_apply"]:
        print(f"    rh apply {name} --dry-run     preview {s['pending_apply']} rename(s)")
    if s["analyzed"]:
        print(f'    rh ask {name} "<question>"    search the analysis')
    print(f"    rh map {name} --suspicious    find the next thing to analyze")
    print(f"    rh menu {name}                interactive session\n")
