"""
Reading the knowledge base: semantic search, reports and call chains.

Nothing here opens the IDA database — it all runs against the workspace, so
`research_wingman.py ask` and `research_wingman.py status` are fast and need no IDA licence seat.
"""

from __future__ import annotations

import os
import re

from .kb import KnowledgeBase
from .workspace import Workspace

_SEP = "─" * 72

# Strips a renamer collision suffix (`_2`, `_3`, ...) so `wrapper_identity`,
# `wrapper_identity_2`, ... `wrapper_identity_10` -- all proposed as the same
# name by the LLM and only distinguished because RenamePolicy.resolve_conflict
# had to make them unique -- collapse back to one dedup group in `ask` results.
_SUFFIX_RE = re.compile(r"_\d+$")

_DEFAULT_RISK_BOOST = {"low": 0.0, "medium": 0.03, "high": 0.07}


def _dedup_key(name: str) -> str:
    return _SUFFIX_RE.sub("", name)


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------

def _fmt_entry(rank: int, entry: dict, score: float | None = None,
              note: str = "") -> str:
    name = entry.get("new_name") or entry.get("old_name") or "?"
    addr = entry.get("address", "?")
    conf = float(entry.get("confidence") or 0.0)
    sec = " [SECURITY]" if entry.get("security_relevant") else ""
    sim = f"  sim={score:.3f}" if score is not None else ""
    lines = [f"  #{rank:>3}  {addr:<14} {name:<40} conf={conf:.2f}{sec}{sim}{note}"]
    if entry.get("summary"):
        lines.append(f"         {entry['summary']}")
    for b in (entry.get("interesting_behaviors") or [])[:3]:
        lines.append(f"         • {b}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Index management
# ---------------------------------------------------------------------------

def _load_embedder(config: dict, workspace: Workspace, kb: KnowledgeBase):
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
        print("[wingman] Semantic search unavailable (pip install faiss-cpu numpy).")
        return None

    entries = kb.get_all_for_embedding()
    current_sig = embedder.content_signature(entries)
    stored_sig = embedder.stored_signature()

    # Rebuild on a *content* change, not just a count change: refinement or
    # --redo can alter a summary without altering how many there are, and the
    # old count-only check let stale vectors linger. A missing/mismatched
    # signature (including an index built by an older version with no .sig)
    # forces a rebuild.
    if not workspace.has_index() or stored_sig != current_sig:
        if not entries:
            return None
        why = "building" if not workspace.has_index() else "stale (summaries changed) — rebuilding"
        print(f"[wingman] Semantic index {why} — embedding {len(entries)} summaries…")
        try:
            embedder.build_index(entries)
        except EmbedderUnavailable as e:
            print(f"[wingman] Could not build index: {e}")
            return None
        return embedder if embedder.is_ready() else None

    return embedder if embedder.load() else None


# ---------------------------------------------------------------------------
# Query modes
# ---------------------------------------------------------------------------

def semantic_query(kb, embedder, query_text: str, top_k: int,
                   security_only: bool, config: dict | None = None) -> None:
    from .embedder import EmbedderUnavailable

    search_cfg = (config or {}).get("search", {})
    min_similarity = float(search_cfg.get("min_similarity", 0.55))
    security_boost = float(search_cfg.get("security_relevant_boost", 0.02))
    risk_boost = search_cfg.get("risk_boost", _DEFAULT_RISK_BOOST)
    pool_multiplier = int(search_cfg.get("semantic_candidate_pool_multiplier", 4))

    print(f'\nQuery: "{query_text}"')
    print(_SEP)
    try:
        # Fetch a wider pool than top_k -- the floor and dedup passes below
        # both shrink the candidate set before it's truncated to top_k.
        results = embedder.search(query_text, top_k=top_k * pool_multiplier)
    except EmbedderUnavailable as e:
        print(f"[wingman] Semantic search failed ({e}) — ranking by confidence.")
        confidence_query(kb, top_k, security_only)
        return

    candidates = []
    for addr, sim in results:
        if sim < min_similarity:
            continue
        entry = kb.get(addr)
        if entry is None:
            continue
        if security_only and not entry.get("security_relevant"):
            continue
        risk = str(entry.get("risk") or "").strip().lower()
        boost = risk_boost.get(risk, 0.0)
        if entry.get("security_relevant"):
            boost += security_boost
        candidates.append((sim, sim + boost, entry))

    # Re-rank by similarity + risk/security boost, not raw similarity alone --
    # a risk-oriented question should surface the actually dangerous function
    # over a low-risk near-duplicate that merely shares more vocabulary.
    candidates.sort(key=lambda c: c[1], reverse=True)

    # Dedup: collapse renamer-suffix families (wrapper_x, wrapper_x_2, ...)
    # to their single best-scoring member so one structural family doesn't
    # crowd out distinct results; note how many were folded in.
    groups: dict[str, list] = {}
    order: list[str] = []
    for sim, adj, entry in candidates:
        name = entry.get("new_name") or entry.get("old_name") or "?"
        # A shared body_hash (see family.py) is a stronger signal than the
        # name-suffix heuristic below -- two structurally-identical functions
        # that got two different plausible-sounding names would otherwise
        # show up as unrelated results. Falls back to name-suffix grouping
        # for entries with no hash yet (pre-migration rows, or bodies too
        # trivial to hash).
        key = entry.get("body_hash") or _dedup_key(name)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append((sim, adj, entry))

    shown = 0
    for key in order:
        members = groups[key]
        sim, adj, entry = members[0]  # highest-adjusted-score member
        shown += 1
        extra = len(members) - 1
        note = f"  (+{extra} similar)" if extra else ""
        print(_fmt_entry(shown, entry, score=sim, note=note))
        if shown >= top_k:
            break

    print(_SEP)
    if shown == 0:
        print(f"  0 result(s) above the relevance floor "
              f"(min_similarity={min_similarity:.2f}) — no confident match "
              f"for this query among the analyzed functions.")
    else:
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


def security_report(kb: KnowledgeBase) -> None:
    entries = kb.search_by_security()
    print(f"\nSecurity-relevant functions ({len(entries)}):")
    print(_SEP)
    for i, entry in enumerate(entries, 1):
        print(_fmt_entry(i, entry))
        print()
    print(_SEP)




# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

def status(config: dict, workspace: Workspace) -> None:
    """What has been done for this database."""
    print(f"\n  Database  : {workspace.db_path}")
    print(f"  Workspace : {workspace.dir}")
    print(_SEP)

    name = os.path.basename(workspace.db_path)
    if not os.path.exists(workspace.kb):
        print("  No analysis yet.\n")
        print(f"  Next:  python research_wingman.py {name}\n")
        return

    kb = KnowledgeBase(workspace.kb)
    s = kb.stats()

    graph_state = "cached" if workspace.has_graph() else "not built"
    indexed = workspace.index_size()
    if indexed == 0:
        index_state = "not built"
    else:
        # Content-hash comparison, not a count-only check: refinement/--redo
        # can change a summary without changing how many there are, and a
        # count-only check misses that (confirmed real 2026-08-16 -- this
        # duplicated, with the OLD count-only logic, the exact staleness
        # check _load_embedder was already fixed to replace, so the two
        # gave contradictory freshness answers for the same index).
        try:
            from .embedder import Embedder
            embedder = Embedder(config, workspace.faiss)
            stale = embedder.stored_signature() != embedder.content_signature(
                kb.get_all_for_embedding())
        except Exception:
            stale = indexed < s["with_summary"]  # best-effort fallback if faiss/numpy unavailable
        index_state = f"stale ({indexed} vectors)" if stale else f"{indexed} vectors"

    kb.close()

    print(f"  Analyzed        : {s['analyzed']}")
    print(f"    approved      : {s['approved']}")
    print(f"    rejected      : {s['rejected']}")
    print(f"  Refined         : {s['refined']}")
    print(f"  Security-flagged: {s['security']}")
    print(_SEP)
    print(f"  Applied to DB   : {s['applied']}")
    print(f"  Ready to apply  : {s['pending_apply']}")
    if s.get("pseudocode_truncated"):
        print(f"  WARNING: {s['pseudocode_truncated']} function(s) had real bodies longer "
              f"than analysis.max_pseudocode_lines -- content was NOT fully shown to the "
              f"model. Query KnowledgeBase.get_pseudocode_truncated() for the list.")
    print(_SEP)
    print(f"  Call graph      : {graph_state}")
    print(f"  Semantic index  : {index_state}")
    print(_SEP)

    print(f"  Next:  python research_wingman.py {name}\n")
