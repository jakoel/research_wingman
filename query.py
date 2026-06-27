#!/usr/bin/env python3
"""
Phase 6 — Ranked semantic query over the function knowledge base.

Usage
-----
  python query.py "user-controlled length without bounds check"
  python query.py --top 10 "authentication bypass"
  python query.py --security-only "memory allocation without bounds check"
  python query.py --chain 0x401000        show call chain for a specific address
  python query.py --report                print all security-relevant functions

Options
-------
  --config PATH      Path to config.json  (default: llm_renamer/config.json)
  --kb PATH          Override knowledge base SQLite path
  --index PATH       Override FAISS index path
  --top N            Number of results to return  (default: 20)
  --security-only    Restrict results to security_relevant=true functions
  --chain ADDR       Show the call chain for a hex address (e.g. 0x401000)
  --report           Print all security-relevant functions, sorted by confidence
  --score-report     Print the top-N functions by score from the call graph cache
  --no-vector        Skip semantic search; show top-N by confidence instead
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from llm_renamer.config import load_config
from llm_renamer.kb import KnowledgeBase
from llm_renamer.embedder import Embedder, EmbedderUnavailable


# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------

_SEP = "─" * 72


def _fmt_entry(rank: int, entry: dict, score: float | None = None) -> str:
    name = entry.get("new_name") or entry.get("old_name") or "?"
    addr = entry.get("address", "?")
    conf = float(entry.get("confidence") or 0.0)
    sec = " [SECURITY]" if entry.get("security_relevant") else ""
    sim = f"  sim={score:.3f}" if score is not None else ""
    header = f"  #{rank:>3}  {addr:<14} {name:<40} conf={conf:.2f}{sec}{sim}"
    lines = [header]
    summary = entry.get("summary") or ""
    if summary:
        lines.append(f"         {summary}")
    behaviors = entry.get("interesting_behaviors") or []
    for b in behaviors[:3]:
        lines.append(f"         • {b}")
    return "\n".join(lines)


def _fmt_chain(entries: list[dict], root_addr: str) -> str:
    if not entries:
        return "  (no call chain data)"
    lines = [f"  Call chain for {root_addr}:"]
    for e in entries:
        name = e.get("new_name") or e.get("old_name") or "?"
        addr = e.get("address", "?")
        conf = float(e.get("confidence") or 0.0)
        sec = " [SECURITY]" if e.get("security_relevant") else ""
        summary = e.get("summary") or ""
        lines.append(f"    {addr:<14} {name:<36} conf={conf:.2f}{sec}")
        if summary:
            lines.append(f"               {summary}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Query modes
# ---------------------------------------------------------------------------

def run_semantic_query(
    query_text: str,
    kb: KnowledgeBase,
    embedder: Embedder,
    top_k: int,
    security_only: bool,
) -> None:
    print(f'\nQuery: "{query_text}"')
    print(_SEP)

    try:
        results = embedder.search(query_text, top_k=top_k * 2)
    except EmbedderUnavailable as e:
        print(f"[query] Semantic index not available: {e}")
        print("[query] Falling back to confidence-ranked results.")
        run_confidence_query(kb, top_k, security_only)
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
    print(f"  {shown} result(s) returned.")


def run_confidence_query(
    kb: KnowledgeBase,
    top_k: int,
    security_only: bool,
) -> None:
    if security_only:
        entries = kb.search_by_security()
    else:
        entries = kb.get_all_phase3_done()
        entries.sort(key=lambda e: float(e.get("confidence") or 0), reverse=True)

    entries = entries[:top_k]
    print(_SEP)
    for i, entry in enumerate(entries, 1):
        print(_fmt_entry(i, entry))
    print(_SEP)
    print(f"  {len(entries)} result(s) returned.")


def run_chain(kb: KnowledgeBase, addr: str) -> None:
    print(f"\nCall chain for {addr}:")
    print(_SEP)
    chain = kb.get_call_chain(addr, depth=4)
    print(_fmt_chain(chain, addr))
    print(_SEP)


def run_report(kb: KnowledgeBase) -> None:
    entries = kb.search_by_security()
    print(f"\nSecurity-relevant functions ({len(entries)} total):")
    print(_SEP)
    for i, entry in enumerate(entries, 1):
        print(_fmt_entry(i, entry))
        print()
    print(_SEP)


def run_score_report(config: dict, out_dir: str) -> None:
    from llm_renamer.call_graph import CallGraph
    from llm_renamer.scorer import score_report

    cache_name = config.get("graph", {}).get("cache_filename", "call_graph.json")
    cache_path = os.path.join(out_dir, cache_name)
    if not os.path.exists(cache_path):
        print(f"[query] No call graph cache found at {cache_path}")
        print("[query] Run main.py first to build the call graph.")
        return

    print(f"[query] Loading call graph from {cache_path}…")
    graph = CallGraph.load(cache_path)
    rows = score_report(graph, config, top_n=30)
    print(f"\nTop {len(rows)} functions by score:")
    print(_SEP)
    print(
        f"  {'Address':<14} {'Score':>6}  {'Callers':>7}  "
        f"{'Input':>5}  {'Sinks':<20}  Name"
    )
    print(_SEP)
    for r in rows:
        sinks = ", ".join(r["sinks"][:2]) if r["sinks"] else ""
        inp = "yes" if r["input_reachable"] else "no"
        print(
            f"  {r['address']:<14} {r['score']:>6.1f}  "
            f"{r['caller_count']:>7}  {inp:>5}  {sinks:<20}  {r['name']}"
        )
    print(_SEP)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args():
    p = argparse.ArgumentParser(
        description="Semantic query over the llm_renamer knowledge base",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("query", nargs="?", default=None,
                   help="Free-text query (semantic similarity search)")
    p.add_argument("--config", metavar="PATH",
                   default=os.path.join(
                       os.path.dirname(__file__), "llm_renamer", "config.json"
                   ))
    p.add_argument("--kb",     metavar="PATH", help="Override knowledge base path")
    p.add_argument("--index",  metavar="PATH", help="Override FAISS index path")
    p.add_argument("--out-dir", metavar="DIR",
                   help="Directory containing output files (default: cwd)")
    p.add_argument("--top",    metavar="N",    type=int, default=20)
    p.add_argument("--security-only", action="store_true",
                   help="Only show security-relevant functions")
    p.add_argument("--chain",  metavar="ADDR",
                   help="Show call chain for a function address (hex)")
    p.add_argument("--report", action="store_true",
                   help="Print all security-relevant functions")
    p.add_argument("--score-report", action="store_true",
                   help="Print top functions by score from the call graph")
    p.add_argument("--no-vector", action="store_true",
                   help="Skip semantic search; rank by confidence instead")
    return p.parse_args()


def main() -> None:
    args = _parse_args()
    config_dir = os.path.dirname(os.path.abspath(args.config))
    config = load_config(config_dir)

    out_dir = args.out_dir or config["output"].get("dir") or os.getcwd()

    # Resolve paths
    kb_path = args.kb or os.path.join(
        out_dir, config.get("kb", {}).get("sqlite_filename", "knowledge_base.sqlite")
    )
    index_path = args.index or os.path.join(
        out_dir, config.get("kb", {}).get("faiss_filename", "kb_vectors.faiss")
    )

    if not os.path.exists(kb_path):
        print(f"[query] Knowledge base not found: {kb_path}")
        print("[query] Run main.py first to build the knowledge base.")
        sys.exit(1)

    kb = KnowledgeBase(kb_path)

    # --score-report doesn't need the KB
    if args.score_report:
        run_score_report(config, out_dir)
        return

    # --report: all security-relevant functions
    if args.report:
        run_report(kb)
        return

    # --chain: call chain for a specific address
    if args.chain:
        run_chain(kb, args.chain)
        return

    # Semantic / confidence query
    if args.query is None:
        print("[query] Provide a query string, or use --report / --chain / --score-report.")
        sys.exit(1)

    if args.no_vector:
        print(f'\nQuery (confidence-ranked): "{args.query}"')
        run_confidence_query(kb, args.top, args.security_only)
        return

    # Try to load FAISS index
    cfg_with_index = {
        **config,
        "kb": {**config.get("kb", {}), "faiss_file": index_path},
    }
    embedder = Embedder(cfg_with_index)
    if not embedder.load():
        print(f"[query] FAISS index not found at {index_path}.")
        print("[query] Run:  python main.py --build-index  to create it.")
        print("[query] Falling back to confidence-ranked results.\n")
        run_confidence_query(kb, args.top, args.security_only)
        return

    run_semantic_query(args.query, kb, embedder, args.top, args.security_only)


if __name__ == "__main__":
    main()
