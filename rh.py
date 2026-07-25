#!/usr/bin/env python3
"""
rh — a copilot for reverse engineering an IDA Pro database.

Just point it at a database:

    python rh.py target.i64            opens the interactive session
    python rh.py                       finds a database here and opens it

Everything is reachable from that menu. The subcommands below exist for
scripting; you never need to remember them.

The call graph is a free map of the binary. The LLM is an expensive lens you
point at one place on that map. So: look first, then spend.

    rh map target.i64                  overview: entry points, imports, size
    rh map target.i64 --suspicious     what's worth looking at
    rh map target.i64 --find "recv"    search names, strings, imported APIs
    rh map target.i64 --explore sub_x  one function and its neighbours

    rh analyze target.i64 -f sub_401a30      one function
    rh analyze target.i64 --callees sub_x    it and what it calls
    rh analyze target.i64 --to-sinks         entry points down to memcpy & co
    rh analyze target.i64 --between a b      everything on the paths a -> b
    rh analyze target.i64 --top 50           highest-scoring unnamed functions

    rh apply  target.i64               write approved renames into the database
    rh ask    target.i64 "question"    search what was learned
    rh status target.i64               what has been done so far
    rh export target.i64               dump everything to review.json

Everything under `map` is instant and costs nothing. Everything under
`analyze` quotes its cost before spending it, and needs an explicit scope —
there is no accidental overnight run.

State lives in <database>.rh/ next to the database, so it follows the binary
rather than the directory you happen to run from.

`analyze` never modifies the database. `apply` never calls the LLM.
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from llm_renamer import ask as ask_mod
from llm_renamer.config import load_config
from llm_renamer.export import export_review
from llm_renamer.kb import KnowledgeBase
from llm_renamer.workspace import Workspace, warn_if_legacy_state_nearby


# ==========================================================================
# Setup shared by every command
# ==========================================================================

def _prepare(args) -> tuple[dict, Workspace]:
    db_path = os.path.abspath(args.database)
    if not os.path.exists(db_path):
        _die(f"database not found: {db_path}")

    config = load_config(args.config)
    if getattr(args, "ollama_url", None):
        config["ollama"]["url"] = args.ollama_url
    if getattr(args, "model", None):
        config["ollama"]["model"] = args.model

    workspace = Workspace(db_path, args.workspace)
    warn_if_legacy_state_nearby(workspace)
    return config, workspace


def _die(message: str) -> None:
    print(f"[rh] ERROR: {message}")
    sys.exit(1)


def _check_ollama(config: dict) -> None:
    from llm_renamer.llm_client import OllamaClient
    llm = OllamaClient(config)
    if not llm.health_check():
        _die(
            f"Ollama is not reachable at {config['ollama']['url']}\n"
            f"       Start it with:  ollama run {config['ollama']['model']}"
        )
    print(f"[rh] Ollama OK ({config['ollama']['model']})")


class _OpenDatabase:
    """Opens the IDA database for the duration of a command."""

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path

    def __enter__(self):
        try:
            import idapro
        except ImportError:
            _die("this command needs IDA Pro's `idapro` package, which is not "
                 "importable here.\n"
                 "       Run it with IDA's bundled Python, or add IDA's "
                 "python directory to PYTHONPATH.\n"
                 "       `rh map` / `ask` / `status` / `export` work without it.")
        self._idapro = idapro
        print(f"[rh] Opening {self._db_path}")
        idapro.open_database(self._db_path, run_auto_analysis=False)
        from llm_renamer.idapro_client import FunctionContextExtractor
        return FunctionContextExtractor

    def __exit__(self, *_):
        print("[rh] Closing database…")
        self._idapro.close_database()


# ==========================================================================
# Commands
# ==========================================================================

def _resolve_one(name: str, graph, extractor) -> int | None:
    """Turn a name or 0xADDR into an address, preferring the cached graph."""
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
            print(f"[rh] {name!r} matches {len(partial)} functions; be more specific.")
            return None
    # Only the map commands run without an extractor (no IDA open).
    if extractor is not None:
        rows = extractor.get_functions_by_name([name])
        if rows:
            return int(rows[0]["address"])
    print(f"[rh] Not found: {name!r}")
    return None


def _resolve_scope(args, graph, extractor, config):
    """Turn the scope flags into (addresses, label). None means 'everything'."""
    from llm_renamer import navigate, mapview

    needs_graph = any([args.callees, args.callers, args.around,
                       args.between, args.to_sinks, args.top])
    if needs_graph and graph is None:
        _die("that scope needs the call graph.\n"
             f"       Build it once:  rh map {os.path.basename(args.database)} --build")

    if args.function:
        names = [f for item in args.function for f in item.split(",") if f]
        return None, names, f"{len(names)} named function(s)"

    if args.between:
        src = _resolve_one(args.between[0], graph, extractor)
        dst = _resolve_one(args.between[1], graph, extractor)
        if src is None or dst is None:
            sys.exit(1)
        paths = navigate.paths_between(graph, src, dst)
        mapview.show_paths(graph, paths, f"Paths 0x{src:X} -> 0x{dst:X}")
        addrs = list(dict.fromkeys(a for p in paths for a in p))
        return addrs, None, f"paths 0x{src:X} -> 0x{dst:X}"

    if args.to_sinks:
        start = None
        if args.start:
            start = _resolve_one(args.start, graph, extractor)
            if start is None:
                sys.exit(1)
        paths = navigate.paths_to_sinks(graph, config, limit=args.limit_paths,
                                        start=start)
        mapview.show_paths(graph, paths, "Entry point -> memory sink")
        addrs = list(dict.fromkeys(a for p in paths for a in p))
        return addrs, None, "entry -> sink paths"

    for flag, fn, word in ((args.callees, navigate.descendants, "callees"),
                           (args.callers, navigate.ancestors, "callers")):
        if flag:
            addr = _resolve_one(flag, graph, extractor)
            if addr is None:
                sys.exit(1)
            addrs = fn(graph, addr, args.depth)
            return addrs, None, f"{word} of 0x{addr:X} (depth {args.depth})"

    if args.around:
        addr = _resolve_one(args.around, graph, extractor)
        if addr is None:
            sys.exit(1)
        addrs = list(dict.fromkeys(
            navigate.descendants(graph, addr, args.depth)
            + navigate.ancestors(graph, addr, args.depth)
        ))
        return addrs, None, f"neighbourhood of 0x{addr:X} (depth {args.depth})"

    if args.top:
        addrs = navigate.top_scored(graph, config, args.top * 3)
        addrs = navigate.unnamed_only(graph, addrs, config)[:args.top]
        return addrs, None, f"top {args.top} by score"

    return None, None, "every auto-named function"


def cmd_analyze(args) -> None:
    from llm_renamer import pipeline

    config, workspace = _prepare(args)

    if args.reset:
        kb = KnowledgeBase(workspace.kb)
        n = kb.reset()
        kb.close()
        print(f"[rh] Cleared {n} analysis result(s).")

    _check_ollama(config)

    with _OpenDatabase(workspace.db_path) as Extractor:
        extractor = Extractor(config)
        graph = pipeline.resolve_graph(
            config, workspace, extractor,
            quick=args.quick, targeted=not args.all,
            rebuild=args.rebuild_graph,
        )
        addresses, functions, label = _resolve_scope(
            args, graph, extractor, config
        )
        confirm = None if args.yes else _confirm_cost
        pipeline.analyze(
            config, workspace, extractor,
            addresses=addresses,
            functions=functions,
            all_functions=addresses is None and functions is None,
            label=label,
            limit=args.limit,
            quick=args.quick,
            refine=not args.no_refine,
            reanalyze=args.redo or bool(functions),
            confirm=confirm,
            graph=graph,
        )


def _confirm_cost(plan, seconds_per_call) -> bool:
    return input("  Go ahead? [Y/n] ").strip().lower() in ("", "y", "yes")


def cmd_map(args) -> None:
    from llm_renamer import mapview, navigate
    from llm_renamer.call_graph import load_or_build

    config, workspace = _prepare(args)

    if args.build:
        with _OpenDatabase(workspace.db_path) as Extractor:
            load_or_build(Extractor(config), config, workspace.call_graph,
                          force_rebuild=True)
        return

    graph = mapview.load_graph(workspace)
    if graph is None:
        sys.exit(1)

    if args.find:
        mapview.find(graph, config, workspace, args.find)
    elif args.explore:
        addr = _resolve_one(args.explore, graph, None)
        if addr is None:
            sys.exit(1)
        mapview.explore(graph, config, workspace, addr)
    elif args.suspicious is not None:
        mapview.suspicious(graph, config, workspace,
                           top=args.suspicious or 25, unnamed_only=True)
    elif args.paths:
        paths = navigate.paths_to_sinks(graph, config, limit=args.paths)
        mapview.show_paths(graph, paths, "Entry point -> memory sink")
    else:
        mapview.overview(graph, config, workspace)


def cmd_menu(args) -> None:
    from llm_renamer import menu

    config, workspace = _prepare(args)
    with _OpenDatabase(workspace.db_path) as Extractor:
        menu.run(config, workspace, Extractor(config))


def cmd_apply(args) -> None:
    from llm_renamer import pipeline

    config, workspace = _prepare(args)

    if not os.path.exists(workspace.kb):
        _die(f"no analysis found in {workspace.dir}\n"
             f"       Run:  rh analyze {os.path.basename(workspace.db_path)}")

    kb = KnowledgeBase(workspace.kb)
    pending = kb.stats()["pending_apply"]
    kb.close()

    if not args.dry_run and pending:
        print(f"[rh] This will write {pending} rename(s) and comment(s) "
              f"into {os.path.basename(workspace.db_path)}.")
        if input("Proceed? [y/N] ").strip().lower() != "y":
            print("Aborted.")
            return

    with _OpenDatabase(workspace.db_path) as Extractor:
        pipeline.apply(
            config, workspace, Extractor(config),
            min_confidence=args.min_confidence,
            dry_run=args.dry_run,
        )


def cmd_ask(args) -> None:
    config, workspace = _prepare(args)

    if not os.path.exists(workspace.kb):
        _die(f"no analysis found in {workspace.dir}\n"
             f"       Run:  rh analyze {os.path.basename(workspace.db_path)}")

    kb = KnowledgeBase(workspace.kb)
    try:
        if args.scores:
            ask_mod.score_report(config, workspace)
            return
        if args.report:
            ask_mod.security_report(kb)
            return
        if args.chain:
            ask_mod.chain(kb, args.chain)
            return
        if not args.query:
            _die("provide a question, or use --report / --chain / --scores")

        if args.no_vector:
            print(f'\nQuery (confidence-ranked): "{args.query}"')
            ask_mod.confidence_query(kb, args.top, args.security_only)
            return

        embedder = ask_mod._load_embedder(
            config, workspace, kb, force_reindex=args.reindex
        )
        if embedder is None:
            print("[rh] No semantic index — ranking by confidence instead.")
            ask_mod.confidence_query(kb, args.top, args.security_only)
            return

        ask_mod.semantic_query(
            kb, embedder, args.query, args.top, args.security_only
        )
    finally:
        kb.close()


def cmd_status(args) -> None:
    config, workspace = _prepare(args)
    ask_mod.status(config, workspace)


def cmd_export(args) -> None:
    _, workspace = _prepare(args)

    if not os.path.exists(workspace.kb):
        _die(f"no analysis found in {workspace.dir}")

    out = os.path.abspath(args.out) if args.out else workspace.review
    kb = KnowledgeBase(workspace.kb)
    count = export_review(kb, out)
    kb.close()
    print(f"[rh] Wrote {count} proposal(s) to {out}")


# ==========================================================================
# CLI
# ==========================================================================

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rh",
        description="Research helper for IDA Pro databases",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    subs = parser.add_subparsers(dest="command", metavar="COMMAND")

    # Options every command accepts.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("database", metavar="DATABASE",
                        help="Path to the .i64 IDA database")
    common.add_argument("--workspace", metavar="DIR",
                        help="State directory (default: <database>.rh)")
    common.add_argument("--config", metavar="PATH",
                        help="Path to config.json")

    # Options for commands that talk to Ollama.
    llm_opts = argparse.ArgumentParser(add_help=False)
    llm_opts.add_argument("--ollama-url", metavar="URL",
                          help="Override the Ollama server URL")
    llm_opts.add_argument("--model", metavar="NAME",
                          help="Override the Ollama model")

    # -- analyze --------------------------------------------------------
    p = subs.add_parser(
        "analyze", parents=[common, llm_opts],
        help="Analyze a scope of functions with the LLM (never modifies the database)",
        description="LLM calls are the scarce resource, so a scope is required. "
                    "Use `rh map` to decide what is worth analyzing.",
    )
    scope = p.add_mutually_exclusive_group(required=True)
    scope.add_argument("-f", "--function", metavar="NAME", nargs="+",
                       help="These functions (name or 0xADDR)")
    scope.add_argument("--callees", metavar="NAME",
                       help="A function and what it calls, --depth hops down")
    scope.add_argument("--callers", metavar="NAME",
                       help="A function and what calls it, --depth hops up")
    scope.add_argument("--around", metavar="NAME",
                       help="A function's callees and callers")
    scope.add_argument("--between", metavar=("FROM", "TO"), nargs=2,
                       help="Every function on the call paths between two functions")
    scope.add_argument("--to-sinks", action="store_true",
                       help="Paths from entry points down to memory sinks")
    scope.add_argument("--top", metavar="N", type=int,
                       help="The N highest-scoring unnamed functions")
    scope.add_argument("--all", action="store_true",
                       help="Every auto-named function (the overnight run)")

    p.add_argument("--depth", metavar="N", type=int, default=2,
                   help="Hops for --callees/--callers/--around (default: 2)")
    p.add_argument("--start", metavar="NAME",
                   help="Start --to-sinks from this function instead of entry points")
    p.add_argument("--limit-paths", metavar="N", type=int, default=10,
                   help="How many sinks --to-sinks traces (default: 10)")
    p.add_argument("--limit", metavar="N", type=int,
                   help="Stop after N LLM calls; rerun to continue")
    p.add_argument("--redo", action="store_true",
                   help="Re-analyze functions that were already done")
    p.add_argument("-y", "--yes", action="store_true",
                   help="Skip the cost confirmation prompt")
    p.add_argument("--quick", action="store_true",
                   help="Skip the call graph and refinement pass")
    p.add_argument("--rebuild-graph", action="store_true",
                   help="Discard the cached call graph and rebuild it")
    p.add_argument("--no-refine", action="store_true",
                   help="Skip the top-down refinement pass")
    p.add_argument("--reset", action="store_true",
                   help="Discard all previous results and start over")
    p.set_defaults(func=cmd_analyze)

    # -- map ------------------------------------------------------------
    p = subs.add_parser(
        "map", parents=[common],
        help="Browse the binary's structure — instant, no LLM calls",
    )
    p.add_argument("--build", action="store_true",
                   help="Build or refresh the call graph (needs IDA, no LLM)")
    p.add_argument("--suspicious", metavar="N", type=int, nargs="?", const=25,
                   help="Highest-scoring unnamed functions (default: 25)")
    p.add_argument("--find", metavar="QUERY",
                   help="Search names, referenced strings and imported APIs")
    p.add_argument("--explore", metavar="NAME",
                   help="One function: neighbours, strings, imports, sinks")
    p.add_argument("--paths", metavar="N", type=int, nargs="?", const=10,
                   help="Entry point -> memory sink paths (default: 10)")
    p.set_defaults(func=cmd_map)

    # -- menu -----------------------------------------------------------
    p = subs.add_parser(
        "menu", parents=[common, llm_opts],
        help="Interactive session — opens the database once and stays open",
    )
    p.set_defaults(func=cmd_menu)

    # -- apply ----------------------------------------------------------
    p = subs.add_parser(
        "apply", parents=[common],
        help="Write approved renames into the database (never calls the LLM)",
    )
    p.add_argument("--dry-run", action="store_true",
                   help="Show what would change without writing anything")
    p.add_argument("--min-confidence", metavar="F", type=float,
                   help="Only apply at or above this confidence "
                        "(default: the configured threshold)")
    p.set_defaults(func=cmd_apply)

    # -- ask ------------------------------------------------------------
    p = subs.add_parser(
        "ask", parents=[common, llm_opts],
        help="Search the analysis (does not open the database)",
    )
    # nargs="*" plus the leftover handling in main() so that the question can
    # sit anywhere: `ask DB "q" --top 5` and `ask DB --top 5 "q"` both work.
    p.add_argument("query", nargs="*", default=[], help="Free-text question")
    p.add_argument("--top", metavar="N", type=int, default=20)
    p.add_argument("--security-only", action="store_true",
                   help="Only show security-relevant functions")
    p.add_argument("--chain", metavar="ADDR",
                   help="Show the call chain below a hex address")
    p.add_argument("--report", action="store_true",
                   help="List every security-relevant function")
    p.add_argument("--scores", action="store_true",
                   help="Show the highest-scoring functions from the call graph")
    p.add_argument("--no-vector", action="store_true",
                   help="Rank by confidence instead of semantic similarity")
    p.add_argument("--reindex", action="store_true",
                   help="Force a rebuild of the semantic index")
    p.set_defaults(func=cmd_ask)

    # -- status ---------------------------------------------------------
    p = subs.add_parser(
        "status", parents=[common],
        help="Show what has been done for this database",
    )
    p.set_defaults(func=cmd_status)

    # -- export ---------------------------------------------------------
    p = subs.add_parser(
        "export", parents=[common],
        help="Write the analysis to a review JSON file",
    )
    p.add_argument("-o", "--out", metavar="PATH",
                   help="Output path (default: <workspace>/review.json)")
    p.set_defaults(func=cmd_export)

    return parser


_COMMANDS = {"menu", "map", "analyze", "apply", "ask", "status", "export"}
_DB_SUFFIXES = (".i64", ".idb")


def _discover_database() -> str | None:
    """Find a database to open when the user just runs `rh.py` with no args."""
    import glob
    found = sorted(
        f for suffix in _DB_SUFFIXES for f in glob.glob(f"*{suffix}")
    )
    if not found:
        return None
    if len(found) == 1:
        return found[0]
    print("\n  Which database?\n")
    for i, name in enumerate(found, 1):
        print(f"    {i}  {name}")
    choice = input("\n  > ").strip()
    try:
        return found[int(choice) - 1]
    except (ValueError, IndexError):
        return None


def _normalize_argv(argv: list[str]) -> list[str]:
    """
    Make the interactive session the default.

        rh.py                 → find a database nearby, open the menu
        rh.py target.i64      → open the menu on it
        rh.py map target.i64  → the explicit command, unchanged

    Subcommands stay available for scripting; nobody has to remember them.
    """
    if not argv:
        db = _discover_database()
        if db is None:
            return []
        return ["menu", db]
    first = argv[0]
    if first in _COMMANDS or first.startswith("-"):
        return argv
    return ["menu"] + argv


def main() -> None:
    parser = _build_parser()
    argv = _normalize_argv(sys.argv[1:])

    if not argv:
        parser.print_help()
        print(f"\n  No {' or '.join(_DB_SUFFIXES)} file in this directory.\n"
              f"  Point it at one:  python rh.py /path/to/target.i64\n")
        sys.exit(1)

    args, extras = parser.parse_known_args(argv)

    if not getattr(args, "func", None):
        parser.print_help()
        sys.exit(1)

    # A bare question placed after a flag lands in `extras` rather than in the
    # `query` positional. Fold those back in; anything else is a genuine typo.
    if args.command == "ask":
        words = list(args.query) + [e for e in extras if not e.startswith("-")]
        extras = [e for e in extras if e.startswith("-")]
        args.query = " ".join(words)

    if extras:
        parser.error(f"unrecognized arguments: {' '.join(extras)}")

    args.func(args)


if __name__ == "__main__":
    main()
