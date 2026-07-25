"""
Interactive session — the copilot front end.

Opens the IDA database once and holds it for the whole session, so browsing the
map is instant. The map (options 1-4) costs nothing. The analysis options
(5-9) always quote what they will spend before spending it.

The ordering is deliberate: you look at the map first and pick a target, then
point the LLM at it. "Analyze everything" is last because on a real binary it
is an overnight job and almost never the right move.
"""

from __future__ import annotations

import os

from . import mapview, navigate, pipeline
from . import ask as ask_mod
from .call_graph import load_or_build
from .export import export_review
from .kb import KnowledgeBase
from .workspace import Workspace

_SEP = "─" * 76


class Session:
    def __init__(self, config: dict, workspace: Workspace, extractor) -> None:
        self.config = config
        self.ws = workspace
        self.extractor = extractor
        self.graph = None
        self.last_selection: list[int] = []

    # ------------------------------------------------------------------
    # Startup
    # ------------------------------------------------------------------

    def start(self) -> None:
        print(f"\n  research helper — {os.path.basename(self.ws.db_path)}")
        self._load_graph()
        while True:
            try:
                if not self._menu():
                    break
            except KeyboardInterrupt:
                print("\n[rh] Interrupted. Type 'q' to quit.\n")
            except EOFError:
                break
        print("\n[rh] Leaving the session.")

    def _load_graph(self) -> None:
        if self.ws.has_graph():
            self.graph = mapview.load_graph(self.ws)
            print(f"[rh] Call graph loaded — {len(self.graph.nodes)} functions.")
            return
        print("\n[rh] No call graph yet. It maps the whole binary and powers "
              "every\n     option below. It uses no LLM calls, but takes a few "
              "minutes.")
        if _yes("Build it now?", default=True):
            self.graph = load_or_build(
                self.extractor, self.config, self.ws.call_graph
            )

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def _header(self) -> None:
        stats = {"analyzed": 0, "security": 0, "pending_apply": 0}
        if os.path.exists(self.ws.kb):
            kb = KnowledgeBase(self.ws.kb)
            stats = kb.stats()
            kb.close()
        spc = pipeline.seconds_per_call(self.ws)
        rate = f"{spc:.1f}s per function" if spc else "speed not measured yet"
        graph = f"{len(self.graph.nodes)} functions" if self.graph else "not built"

        print(f"\n{_SEP}")
        print(f"  {os.path.basename(self.ws.db_path)}   graph: {graph}   {rate}")
        print(f"  analyzed: {stats['analyzed']}   "
              f"security-flagged: {stats['security']}   "
              f"ready to apply: {stats['pending_apply']}")
        print(_SEP)

    def _menu(self) -> bool:
        self._header()
        print("""  MAP — instant, no LLM
    1  Overview            size, entry points, imports, landmarks
    2  Suspicious          ranked by score
    3  Find                by name, string or imported API
    4  Explore             one function and its neighbours

  ANALYZE — uses the LLM, cost quoted first
    5  One function
    6  Around a function   its callees and/or callers
    7  A call path         entry -> sink, or between two functions
    8  Top N suspicious
    9  Everything          (the overnight run)

  RESULTS
    a  Ask     s  Status     p  Apply to database     e  Export
    m  Maintenance           q  Quit""")

        choice = input("\n  > ").strip().lower()
        actions = {
            "1": self._overview, "2": self._suspicious, "3": self._find,
            "4": self._explore, "5": self._one, "6": self._around,
            "7": self._path, "8": self._top_n, "9": self._everything,
            "a": self._ask, "s": self._status, "p": self._apply,
            "e": self._export, "m": self._maintenance,
        }
        if choice in ("q", "quit", "exit"):
            return False
        action = actions.get(choice)
        if action is None:
            print("  Unrecognised choice.")
            return True
        # Option 5 works from IDA alone; everything else on the map and scope
        # side needs the graph.
        if self.graph is None and choice in {"1", "2", "3", "4", "6", "7", "8"}:
            print("  That needs the call graph — restart and build it first.")
            return True
        action()
        return True

    # ------------------------------------------------------------------
    # Map actions (free)
    # ------------------------------------------------------------------

    def _overview(self) -> None:
        mapview.overview(self.graph, self.config, self.ws)

    def _suspicious(self) -> None:
        n = _int("How many?", 25)
        only = _yes("Only still-unnamed functions?", default=True)
        self.last_selection = mapview.suspicious(
            self.graph, self.config, self.ws, top=n, unnamed_only=only
        )
        self._offer_analyze(self.last_selection, f"top {n} suspicious")

    def _find(self) -> None:
        q = input("  Name, string or API to search for: ").strip()
        if not q:
            return
        self.last_selection = mapview.find(self.graph, self.config, self.ws, q)
        self._offer_analyze(self.last_selection, f'matches for "{q}"')

    def _explore(self) -> None:
        addr = self._resolve("Function (name or 0xADDR): ")
        if addr is None:
            return
        mapview.explore(self.graph, self.config, self.ws, addr)
        self.last_selection = [addr]

    # ------------------------------------------------------------------
    # Analysis actions (cost quoted)
    # ------------------------------------------------------------------

    def _one(self) -> None:
        addr = self._resolve("Function (name or 0xADDR): ")
        if addr is None:
            return
        self._analyze([addr], f"0x{addr:X}", reanalyze=True)

    def _around(self) -> None:
        addr = self._resolve("Function (name or 0xADDR): ")
        if addr is None:
            return
        print("\n    1  What it calls        (understand this function)")
        print("    2  What calls it        (how is it reached)")
        print("    3  Both")
        direction = input("  > ").strip() or "1"
        depth = _int("Depth (hops)", 2)

        selection: list[int] = []
        if direction in ("1", "3"):
            selection += navigate.descendants(self.graph, addr, depth)
        if direction in ("2", "3"):
            selection += navigate.ancestors(self.graph, addr, depth)
        selection = list(dict.fromkeys(selection))

        label = {"1": "callees", "2": "callers", "3": "neighbourhood"}.get(
            direction, "callees")
        mapview._render(self.graph, selection, self.config, self.ws,
                        f"{label} of 0x{addr:X}, depth {depth}", limit=60)
        self._analyze(selection, f"{label} of 0x{addr:X} (depth {depth})")

    def _path(self) -> None:
        print("\n    1  Entry point -> memory sink   (how does data reach it)")
        print("    2  Between two functions")
        mode = input("  > ").strip() or "1"

        if mode == "2":
            src = self._resolve("From (name or 0xADDR): ")
            if src is None:
                return
            dst = self._resolve("To (name or 0xADDR): ")
            if dst is None:
                return
            paths = navigate.paths_between(self.graph, src, dst)
            title = f"Paths 0x{src:X} -> 0x{dst:X}"
        else:
            start = None
            if _yes("Start from a specific function?", default=False):
                start = self._resolve("Start (name or 0xADDR): ")
            limit = _int("How many sinks to trace?", 10)
            paths = navigate.paths_to_sinks(
                self.graph, self.config, limit=limit, start=start
            )
            title = "Entry point -> memory sink"

        mapview.show_paths(self.graph, paths, title)
        selection = list(dict.fromkeys(a for p in paths for a in p))
        self._analyze(selection, title.lower())

    def _top_n(self) -> None:
        n = _int("How many of the top-scoring functions?", 50)
        selection = navigate.top_scored(self.graph, self.config, n * 3)
        selection = navigate.unnamed_only(self.graph, selection, self.config)[:n]
        mapview._render(self.graph, selection, self.config, self.ws,
                        f"Top {len(selection)} unnamed by score", limit=n)
        self._analyze(selection, f"top {n} by score")

    def _everything(self) -> None:
        print("\n  This analyzes every auto-named function in the binary.")
        print("  On a real target that is usually hours. Options 5-8 are")
        print("  almost always the better move.")
        if not _yes("Continue anyway?", default=False):
            return
        pipeline.analyze(
            self.config, self.ws, self.extractor,
            all_functions=True, label="every auto-named function",
            confirm=_confirm_plan,
        )

    # ------------------------------------------------------------------
    # Results
    # ------------------------------------------------------------------

    def _ask(self) -> None:
        if not os.path.exists(self.ws.kb):
            print("  Nothing analyzed yet.")
            return
        q = input("  Question (blank for the security report): ").strip()
        kb = KnowledgeBase(self.ws.kb)
        try:
            if not q:
                ask_mod.security_report(kb)
                return
            embedder = ask_mod._load_embedder(self.config, self.ws, kb)
            if embedder is None:
                ask_mod.confidence_query(kb, 20, False)
            else:
                ask_mod.semantic_query(kb, embedder, q, 20, False)
        finally:
            kb.close()

    def _status(self) -> None:
        ask_mod.status(self.config, self.ws, show_next=False)

    def _maintenance(self) -> None:
        print("\n    1  Rebuild the call graph      (no LLM, takes minutes)")
        print("    2  Rebuild the search index    (re-embeds every summary)")
        print("    3  Change the model            "
              f"(currently {self.config['ollama']['model']})")
        print("    4  Delete all analysis results (cannot be undone)")
        print("    b  Back")
        choice = input("  > ").strip().lower()

        if choice == "1":
            self.graph = load_or_build(self.extractor, self.config,
                                       self.ws.call_graph, force_rebuild=True)
        elif choice == "2":
            ask_mod.build_index(self.config, self.ws)
        elif choice == "3":
            new = input(f"  Model [{self.config['ollama']['model']}]: ").strip()
            if new:
                self.config["ollama"]["model"] = new
                print(f"  Using {new} for this session. To make it permanent, "
                      "edit llm_renamer/config.json")
        elif choice == "4":
            if not os.path.exists(self.ws.kb):
                print("  Nothing to delete.")
                return
            kb = KnowledgeBase(self.ws.kb)
            n = kb.stats()["analyzed"]
            kb.close()
            print(f"\n  This deletes {n} analyzed function(s) and every rename "
                  "proposal.\n  Renames already written into the database are "
                  "NOT undone.")
            if _yes("  Really delete?", default=False):
                kb = KnowledgeBase(self.ws.kb)
                removed = kb.reset()
                kb.close()
                print(f"  Deleted {removed} result(s).")

    def _apply(self) -> None:
        kb = KnowledgeBase(self.ws.kb) if os.path.exists(self.ws.kb) else None
        pending = kb.stats()["pending_apply"] if kb else 0
        if kb:
            kb.close()
        if not pending:
            print("  Nothing ready to apply.")
            return
        pipeline.apply(self.config, self.ws, self.extractor, dry_run=True)
        if _yes(f"\n  Write these {pending} rename(s) into the database?",
                default=False):
            pipeline.apply(self.config, self.ws, self.extractor)

    def _export(self) -> None:
        if not os.path.exists(self.ws.kb):
            print("  Nothing analyzed yet.")
            return
        kb = KnowledgeBase(self.ws.kb)
        n = export_review(kb, self.ws.review)
        kb.close()
        print(f"  Wrote {n} proposal(s) to {self.ws.review}")

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _offer_analyze(self, selection: list[int], label: str) -> None:
        if selection and _yes(f"\n  Analyze these {len(selection)} with the LLM?",
                              default=False):
            self._analyze(selection, label)

    def _analyze(self, selection: list[int], label: str,
                 reanalyze: bool = False) -> None:
        if not selection:
            print("  Nothing selected.")
            return

        # If the whole selection is already done, offer to redo it here rather
        # than printing a flag the user would have to leave the session to use.
        if not reanalyze:
            plan = pipeline.build_plan(
                self.config, self.ws, self.extractor, self.graph,
                addresses=selection, label=label,
            )
            if not plan.todo and plan.already_done:
                print(f"\n  All {plan.already_done} of these are already "
                      "analyzed.")
                if not _yes("  Analyze them again?", default=False):
                    return
                reanalyze = True

        pipeline.analyze(
            self.config, self.ws, self.extractor,
            addresses=selection, label=label, reanalyze=reanalyze,
            confirm=_confirm_plan, graph=self.graph,
        )

    def _resolve(self, prompt: str) -> int | None:
        """Turn typed input into an address, via the graph or IDA."""
        raw = input(f"  {prompt}").strip()
        if not raw:
            return None
        if raw.lower().startswith("0x"):
            try:
                return int(raw, 16)
            except ValueError:
                pass
        if self.graph:
            exact = [a for a, n in self.graph.nodes.items() if n.name == raw]
            if exact:
                return exact[0]
            partial = [a for a, n in self.graph.nodes.items()
                       if raw.lower() in n.name.lower()]
            if len(partial) == 1:
                return partial[0]
            if len(partial) > 1:
                print(f"  {len(partial)} functions match — showing the first 10:")
                for a in partial[:10]:
                    print(navigate.describe(self.graph, a, self.config))
                return None
        rows = self.extractor.get_functions_by_name([raw])
        if rows:
            return int(rows[0]["address"])
        print(f"  Not found: {raw!r}")
        return None


# ---------------------------------------------------------------------------
# Prompt helpers
# ---------------------------------------------------------------------------

def _confirm_plan(plan, spc) -> bool:
    return _yes("  Go ahead?", default=True)


def _yes(question: str, default: bool = False) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    answer = input(f"{question} {suffix} ").strip().lower()
    if not answer:
        return default
    return answer.startswith("y")


def _int(question: str, default: int) -> int:
    raw = input(f"  {question} [{default}] ").strip()
    try:
        return max(1, int(raw))
    except ValueError:
        return default


def run(config: dict, workspace: Workspace, extractor) -> None:
    Session(config, workspace, extractor).start()
