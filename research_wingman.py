#!/usr/bin/env python3
"""
research-wingman — a copilot for reverse engineering an IDA Pro database.

Just point it at a database — or a raw sample, and it builds one first:

    python research_wingman.py target.i64             overview: entry points, imports, size
    python research_wingman.py                        finds a database here, same overview
    python research_wingman.py sample.elf --all       point at a sample and walk away —
                                                        builds the database, asks which
                                                        profile, then analyzes everything

The call graph is a free map of the binary. The LLM is an expensive lens you
point at one place on that map. So: look first, then spend.

    research_wingman.py map target.i64                  overview: entry points, imports, size
    research_wingman.py map target.i64 --suspicious     what's worth looking at
    research_wingman.py map target.i64 --find "recv"    search names, strings, imported APIs
    research_wingman.py map target.i64 --explore sub_x  one function and its neighbours

    research_wingman.py analyze target.i64 -f sub_401a30      one function + its callees
    research_wingman.py analyze target.i64 --top 50           highest-scoring unnamed functions
    research_wingman.py analyze target.i64 --all               every auto-named function

    research_wingman.py apply  target.i64               write approved renames into the database
    research_wingman.py ask    target.i64 "question"    search what was learned
    research_wingman.py status target.i64               what has been done so far
    research_wingman.py export target.i64               dump everything to review.json

    research_wingman.py diff old.i64 patched.i64 --pair sub_401000 sub_402100
                                                          old vs patched, function by function

    research_wingman.py batch samples/ --profile malware
                                                          full --all pipeline, one sample at
                                                          a time, for every sample in a folder

Everything under `map` is instant and costs nothing. Everything under
`analyze` quotes its cost before spending it, and needs an explicit scope —
there is no accidental overnight run.

State lives in <database>.wingman/ next to the database, so it follows the binary
rather than the directory you happen to run from.

`analyze` never modifies the database. `apply` never calls the LLM.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from llm_renamer import ask as ask_mod
from llm_renamer.config import load_config
from llm_renamer.export import export_review
from llm_renamer.kb import KnowledgeBase
from llm_renamer.llm_client import LLMError
from llm_renamer.prompts import SYSTEM_PROMPTS as _PROFILES
from llm_renamer.workspace import Workspace, warn_if_legacy_state_nearby


# ==========================================================================
# Setup shared by every command
# ==========================================================================

def _ensure_database(path: str, allow_create: bool) -> str:
    """If `path` isn't already an IDA database, resolve to `<path>.i64` --
    building it from scratch (full auto-analysis, needs IDA) only when
    `allow_create` is set.

    `allow_create=False` still resolves to an existing `<path>.i64` (so a
    command pointed at a raw sample it's already analyzed gets consistent
    workspace naming), but never spends the several minutes building one that
    isn't there -- correct for `ask`/`status`/`export`/plain `map`, none of
    which touch IDA at all (README: "only analyze, apply, and map
    --build need IDA"). A raw sample with nothing built yet just falls
    through to those commands' existing "no analysis found" checks instead of
    silently paying for an unwanted analysis pass first.

    idalib can't safely reuse a session across two open_database() calls in
    one process (a second open after closing the first hangs silently), so
    the actual creation happens in a fresh subprocess -- same reasoning as
    `_extract-pseudocode`. Point the tool at a raw sample and this is what
    replaces the manual "open in IDA, wait, save, then run the CLI" dance.
    """
    if path.lower().endswith((".i64", ".idb")):
        return path
    i64_path = path + ".i64"
    if os.path.exists(i64_path):
        return i64_path
    if not allow_create:
        return path
    print(f"[wingman] {os.path.basename(path)} isn't an IDA database yet — "
          f"building one now (full auto-analysis, needs IDA; can take a few "
          f"minutes on a large binary)…")
    result = subprocess.run(
        [sys.executable, os.path.abspath(__file__), "_create-database", path],
    )
    if result.returncode != 0 or not os.path.exists(i64_path):
        _die(f"failed to create a database from {path}")
    return i64_path


_PROFILE_BLURBS = {
    "vuln_research": "memory-safety bugs in real software (default)",
    "malware": "malicious capability triage — C2, persistence, evasion, propagation",
}


def _prompt_for_profile(default: str) -> str:
    names = sorted(_PROFILES)
    print("\n  Which analysis profile?\n")
    for i, name in enumerate(names, 1):
        blurb = _PROFILE_BLURBS.get(name, "")
        mark = "  <- default" if name == default else ""
        print(f"    {i}  {name:<15} {blurb}{mark}")
    try:
        choice = input("\n  > ").strip()
    except EOFError:
        choice = ""
    if not choice:
        return default
    try:
        return names[int(choice) - 1]
    except (ValueError, IndexError):
        print(f"[wingman] Didn't understand {choice!r} — using {default}.")
        return default


def cmd_create_database(args) -> None:
    """Hidden, internal: build a fresh IDA database from a raw binary with
    full auto-analysis. Invoked via subprocess by `_ensure_database` -- never
    typed directly."""
    import idapro
    print(f"[wingman] Opening {os.path.basename(args.database)} "
          f"with full auto-analysis…")
    idapro.open_database(args.database, run_auto_analysis=True)
    import ida_auto
    ida_auto.auto_wait()
    import idautils
    n = len(list(idautils.Functions()))
    print(f"[wingman] Analysis complete — {n} function(s) identified.")
    idapro.close_database(save=True)


def _prepare(args, allow_create: bool = False) -> tuple[dict, Workspace]:
    db_path = os.path.abspath(args.database)
    if not os.path.exists(db_path):
        _die(f"database not found: {db_path}")
    db_path = _ensure_database(db_path, allow_create)

    config = load_config(args.config)
    if getattr(args, "ollama_url", None):
        config["ollama"]["url"] = args.ollama_url
    if getattr(args, "model", None):
        config["ollama"]["model"] = args.model
    if getattr(args, "profile", None):
        config["analysis"]["profile"] = args.profile

    workspace = Workspace(db_path, args.workspace)
    warn_if_legacy_state_nearby(workspace)
    return config, workspace


def _die(message: str) -> None:
    print(f"[wingman] ERROR: {message}")
    sys.exit(1)


def _check_ollama(config: dict) -> None:
    from llm_renamer.llm_client import OllamaClient
    llm = OllamaClient(config)
    resolved = llm.resolve_model()
    if resolved is None:
        _die(
            f"Ollama is not reachable at {config['ollama']['url']}, or has no "
            f"models installed.\n"
            f"       Start it with:  ollama run {config['ollama']['model']}"
        )
    model, changed = resolved
    if changed:
        print(f"[wingman] '{config['ollama']['model']}' not found on "
              f"{config['ollama']['url']} — using '{model}' instead "
              f"(largest model available there).")
        config["ollama"]["model"] = model
    else:
        print(f"[wingman] Ollama OK ({model})")


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
                 "       `research_wingman.py map` / `ask` / `status` / `export` work without it.")
        self._idapro = idapro
        # Quiet IDA's own console chatter ("Database initialized, you need to
        # call auto_wait()", etc.) -- benign but noisy, and it flushes late so
        # it lands after our own output and reads like something went wrong.
        # Best-effort: older idalib builds may not expose this.
        try:
            idapro.enable_console_messages(False)
        except Exception:
            pass
        print(f"[wingman] Opening {os.path.basename(self._db_path)}…")
        idapro.open_database(self._db_path, run_auto_analysis=False)
        from llm_renamer.idapro_client import FunctionContextExtractor
        return FunctionContextExtractor

    def __exit__(self, *_):
        self._idapro.close_database()


# ==========================================================================
# Commands
# ==========================================================================


def _resolve_scope(args, graph, extractor, config, workspace):
    """Turn the scope flags into (addresses, functions, label, force)."""
    from llm_renamer import navigate

    needs_graph = args.top is not None
    if needs_graph and graph is None:
        _die("that scope needs the call graph.\n"
             f"       Build it once:  research_wingman.py map {os.path.basename(args.database)} --build")

    if args.function:
        names = [f for item in args.function for f in item.split(",") if f]
        if graph is None:
            # No cached graph: analyze exactly the named functions, no callee
            # expansion -- this is what makes `-f` usable without paying for
            # a whole-program graph build first. Resolve to addresses (not
            # just names) and populate `force` from them, same as the graph
            # branch below -- without this, an explicit -f target that isn't
            # `sub_`-prefixed (e.g. a named-but-meaningless garble-obfuscated
            # Go function like `main.dulqs`) is silently dropped by
            # build_plan's is_analysis_candidate filter, breaking the
            # documented invariant that an explicit -f target is always kept
            # even if already named (see build_plan's docstring).
            rows = extractor.get_functions_by_name(names)
            addrs = [int(r["address"]) for r in rows]
            return addrs, None, f"{len(addrs)} named function(s)", set(addrs)
        # Graph available: pull in each target's full callee subtree (the
        # project's standard scope-expansion pattern -- see
        # navigate.full_subtree) so it's analyzed leaves-first with real
        # callee summaries in context, instead of the LLM seeing bare sub_*
        # names it knows nothing about. Mirrors what the interactive menu's
        # "one function" option already did. The named targets themselves
        # are always (re)analyzed via `force`; callees pulled in for context
        # are skipped if already analyzed.
        targets = []
        for name in names:
            addr = navigate.resolve_one(graph, name, extractor, config, workspace)
            if addr is None:
                sys.exit(1)
            targets.append(addr)
        addrs = navigate.full_subtree(graph, list(dict.fromkeys(targets)))
        extra = len(addrs) - len(targets)
        label = (f"{len(targets)} named function(s)"
                 + (f" + {extra} callee(s)" if extra else ""))
        return addrs, None, label, set(targets)

    if args.top is not None:
        addrs = navigate.top_scored(graph, config, args.top * 3)
        addrs = navigate.unnamed_only(graph, addrs, config)[:args.top]
        # Score-based selection has no regard for whether a picked function's
        # neighbours are also picked, so it routinely lands functions with
        # zero real context: no analyzed caller or callee to inform the
        # prompt. Same standard expansion as every other scope -- see
        # navigate.full_subtree.
        addrs = navigate.full_subtree(graph, addrs)
        return addrs, None, f"top {args.top} by score", None

    return None, None, "every auto-named function", None


def cmd_analyze(args) -> None:
    from llm_renamer import pipeline

    config, workspace = _prepare(args, allow_create=True)

    if not getattr(args, "profile", None):
        config["analysis"]["profile"] = _prompt_for_profile(config["analysis"]["profile"])

    _check_ollama(config)

    with _OpenDatabase(workspace.db_path) as Extractor:
        extractor = Extractor(config)
        graph = pipeline.resolve_graph(
            config, workspace, extractor,
            targeted=not args.all,
        )
        addresses, functions, label, force = _resolve_scope(
            args, graph, extractor, config, workspace
        )
        confirm = None if args.yes else _confirm_cost
        pipeline.analyze(
            config, workspace, extractor,
            addresses=addresses,
            functions=functions,
            all_functions=addresses is None and functions is None,
            label=label,
            limit=args.limit,
            refine=not args.no_refine,
            reanalyze=args.redo,
            confirm=confirm,
            graph=graph,
            force=force,
            apply_immediately=not args.no_apply,
        )

        if not args.no_apply:
            # Apply is the default: approved renames are written straight into
            # the database. Reuses the already-open database (no second
            # open/close round trip). `analyze()` and `apply()` are still two
            # distinct functions internally -- only chained here -- and the
            # write step keeps every safeguard: it refuses to overwrite an
            # analyst's name and is idempotent. Opt out with --no-apply (then
            # preview with `research_wingman.py apply --dry-run`).
            print("[wingman] Writing approved renames into the database "
                  "(use --no-apply to skip)…")
            pipeline.apply(config, workspace, extractor, dry_run=False)

    # Outside the `with _OpenDatabase` block on purpose -- report generation
    # only needs the KB + cached call graph, not IDA/extractor, so closing
    # IDA first frees the licence seat sooner. Gated on `--all` (a full scan,
    # not a partial scope where a "malware capability report" would be
    # misleading) and the *resolved* profile (config["analysis"]["profile"],
    # not args.profile directly -- the profile can be filled in interactively
    # above when --profile wasn't passed, and only the config value reflects
    # that). vuln_research gets no auto-report: the capability/IOC template
    # doesn't fit a legitimate-software bug-hunting run.
    if args.all and config["analysis"]["profile"] == "malware" and not args.no_report:
        from llm_renamer import report as report_mod
        from llm_renamer.kb import KnowledgeBase
        print("[wingman] Generating capability report…")
        kb = KnowledgeBase(workspace.kb)
        text, meta = report_mod.generate_capability_report(config, kb, graph)
        kb.close()
        out_path = os.path.join(workspace.dir, "capability_report.md")
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"[wingman] Report written to {out_path} "
              f"({meta['function_count']} functions, num_ctx={meta['num_ctx']})")


def _confirm_cost(plan, seconds_per_call) -> bool:
    return input("  Go ahead? [Y/n] ").strip().lower() in ("", "y", "yes")


def cmd_map(args) -> None:
    from llm_renamer import mapview, navigate
    from llm_renamer.call_graph import load_or_build

    config, workspace = _prepare(args, allow_create=args.build)

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
        addr = navigate.resolve_one(graph, args.explore, None, config, workspace)
        if addr is None:
            sys.exit(1)
        mapview.explore(graph, config, workspace, addr)
    elif args.suspicious is not None:
        mapview.suspicious(graph, config, workspace,
                           top=args.suspicious, unnamed_only=True)
    elif args.paths is not None:
        paths = navigate.paths_to_sinks(graph, config, limit=args.paths)
        mapview.show_paths(graph, paths, "Entry point -> memory sink")
    else:
        mapview.overview(graph, config, workspace)


def cmd_apply(args) -> None:
    from llm_renamer import pipeline

    config, workspace = _prepare(args, allow_create=True)

    if not os.path.exists(workspace.kb):
        _die(f"no analysis found in {workspace.dir}\n"
             f"       Run:  research_wingman.py analyze {os.path.basename(workspace.db_path)}")

    kb = KnowledgeBase(workspace.kb)
    pending = kb.stats()["pending_apply"]
    kb.close()

    if not args.dry_run and pending and not args.yes:
        print(f"[wingman] This will write {pending} rename(s) and comment(s) "
              f"into {os.path.basename(workspace.db_path)}.")
        if input("Proceed? [y/N] ").strip().lower() != "y":
            print("Aborted.")
            return

    with _OpenDatabase(workspace.db_path) as Extractor:
        pipeline.apply(
            config, workspace, Extractor(config),
            dry_run=args.dry_run,
        )


def cmd_ask(args) -> None:
    config, workspace = _prepare(args)

    if not os.path.exists(workspace.kb):
        _die(f"no analysis found in {workspace.dir}\n"
             f"       Run:  research_wingman.py analyze {os.path.basename(workspace.db_path)}")

    kb = KnowledgeBase(workspace.kb)
    try:
        if args.report:
            ask_mod.security_report(kb)
            return
        if not args.query:
            _die("provide a question, or use --report")

        embedder = ask_mod._load_embedder(config, workspace, kb)
        if embedder is None:
            # Be explicit that the fallback does NOT use the query text --
            # confidence_query ranks *everything*, so returning a list here
            # without saying so reads as if the question was searched when it
            # was ignored. (pip install faiss-cpu numpy to enable real search.)
            print(f'\n[wingman] Semantic search unavailable — your query '
                  f'"{args.query}" was NOT used; showing the highest-confidence '
                  f'functions instead. Install faiss-cpu + numpy for real search.')
            ask_mod.confidence_query(kb, args.top, args.security_only)
            return

        ask_mod.semantic_query(
            kb, embedder, args.query, args.top, args.security_only, config
        )
    finally:
        kb.close()


def cmd_status(args) -> None:
    config, workspace = _prepare(args)
    ask_mod.status(config, workspace)


def cmd_report(args) -> None:
    """Regenerate the capability report from an existing KB + cached call
    graph -- no IDA session needed, same category as `ask`/`status`."""
    config, workspace = _prepare(args)
    if getattr(args, "ollama_url", None):
        config["ollama"]["url"] = args.ollama_url
    if getattr(args, "model", None):
        config["ollama"]["model"] = args.model

    if not os.path.exists(workspace.kb):
        _die(f"no analysis yet for this database -- run "
             f"`research_wingman.py {os.path.basename(workspace.db_path)} --all` first")
    if not workspace.has_graph():
        _die(f"no call graph yet -- run "
             f"`research_wingman.py map {os.path.basename(workspace.db_path)} --build` first")

    _check_ollama(config)

    from llm_renamer import report as report_mod
    from llm_renamer.call_graph import CallGraph
    from llm_renamer.kb import KnowledgeBase

    graph = CallGraph.load(workspace.call_graph)
    kb = KnowledgeBase(workspace.kb)
    print("[wingman] Generating capability report…")
    text, meta = report_mod.generate_capability_report(config, kb, graph)
    kb.close()

    out_path = os.path.join(workspace.dir, "capability_report.md")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"[wingman] Report written to {out_path} "
          f"({meta['function_count']} functions, num_ctx={meta['num_ctx']})")


def _default_diff_out(old_path: str, patched_path: str) -> str:
    workspace = Workspace(patched_path)
    old_base = os.path.splitext(os.path.basename(old_path))[0]
    return os.path.join(workspace.dir, f"diff_vs_{old_base}.json")


def cmd_extract_pseudocode(args) -> None:
    """Internal: open exactly one database, extract pseudocode for the given
    refs, write JSON, exit. Not meant to be typed directly -- `diff` shells
    out to this once per database (see its docstring for why: idalib does
    not support opening a second database in the same process after closing
    the first, it hangs)."""
    config = load_config(args.config)
    db_path = os.path.abspath(args.database)
    if not os.path.exists(db_path):
        _die(f"database not found: {db_path}")

    out: dict[str, dict] = {}
    with _OpenDatabase(db_path) as Extractor:
        extractor = Extractor(config)
        for ref in args.addr:
            rows = extractor.get_functions_by_name([ref])
            if not rows:
                _die(f"not found in {os.path.basename(db_path)}: {ref}")
            row = rows[0]
            out[ref] = {
                "address": row["address"],
                "name": row["name"],
                "pseudocode": extractor.pseudocode(row["address"], args.max_lines),
            }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out, f)


def _extract_pseudocode_subprocess(db_path: str, refs: list[str],
                                    max_lines: int, config_path: str | None) -> dict[str, dict]:
    """Run `research_wingman.py _extract-pseudocode` as a fresh subprocess so
    it gets its own idalib session -- see cmd_extract_pseudocode's docstring."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out_path = tmp.name
    try:
        cmd = [sys.executable, os.path.abspath(__file__), "_extract-pseudocode",
               db_path, "--max-lines", str(max_lines), "--out", out_path]
        for ref in refs:
            cmd += ["--addr", ref]
        if config_path:
            cmd += ["--config", config_path]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            _die(f"extracting from {os.path.basename(db_path)} failed:\n"
                 f"{proc.stdout}\n{proc.stderr}")
        with open(out_path, "r", encoding="utf-8") as f:
            return json.load(f)
    finally:
        if os.path.exists(out_path):
            os.remove(out_path)


def cmd_diff(args) -> None:
    from llm_renamer import diff as diff_mod

    config = load_config(args.config)
    if getattr(args, "ollama_url", None):
        config["ollama"]["url"] = args.ollama_url
    if getattr(args, "model", None):
        config["ollama"]["model"] = args.model

    old_path = os.path.abspath(args.old_database)
    patched_path = os.path.abspath(args.patched_database)
    if not os.path.exists(old_path):
        _die(f"database not found: {old_path}")
    if not os.path.exists(patched_path):
        _die(f"database not found: {patched_path}")

    out_path = os.path.abspath(args.out) if args.out else _default_diff_out(old_path, patched_path)

    pairing_report = None  # only set for --auto; written into the output report
                            # below so noise/candidate/new/removed classifications
                            # stay auditable -- nothing gets silently dropped.
    new_fns_meta: list[dict] = []      # patched-only functions to summarize
    removed_fns_meta: list[dict] = []  # old-only functions to summarize
    related_patch: dict[int, list] = {}
    related_old: dict[int, list] = {}

    if args.auto:
        from llm_renamer import autopair
        old_workspace = Workspace(old_path)
        patched_workspace = Workspace(patched_path)
        if not old_workspace.has_graph() or not patched_workspace.has_graph():
            _die("--auto needs the call graph built for both databases first.\n"
                 f"       research_wingman.py map {os.path.basename(old_path)} --build\n"
                 f"       research_wingman.py map {os.path.basename(patched_path)} --build")

        print(f"[wingman] Auto-pairing functions (no BinDiff -- name match + "
              f"structural fallback)…")
        full = autopair.auto_pair_full(old_workspace.call_graph, patched_workspace.call_graph)
        classified = full["classified"]
        related_patch, related_old = full["related_patch"], full["related_old"]
        # Leaves-first: a function called by other new/removed functions in
        # this same set gets summarized before its callers, so those callers'
        # related-notes can quote its summary (see summary_lookup below).
        new_fns_meta = autopair.sort_leaves_first(full["new"], related_patch)
        removed_fns_meta = autopair.sort_leaves_first(full["removed"], related_old)
        noise_new, noise_removed = full["noise_new"], full["noise_removed"]
        by_cat = defaultdict(list)
        for r in classified:
            by_cat[r["category"]].append(r)
        promoted = sum(1 for r in by_cat["candidate"] if r.get("promoted_by_constants"))
        print(f"[wingman] paired={len(classified)}  unchanged={len(by_cat['unchanged'])}  "
              f"noise={len(by_cat['noise'])}  candidate={len(by_cat['candidate'])}"
              + (f" ({promoted} promoted by changed constants)" if promoted else "") +
              f"  new={len(new_fns_meta)} (+{len(noise_new)} noise)  "
              f"removed={len(removed_fns_meta)} (+{len(noise_removed)} noise)")
        # `unchanged` means identical size/block-count AND identical tracked
        # constant operands (see autopair.classify) -- keep the report to a
        # reasonable size by recording just its count, but keep every other
        # category in full since those are the classifications worth being
        # able to double-check. noise_new/noise_removed follow the same
        # policy as matched-pair noise: recorded, never sent to the LLM.
        pairing_report = {
            "paired": len(classified), "unchanged_count": len(by_cat["unchanged"]),
            "noise": [{k: v for k, v in r.items() if k != "category"} for r in by_cat["noise"]],
            "candidate": [{k: v for k, v in r.items() if k != "category"} for r in by_cat["candidate"]],
            "new": new_fns_meta, "removed": removed_fns_meta,
            "new_noise": noise_new, "removed_noise": noise_removed,
        }

        if not by_cat["candidate"] and not new_fns_meta and not removed_fns_meta:
            print("[wingman] Nothing candidate, new, or removed -- nothing to diff.")
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump({"pairing": pairing_report, "diffs": []}, f, indent=2)
            print(f"[wingman] Wrote pairing report (no diffs) to {out_path}")
            return

        pairs = [(f'0x{r["old_address"]:X}', f'0x{r["patched_address"]:X}') for r in by_cat["candidate"]]
    else:
        pairs = args.pair

    _check_ollama(config)

    old_refs = [old_ref for old_ref, _ in pairs] + [f'0x{f["address"]:X}' for f in removed_fns_meta]
    patched_refs = [patched_ref for _, patched_ref in pairs] + [f'0x{f["address"]:X}' for f in new_fns_meta]

    print(f"[wingman] Extracting {len(old_refs)} function(s) from {os.path.basename(old_path)}…")
    old_fns = _extract_pseudocode_subprocess(old_path, old_refs, args.max_lines, args.config)
    print(f"[wingman] Extracting {len(patched_refs)} function(s) from {os.path.basename(patched_path)}…")
    patched_fns = _extract_pseudocode_subprocess(patched_path, patched_refs, args.max_lines, args.config)

    # Filled in as new/removed functions get summarized, below -- so that by
    # the time a candidate (or a later new/removed function) asks about a
    # neighbour, its summary is usually already available to quote instead of
    # just naming it. new/removed go leaves-first specifically to maximize
    # that (see autopair.sort_leaves_first); candidates go last since they're
    # the most likely to reference a new/removed helper.
    summary_lookup: dict[int, str] = {}

    def related_note_for(old_addr: int | None, patched_addr: int | None) -> str:
        raw: list[tuple[int, str, str]] = []
        if patched_addr is not None:
            raw += related_patch.get(patched_addr, [])
        if old_addr is not None:
            raw += related_old.get(old_addr, [])
        enriched = [(name, rel, summary_lookup.get(addr, "")) for addr, name, rel in raw]
        enriched = list(dict.fromkeys(enriched))  # de-dup: same neighbour can show up from both sides
        return diff_mod.format_related_note(enriched, config=config)

    results = []

    def save_progress() -> None:
        # Written after EVERY item, not just at the end -- a single malformed
        # LLM response used to raise uncaught and discard the whole run's
        # results (confirmed live 2026-08-11 on crypt32.dll: 1000+ lines of
        # real analysis, including several risk=high findings, lost to one
        # truncated JSON response after ~40 minutes of real LLM calls,
        # because nothing was written to disk until the very end). Cheap
        # relative to an LLM call; makes that failure mode cost at most one
        # item instead of the whole run.
        report = {"pairing": pairing_report, "diffs": results} if pairing_report else results
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

    def summarize_standalone(situation: str, items: list[dict], fns: dict) -> None:
        # `new` (patched-only) and `removed` (old-only) functions are handled
        # identically apart from which side's address/name key they report
        # under and which order related_note_for takes its two addresses in
        # -- was two ~23-line copies of the same loop, now one.
        addr_key, name_key = (("patched_address", "patched_name") if situation == "new"
                               else ("old_address", "old_name"))
        tag_base = situation.upper()
        for f in items:
            ref = f'0x{f["address"]:X}'
            fn = fns[ref]
            related_note = (related_note_for(None, fn["address"]) if situation == "new"
                             else related_note_for(fn["address"], None))
            print(f"\n[wingman] Summarizing {situation} function {fn['name']}…")
            if related_note:
                print(f"  ({related_note.strip()})")
            try:
                verdict = diff_mod.summarize_new_function(config, fn["name"], fn["pseudocode"], situation, related_note)
            except LLMError as e:
                print(f"  [ERROR] {e}")
                results.append({addr_key: ref, name_key: fn["name"], "error": str(e)})
                save_progress()
                continue
            tag = f"{tag_base}-SECURITY" if verdict["security_relevant"] else tag_base
            print(f"  [{tag}] risk={verdict['risk']}")
            if verdict["summary"]:
                print(f"  {verdict['summary']}")
            if verdict["explanation"]:
                print(f"  -> {verdict['explanation']}")
            summary_lookup[fn["address"]] = verdict["summary"]
            results.append({addr_key: ref, name_key: fn["name"], **verdict})
            save_progress()

    summarize_standalone("new", new_fns_meta, patched_fns)
    summarize_standalone("removed", removed_fns_meta, old_fns)

    for old_ref, patched_ref in pairs:
        old_fn = old_fns[old_ref]
        patched_fn = patched_fns[patched_ref]
        label = (old_fn["name"] if old_fn["name"] == patched_fn["name"]
                 else f'{old_fn["name"]} / {patched_fn["name"]}')
        related_note = related_note_for(old_fn["address"], patched_fn["address"])

        print(f"\n[wingman] Comparing {label}…")
        if related_note:
            print(f"  ({related_note.strip()})")
        base_entry = {
            "kind": "pair",
            "old_address": f'0x{old_fn["address"]:X}',
            "old_name": old_fn["name"],
            "patched_address": f'0x{patched_fn["address"]:X}',
            "patched_name": patched_fn["name"],
        }
        try:
            verdict = diff_mod.compare_functions(
                config, label, old_fn["pseudocode"], patched_fn["pseudocode"], related_note
            )
        except LLMError as e:
            print(f"  [ERROR] {e}")
            results.append({**base_entry, "error": str(e)})
            save_progress()
            continue
        tag = ("SECURITY" if verdict["security_relevant"]
               else "DIFF" if verdict["meaningful_diff_found"] else "NO DIFF")
        differences = verdict.get("differences", [])
        print(f"  [{tag}] risk={verdict['risk']}  "
              f"({len(differences)} difference(s) found, "
              f"num_ctx={verdict['num_ctx_used']}, prompt={verdict['prompt_chars']} chars)")
        for d in differences:
            d_tag = "SECURITY" if d["security_relevant"] else "diff" if d["meaningful"] else "no-op"
            print(f"  - [{d_tag} risk={d['risk']}] {d['summary']}")
            if d["explanation"]:
                print(f"    -> {d['explanation']}")
        sc = verdict.get("self_consistency", {})
        if sc.get("flagged_for_human_review"):
            print(f"  [!] VERDICT UNSTABLE — two independent samples disagreed on this one "
                  f"(large/complex prompt); the verdict above is a reconciled third pass. "
                  f"Worth a human/manual look. Both original drafts are in the JSON report "
                  f"under self_consistency.draft_1/draft_2.")
            if verdict.get("reconciliation_note"):
                print(f"  Reconciliation: {verdict['reconciliation_note']}")

        results.append({**base_entry, **verdict})
        save_progress()

    save_progress()
    print(f"\n[wingman] Wrote {len(results)} verdict(s) to {out_path}")

    if not args.no_report and any(
        r.get("meaningful_diff_found") or r.get("security_relevant") or "situation" in r
        for r in results if not r.get("error")
    ):
        from llm_renamer import report as report_mod
        print("[wingman] Generating diff report…")
        text, meta = report_mod.generate_diff_report(config, pairing_report, results)
        report_path = out_path.rsplit(".json", 1)[0] + ".md" if out_path.endswith(".json") else out_path + ".md"
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"[wingman] Report written to {report_path} "
              f"({meta['entry_count']} entries, num_ctx={meta['num_ctx']})")


def cmd_export(args) -> None:
    _, workspace = _prepare(args)

    if not os.path.exists(workspace.kb):
        _die(f"no analysis found in {workspace.dir}")

    out = os.path.abspath(args.out) if args.out else workspace.review
    kb = KnowledgeBase(workspace.kb)
    count = export_review(kb, out)
    kb.close()
    print(f"[wingman] Wrote {count} proposal(s) to {out}")


# Every extension/filename wingman itself writes next to a sample -- skipped
# when scanning a folder so `batch` never tries to re-ingest its own output
# as if it were another sample. (llm_responses.json used to live here too --
# now inside .wingman/ with everything else, so it's not in this list.)
_GENERATED_SUFFIXES = (
    ".i64", ".idb", ".id0", ".id1", ".id2", ".id3", ".nam", ".til",
)
_GENERATED_EXACT = {"review.json", "call_graph.json"}


def _discover_batch_targets(folder: str) -> list[str]:
    """Every raw sample in `folder`, in name order, plus any `.i64` left with
    no raw sibling (e.g. the raw file got quarantined by AV after the
    database was already built -- still worth analyzing what's there)."""
    names = sorted(f for f in os.listdir(folder) if os.path.isfile(os.path.join(folder, f)))
    raw_bases = set()
    targets = []
    for name in names:
        if name in _GENERATED_EXACT or any(name.lower().endswith(s) for s in _GENERATED_SUFFIXES):
            continue
        raw_bases.add(name)
        targets.append(os.path.join(folder, name))
    for name in names:
        if name.lower().endswith(".i64") and name[:-4] not in raw_bases:
            targets.append(os.path.join(folder, name))
    return targets


def cmd_batch(args) -> None:
    """Loop `--all` over every sample in a folder, one subprocess per sample.

    A fresh subprocess per sample -- not just per database creation -- for
    the same reason `_ensure_database` and `diff` already shell out: idalib
    hangs silently if a second `open_database()` happens in a process that
    already closed one. This also means one sample crashing (or getting
    quarantined mid-run, as happened live in this session) can't take the
    rest of the batch down with it -- each is fully isolated.
    """
    folder = os.path.abspath(args.folder)
    if not os.path.isdir(folder):
        _die(f"not a directory: {folder}")
    if not args.profile:
        _die("batch needs --profile (malware or vuln_research) -- it runs "
             "unattended across every sample, so there's no per-sample "
             "prompt to answer")

    targets = _discover_batch_targets(folder)
    if not targets:
        _die(f"no samples found in {folder}")

    print(f"[batch] {len(targets)} sample(s) in {folder}:")
    for t in targets:
        print(f"    {os.path.basename(t)}")

    results = []
    for i, target in enumerate(targets, 1):
        name = os.path.basename(target)
        print(f"\n{'=' * 70}\n[batch] ({i}/{len(targets)}) {name}\n{'=' * 70}")
        cmd = [sys.executable, os.path.abspath(__file__), "--all", target,
               "--profile", args.profile, "-y"]
        if args.redo:
            cmd.append("--redo")
        if args.limit is not None:
            cmd += ["--limit", str(args.limit)]
        if args.config:
            cmd += ["--config", args.config]
        if args.ollama_url:
            cmd += ["--ollama-url", args.ollama_url]
        if args.model:
            cmd += ["--model", args.model]
        if args.no_report:
            cmd.append("--no-report")

        start = time.time()
        proc = subprocess.run(cmd)
        elapsed = time.time() - start
        status = "ok" if proc.returncode == 0 else f"FAILED (exit {proc.returncode})"
        results.append((name, status, elapsed))
        print(f"[batch] {name}: {status} ({elapsed:.0f}s)")

    print(f"\n{'=' * 70}\n[batch] Done — {len(targets)} sample(s)\n{'=' * 70}")
    for name, status, elapsed in results:
        print(f"  {status:<20} {elapsed:>7.0f}s  {name}")


# ==========================================================================
# CLI
# ==========================================================================

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="research_wingman.py",
        description="research-wingman — a copilot for IDA Pro databases",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    subs = parser.add_subparsers(dest="command", metavar="COMMAND")

    # Options every command accepts.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("database", metavar="DATABASE",
                        help="Path to the .i64 IDA database")
    common.add_argument("--workspace", metavar="DIR",
                        help="State directory (default: <database>.wingman)")
    common.add_argument("--config", metavar="PATH",
                        help="Path to config.json")

    # Options for commands that talk to Ollama.
    llm_opts = argparse.ArgumentParser(add_help=False)
    llm_opts.add_argument("--ollama-url", metavar="URL",
                          help="Override the Ollama server URL")
    llm_opts.add_argument("--model", metavar="NAME",
                          help="Override the Ollama model")

    # --profile is its own group, separate from llm_opts, because `diff` uses
    # llm_opts too but has no notion of a profile -- its system prompts
    # (diff_compare.md etc.) are fixed, not profile-dependent. Sharing one
    # group meant `diff --profile malware` was silently accepted and ignored.
    profile_opt = argparse.ArgumentParser(add_help=False)
    profile_opt.add_argument("--profile", choices=sorted(_PROFILES),
                             help="Analysis prompt profile (default: "
                                  "config's analysis.profile, or vuln_research)")

    # Shared by `analyze` (a full --all malware-profile run) and `diff`
    # (--auto or --pair) -- both can trigger an automatic macro-report
    # synthesis call at the end; this is the one flag that opts out of
    # either. Its own subparser group for the same reason profile_opt is
    # separate from llm_opts: not every command that shares llm_opts wants it.
    report_opt = argparse.ArgumentParser(add_help=False)
    report_opt.add_argument("--no-report", action="store_true",
                            help="Skip generating the macro capability/diff "
                                 "report (default: generate one)")

    # -- analyze --------------------------------------------------------
    p = subs.add_parser(
        "analyze", parents=[common, llm_opts, profile_opt, report_opt],
        help="Analyze a scope of functions with the LLM (never modifies the database)",
        description="LLM calls are the scarce resource, so a scope is required. "
                    "Use `research_wingman.py map` to decide what is worth analyzing.",
    )
    scope = p.add_mutually_exclusive_group(required=True)
    scope.add_argument("-f", "--function", metavar="NAME", nargs="+",
                       help="These functions (name or 0xADDR) + their full callee subtree")
    scope.add_argument("--top", metavar="N", type=int,
                       help="The N highest-scoring unnamed functions")
    scope.add_argument("--all", action="store_true",
                       help="Every auto-named function (the overnight run)")

    p.add_argument("--limit", metavar="N", type=int,
                   help="Stop after N LLM calls; rerun to continue")
    p.add_argument("--redo", action="store_true",
                   help="Re-analyze functions that were already done")
    p.add_argument("-y", "--yes", action="store_true",
                   help="Skip the cost confirmation prompt")
    p.add_argument("--no-refine", action="store_true",
                   help="Skip the top-down refinement pass")
    p.add_argument("--no-apply", action="store_true",
                   help="Do NOT write renames into the database — analysis "
                        "only; apply later with `research_wingman.py apply` (default: apply)")
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

    # -- apply ----------------------------------------------------------
    p = subs.add_parser(
        "apply", parents=[common],
        help="Write approved renames into the database (never calls the LLM)",
    )
    p.add_argument("--dry-run", action="store_true",
                   help="Show what would change without writing anything")
    p.add_argument("-y", "--yes", action="store_true",
                   help="Skip the write confirmation prompt")
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
    p.add_argument("--report", action="store_true",
                   help="List every security-relevant function")
    p.set_defaults(func=cmd_ask)

    # -- status ---------------------------------------------------------
    p = subs.add_parser(
        "status", parents=[common],
        help="Show what has been done for this database",
    )
    p.set_defaults(func=cmd_status)

    # -- report -----------------------------------------------------------
    p = subs.add_parser(
        "report", parents=[common, llm_opts],
        help="Regenerate the macro capability report from an already-analyzed database",
        description="Reads the existing knowledge base + cached call graph directly -- "
                    "no IDA needed, same as `ask`/`status`. Useful to re-roll the "
                    "synthesis call, or regenerate after further refinement, without "
                    "rerunning analysis.",
    )
    p.set_defaults(func=cmd_report)

    # -- diff -----------------------------------------------------------
    p = subs.add_parser(
        "diff", parents=[llm_opts, report_opt],
        help="Compare matched functions across two databases (old vs patched) with the LLM",
        description="Pulls full pseudocode for matched functions from both databases and asks "
                    "the LLM whether the patched version differs in a security-relevant way. "
                    "--auto pairs functions itself (name match + structural fallback, no "
                    "BinDiff needed) and picks the ones worth comparing; --pair lets you supply "
                    "pairs yourself (e.g. from a BinDiff export) instead.",
    )
    p.add_argument("old_database", metavar="OLD_DATABASE",
                   help="Path to the old/pre-patch .i64")
    p.add_argument("patched_database", metavar="PATCHED_DATABASE",
                   help="Path to the patched .i64")
    scope = p.add_mutually_exclusive_group(required=True)
    scope.add_argument("--auto", action="store_true",
                       help="Pair functions automatically (needs both call graphs built via "
                            "`map --build` first) and diff whatever looks like a real change")
    scope.add_argument("--pair", metavar=("OLD", "PATCHED"), nargs=2, action="append",
                       dest="pair",
                       help="A matched function (name or 0xADDR) in each database; repeatable")
    p.add_argument("--max-lines", metavar="N", type=int, default=2000,
                   help="Pseudocode line cap per function (default: 2000 -- "
                        "large enough that truncation is very unlikely)")
    p.add_argument("--config", metavar="PATH", help="Path to config.json")
    p.add_argument("-o", "--out", metavar="PATH",
                   help="Output path (default: <patched>.wingman/diff_vs_<old>.json)")
    p.set_defaults(func=cmd_diff)

    # -- _extract-pseudocode (internal, used by `diff`) ------------------
    p = subs.add_parser("_extract-pseudocode", help=argparse.SUPPRESS)
    p.add_argument("database")
    p.add_argument("--addr", action="append", required=True, dest="addr")
    p.add_argument("--max-lines", type=int, default=2000)
    p.add_argument("--config")
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_extract_pseudocode)

    # -- export ---------------------------------------------------------
    p = subs.add_parser(
        "export", parents=[common],
        help="Write the analysis to a review JSON file",
    )
    p.add_argument("-o", "--out", metavar="PATH",
                   help="Output path (default: <workspace>/review.json)")
    p.set_defaults(func=cmd_export)

    # -- _create-database (internal, used by _ensure_database) ----------
    p = subs.add_parser("_create-database", help=argparse.SUPPRESS)
    p.add_argument("database")
    p.set_defaults(func=cmd_create_database)

    # -- batch ------------------------------------------------------------
    p = subs.add_parser(
        "batch", parents=[llm_opts, profile_opt, report_opt],
        help="Run the full --all pipeline (build + analyze + apply) on "
             "every sample in a folder, one at a time",
        description="For each raw sample in FOLDER (or a `.i64` left with no "
                    "raw sibling): build a database if needed, analyze every "
                    "auto-named function, and apply approved renames -- "
                    "exactly `--all` on one sample, just looped across a "
                    "folder. --profile is required (no per-sample prompt in "
                    "an unattended run). Each sample runs in its own "
                    "subprocess, so one crashing or getting AV-quarantined "
                    "mid-run doesn't take the rest of the batch down with it.",
    )
    p.add_argument("folder", metavar="FOLDER",
                   help="Directory of raw samples and/or .i64 databases")
    p.add_argument("--config", metavar="PATH", help="Path to config.json")
    p.add_argument("--limit", metavar="N", type=int,
                   help="Stop each sample's analysis after N LLM calls")
    p.add_argument("--redo", action="store_true",
                   help="Re-analyze functions already done, for every sample")
    p.set_defaults(func=cmd_batch)

    return parser


_COMMANDS = {"map", "analyze", "apply", "ask", "status", "export", "diff", "batch",
             "report", "_extract-pseudocode", "_create-database"}
_DB_SUFFIXES = (".i64", ".idb")


def _discover_database() -> str | None:
    """Find a database to open when the user just runs `research_wingman.py` with no args."""
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
    Make the free, no-commitment view the default.

        research_wingman.py                 → find a database nearby, `map` it
        research_wingman.py target.i64      → `map target.i64`
        research_wingman.py map target.i64  → the explicit command, unchanged
        research_wingman.py --all target.i64 → the "point at a sample and
                                                walk away" case: shorthand for
                                                `analyze target.i64 --all`,
                                                no subcommand needed

    Subcommands stay available for scripting; nobody has to remember them.
    """
    if not argv:
        db = _discover_database()
        if db is None:
            return []
        return ["map", db]
    if "--all" in argv and argv[0] not in _COMMANDS:
        return ["analyze"] + argv
    first = argv[0]
    if first in _COMMANDS or first.startswith("-"):
        return argv
    return ["map"] + argv


def main() -> None:
    parser = _build_parser()
    argv = _normalize_argv(sys.argv[1:])

    if not argv:
        parser.print_help()
        print(f"\n  No {' or '.join(_DB_SUFFIXES)} file in this directory.\n"
              f"  Point it at one:  python research_wingman.py /path/to/target.i64\n")
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
