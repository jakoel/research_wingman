"""
The two operations that need an open IDA database.

    analyze()  reads the database, calls the LLM, writes the knowledge base.
               Never modifies the database.

    apply()    reads the knowledge base, writes renames and comments into the
               database. Never calls the LLM.

Keeping these apart is the whole safety story: the expensive operation and the
irreversible one are different commands.

Analysis is always *scoped*. LLM calls are the scarce resource — a few thousand
functions is an overnight run — so a scope must be chosen explicitly and its
cost is quoted before anything is spent. `navigate.py` is what produces those
scopes from the call graph, for free.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from . import family
from .audit import AuditLogger
from .call_graph import CallGraph, load_or_build
from .idapro_client import FunctionContextExtractor
from .kb import KnowledgeBase, STATUS_APPROVED, STATUS_REJECTED, addr_to_hex
from .llm_client import OllamaClient, LLMError
from .llm_log import LLMResponseLog
from .prompts import build_user_prompt, get_system_prompt
from .refiner import Refiner, repair_naming_conflicts
from .renamer import RenamePolicy, format_comment
from .scorer import build_worklist, depth_from_leaves, score_node
from .validator import validate_llm_output
from .workspace import Workspace


# ==========================================================================
# Planning — decide and price the work before spending anything
# ==========================================================================

@dataclass
class Plan:
    """A priced, ordered unit of analysis work."""
    label: str
    rows: list[dict] = field(default_factory=list)
    already_done: int = 0
    scope_size: int = 0
    # `--limit` -- NOT applied by slicing `rows` (see build_plan): cheap
    # rejections (no pseudocode, too few lines) shouldn't count against it,
    # per ARCHITECTURE.md §7.2, so `rows` holds every real candidate and
    # `_run_plan` enforces the limit itself, counting only actual LLM calls.
    limit: int | None = None

    @property
    def todo(self) -> int:
        return len(self.rows)

    @property
    def estimated_calls(self) -> int:
        """Best-effort call count for display -- `rows` may hold more
        candidates than will actually get an LLM call once `limit` is
        enforced during the run."""
        return self.todo if self.limit is None else min(self.todo, self.limit)

    def estimate(self, seconds_per_call: float | None) -> str:
        n = self.estimated_calls
        if not n:
            return "nothing to do"
        if seconds_per_call is None:
            return f"~{n} LLM call(s), duration unknown (first run)"
        total = n * seconds_per_call
        return f"~{n} LLM call(s), about {_duration(total)}"

    def describe(self, seconds_per_call: float | None) -> str:
        lines = [f"  Scope     : {self.label}",
                 f"  Functions : {self.scope_size}"]
        if self.already_done:
            lines.append(f"  Already   : {self.already_done} (skipped)")
        lines.append(f"  Cost      : {self.estimate(seconds_per_call)}")
        return "\n".join(lines)


def _duration(seconds: float) -> str:
    if seconds < 90:
        return f"{int(seconds)}s"
    if seconds < 5400:
        return f"{seconds / 60:.0f} min"
    return f"{seconds / 3600:.1f} hours"


def resolve_graph(
    config: dict,
    workspace: Workspace,
    extractor: FunctionContextExtractor,
    *,
    targeted: bool = False,
    rebuild: bool = False,
) -> CallGraph | None:
    """
    Load the call graph, building it only when that's the cheaper choice.

    A targeted run on a database with no cached graph does NOT trigger a full
    build — that would make "analyze this one function" cost minutes. It runs
    without callee context instead and says so.
    """
    if rebuild or workspace.has_graph() or not targeted:
        graph = load_or_build(extractor, config, workspace.call_graph,
                              force_rebuild=rebuild)
        # Cheap structural-staleness check: IDA is already open here, so
        # comparing the live function count against the cached graph costs
        # nothing and catches the case that actually invalidates cached graph
        # *structure* -- the binary was re-analyzed in IDA and functions were
        # added/removed since the cache was built. (A rename never changes the
        # count, and `apply` patches cached names directly, so this won't
        # false-fire on the normal workflow the way an mtime check would.)
        if not rebuild:
            try:
                live = extractor.get_function_count()
                cached = len(graph.nodes)
                if live != cached:
                    print(f"[wingman] NOTE: call graph has {cached} functions but the "
                          f"database now has {live} — the binary changed since "
                          f"the graph was built.\n"
                          f"[wingman]       Structure may be stale; rebuild with "
                          f"`research_wingman.py map <db> --build` if results look off.")
            except Exception:
                pass
        return graph
    print("[wingman] No cached call graph — running without callee context.\n"
          "[wingman] Build it once with `research_wingman.py map <db> --build` for better results.")
    return None


def build_plan(
    config: dict,
    workspace: Workspace,
    extractor: FunctionContextExtractor,
    graph: CallGraph | None,
    *,
    addresses: list[int] | None = None,
    functions: list[str] | None = None,
    all_functions: bool = False,
    reanalyze: bool = False,
    limit: int | None = None,
    label: str = "",
    force: set[int] | None = None,
) -> Plan:
    """Resolve a scope to concrete, ordered function rows and price it.

    `force` names addresses that must always be included even if already
    analyzed (e.g. the function you explicitly asked about), while the rest
    of the scope (e.g. its callees, pulled in for context) still skips
    anything already in the KB — so re-asking about one function doesn't
    re-spend LLM calls on callees it already knows about.
    """
    if addresses is not None:
        targets = [addr_to_hex(a) for a in addresses]
        rows = extractor.get_functions_by_name(targets)
        label = label or f"{len(addresses)} selected function(s)"
    elif functions:
        rows = extractor.get_functions_by_name(functions)
        label = label or f"{len(functions)} named function(s)"
    elif all_functions:
        rows = extractor.get_all_auto_functions()
        label = label or "every auto-named function"
    else:
        raise ValueError("build_plan needs addresses, functions, or all_functions")

    # Only sub_-style unnamed functions are worth an LLM call. Drop any named
    # function (library/symbol/import/analyst) or trivial auto stub that landed
    # in the scope via `--top`'s scoring pass -- analyzing it wastes calls. An
    # explicit -f target (in `force`) is kept even if named, so a user can
    # still analyze a specific named function on demand.
    from .validator import is_analysis_candidate
    force = force or set()
    rows = [r for r in rows
            if is_analysis_candidate(str(r.get("name", "")), config)
            or int(r["address"]) in force]

    scope_size = len(rows)

    if graph is not None and rows:
        rows = _order_bottom_up(rows, graph, config)

    already = 0
    if not reanalyze:
        kb = KnowledgeBase(workspace.kb)
        keep = []
        for row in rows:
            addr_int = int(row["address"])
            if kb.is_analyzed(addr_to_hex(addr_int)) and not (force and addr_int in force):
                already += 1
            else:
                keep.append(row)
        kb.close()
        rows = keep

    return Plan(label=label, rows=rows, already_done=already,
                scope_size=scope_size, limit=limit)


def seconds_per_call(workspace: Workspace) -> float | None:
    """Observed LLM latency for this workspace, if we've measured it."""
    import os
    if not os.path.exists(workspace.kb):
        return None
    kb = KnowledgeBase(workspace.kb)
    try:
        return kb.seconds_per_call()
    finally:
        kb.close()


# ==========================================================================
# Analyze
# ==========================================================================

def analyze(
    config: dict,
    workspace: Workspace,
    extractor: FunctionContextExtractor,
    *,
    addresses: list[int] | None = None,
    functions: list[str] | None = None,
    all_functions: bool = False,
    limit: int | None = None,
    rebuild_graph: bool = False,
    refine: bool = True,
    reanalyze: bool = False,
    label: str = "",
    confirm=None,
    graph: CallGraph | None = None,
    force: set[int] | None = None,
    apply_immediately: bool = False,
) -> dict:
    """
    Analyze a scope of functions and record the results.

    `confirm` is an optional callable taking (plan, seconds_per_call) and
    returning a bool — the caller's chance to see the cost and decline.
    Pass `graph` when the caller already resolved it (the scope selectors need
    it), to avoid loading the cache twice. See `build_plan` for `force`.

    `apply_immediately` writes each function's approved rename + summary
    comment into the database the moment it's approved, instead of leaving
    the .i64 unchanged until a separate `apply()` call. Defaults to False so
    `analyze()` keeps its documented invariant of never touching the .i64 on
    its own (README "Two rules") -- callers that want the CLI's normal
    "analyze applies by default" behavior pass True explicitly (see
    research_wingman.py's `cmd_analyze`).

    Either way, refinement (which runs after the main loop) can still improve
    an already-applied row -- a separate, final `apply()` pass after analyze()
    returns is still the correct way to pick those up; this is a liveness
    improvement during a long run, not a replacement for that final pass.
    """
    if graph is None:
        graph = resolve_graph(config, workspace, extractor,
                              targeted=not all_functions,
                              rebuild=rebuild_graph)

    plan = build_plan(
        config, workspace, extractor, graph,
        addresses=addresses, functions=functions, all_functions=all_functions,
        reanalyze=reanalyze, limit=limit, label=label, force=force,
    )

    spc = seconds_per_call(workspace)
    print("\n" + plan.describe(spc) + "\n")

    if not plan.todo:
        if plan.already_done:
            print("[wingman] Everything in this scope is already analyzed. "
                  "Use --redo to run it again.\n")
        else:
            print("[wingman] Nothing to analyze in this scope.\n")
        kb = KnowledgeBase(workspace.kb)
        stats = kb.stats()
        kb.close()
        return stats

    if confirm is not None and not confirm(plan, spc):
        print("[wingman] Cancelled — no LLM calls made.\n")
        kb = KnowledgeBase(workspace.kb)
        stats = kb.stats()
        kb.close()
        return stats

    return _run_plan(config, workspace, extractor, graph, plan,
                     refine=refine and graph is not None,
                     apply_immediately=apply_immediately)


def _run_plan(
    config: dict,
    workspace: Workspace,
    extractor: FunctionContextExtractor,
    graph: CallGraph | None,
    plan: Plan,
    *,
    refine: bool,
    apply_immediately: bool = False,
) -> dict:
    kb = KnowledgeBase(workspace.kb)
    llm = OllamaClient(config)
    # What num_ctx would have been used pre-analyze_sized -- _report_result
    # only prints a note when the real prompt needed more than this, so the
    # common case (most functions fit easily) stays quiet and the noise is
    # limited to the functions where sizing actually mattered.
    base_ctx = int(config["ollama"].get("num_ctx", 8192))
    max_pseudocode_lines = int(config["analysis"].get("max_pseudocode_lines", 200))
    policy = RenamePolicy(config, extractor) if apply_immediately else None
    system_prompt = get_system_prompt(config.get("analysis", {}).get("profile"))

    scores: dict[int, float] = {}
    if graph is not None:
        depths = depth_from_leaves(graph)
        scores = {
            addr: score_node(node, config) + float(depths.get(addr, 0))
            for addr, node in graph.nodes.items()
        }

    total = plan.estimated_calls
    processed = errors = llm_calls = 0
    started = time.time()
    applied_renames: dict[int, str] = {}  # ea -> final name, for cache patching

    with AuditLogger(workspace.audit) as audit, \
         LLMResponseLog(workspace.llm_responses) as llmlog:
        for row in plan.rows:
            ea = int(row["address"])
            name = str(row.get("name", f"sub_{ea:X}"))
            addr_hex = addr_to_hex(ea)

            _progress(processed, total, name, llm_calls, errors)

            base = {
                "address": addr_hex,
                "old_name": name,
                "caller_count": graph.nodes[ea].caller_count
                                if graph and ea in graph.nodes else 0,
                "score": scores.get(ea, 0.0),
            }

            try:
                ctx = extractor.extract(row)
                # Fold in the deterministic Phase-1 graph signals (sinks called,
                # input-reachability, caller count) so the prompt carries them
                # instead of the model re-deriving them from pseudocode. The
                # node is the authority for these -- dangerous_sink_calls is
                # complete and uncapped there, unlike the address-order-capped
                # import list in ctx. See prompts._render_graph_signals.
                if graph is not None and ea in graph.nodes:
                    gnode = graph.nodes[ea]
                    ctx["dangerous_sink_calls"] = gnode.dangerous_sink_calls
                    ctx["input_reachable"] = gnode.input_reachable
                    ctx["caller_count"] = gnode.caller_count
                    # Real dataflow, not graph-topology guessing: only decompiles
                    # again for the small subset already known to call a sink
                    # (bounded cost) -- see FunctionContextExtractor.sink_argument_taint.
                    if gnode.dangerous_sink_calls:
                        ctx["tainted_sink_calls"] = extractor.sink_argument_taint(
                            ea, set(gnode.dangerous_sink_calls)
                        )

                # Deterministic structural-family signal (see family.py) --
                # independent of the graph-signal fold-in above, order
                # doesn't matter. Gated on is_hashable so trivial bodies
                # (coincidental matches, not real families) never get a hash
                # at all, rather than a hash nobody should trust.
                normalized = family.normalize_pseudocode(ctx.get("pseudocode") or "")
                if family.is_hashable(normalized):
                    ctx["body_hash"] = family.body_hash(normalized)
                    ctx["family_members"] = kb.get_family_members(
                        ctx["body_hash"], exclude_address=addr_hex
                    )
                    ctx["family_size"] = kb.count_family_members(
                        ctx["body_hash"], exclude_address=addr_hex
                    )
            except Exception as e:
                errors += 1
                audit.record_error(address=addr_hex, old_name=name, phase="analyze",
                                   error=f"Context extraction failed: {e}")
                kb.record({**base, "analyzed": True, "status": STATUS_REJECTED,
                           "rejection_reason": f"Context extraction failed: {e}"})
                processed += 1
                continue

            skip_reason = _pre_llm_rejection(ctx, config)
            if skip_reason:
                kb.record({**base, "analyzed": True, "status": STATUS_REJECTED,
                           "rejection_reason": skip_reason})
                print(f"\n  [--] {name}  skipped: {skip_reason}")
                audit.record(address=addr_hex, old_name=name, phase="analyze",
                             status="rejected", detail=skip_reason)
                processed += 1
                continue

            # --limit checked here: after cheap rejections, before the LLM
            # call, counting only actual LLM calls made this run (see
            # ARCHITECTURE.md §7.2 -- plan.rows deliberately holds every real
            # candidate, not a pre-sliced `limit` of them, so a cheap
            # rejection above doesn't eat into the budget).
            if plan.limit is not None and llm_calls >= plan.limit:
                break

            callee_entries: list[dict] = []
            caller_entries: list[dict] = []
            if graph is not None:
                callee_entries = kb.get_callee_summaries(graph.callees_of(ea))
                caller_entries = kb.get_callers_in_kb(addr_hex, graph.callers_of(ea))

            try:
                prompt = build_user_prompt(
                    ctx, callee_kb_entries=callee_entries,
                    caller_kb_entries=caller_entries,
                    config=config,
                )
                raw, num_ctx_used, prompt_chars = llm.analyze_sized(system_prompt, prompt)
                llm_calls += 1
            except LLMError as e:
                # Left unanalyzed on purpose: a transient LLM failure should be
                # retried on the next run, not baked in as a rejection.
                errors += 1
                audit.record_error(address=addr_hex, old_name=name, phase="analyze",
                                   error=str(e))
                print(f"\n  [!!] {name}  LLM error: {e}")
                processed += 1
                continue

            validation = validate_llm_output(raw, config)

            llmlog.record(
                address=addr_hex, old_name=name, phase="analyze",
                model=config["ollama"]["model"], raw_response=raw,
                validation={
                    "ok": validation.ok,
                    "reason": validation.reason,
                    "sanitized_name": validation.sanitized_name,
                },
            )

            entry = {
                **base,
                "analyzed": True,
                "confidence": float(raw.get("confidence", 0.0) or 0.0),
                "reason": str(raw.get("reason", "")).strip(),
                "summary": raw.get("summary"),
                "security_relevant": bool(raw.get("security_relevant", False)),
                "risk": str(raw.get("risk", "")).strip().lower(),
                "interesting_behaviors": [
                    str(b).strip() for b in (raw.get("interesting_behaviors") or [])
                    if str(b).strip()
                ][:5],
                "callee_summaries_used": [
                    e.get("new_name") or e.get("old_name", "") for e in callee_entries
                ],
                "num_ctx_used": num_ctx_used,
                "prompt_chars": prompt_chars,
                "pseudocode_truncated": ctx.get("pseudocode_truncated", False),
                "body_hash": ctx.get("body_hash"),
            }
            if validation:
                entry["new_name"] = validation.sanitized_name
                entry["status"] = STATUS_APPROVED
            else:
                entry["new_name"] = None
                entry["status"] = STATUS_REJECTED
                entry["rejection_reason"] = validation.reason

            kb.record(entry)
            _report_result(name, entry, base_ctx, max_pseudocode_lines)

            if apply_immediately and policy is not None and entry["status"] == STATUS_APPROVED:
                # Write this function's rename + summary comment right now
                # instead of leaving the .i64 unchanged until a separate
                # apply() call at the very end of a possibly very long run
                # (see analyze()'s `apply_immediately` docstring). Cached
                # call-graph name patching is deliberately NOT done here
                # (that would mean a full JSON read+rewrite per function on
                # a large binary) -- accumulated in `applied_renames` and
                # patched once after the loop instead.
                status, detail = _apply_one(entry, extractor, policy, kb, audit, dry_run=False)
                if status == "applied":
                    applied_renames[ea] = detail

            if graph is not None:
                for callee in graph.callees_of(ea):
                    kb.upsert_edge(addr_hex, addr_to_hex(callee))
                kb.flush()

            # Records the ANALYZE decision only -- whether this run's apply
            # (if apply_immediately fired just above) actually wrote the
            # rename is a separate fact, logged by _apply_one()'s own
            # phase="apply" record with the real outcome, not asserted here.
            audit.record(
                address=addr_hex, old_name=name, phase="analyze",
                status=entry["status"], new_name=entry.get("new_name") or "",
                detail=entry.get("rejection_reason", ""),
            )
            processed += 1

    print()
    kb.record_timing(llm_calls, time.time() - started)

    if refine and graph is not None:
        with LLMResponseLog(workspace.llm_responses) as refine_log:
            Refiner(graph, kb, llm, config, llm_log=refine_log,
                   extractor=extractor).run()
            # Targeted, deterministic-trigger repair pass for two specific,
            # always-wrong naming defects (a thunk named after its own real
            # callee; a cross-KB name collision) -- see repair_naming_conflicts'
            # docstring. Part of the same post-loop quality pass as refinement
            # above, so it shares --no-refine as its opt-out rather than a
            # separate flag.
            repair_naming_conflicts(graph, kb, llm, config,
                                    extractor=extractor, llm_log=refine_log)

    stats = kb.stats()
    kb.close()

    # Mirrors apply()'s own cache-patching (see its comment) -- functions
    # written via apply_immediately during the loop above never go through
    # that separate apply() call, so without this the cached call graph
    # would go stale for exactly the renames this feature was built to
    # write promptly.
    if applied_renames:
        from .call_graph import update_cached_names
        update_cached_names(workspace.call_graph, applied_renames)

    _print_analyze_summary(stats, errors, llm_calls, workspace)
    return stats


def _order_bottom_up(rows: list[dict], graph: CallGraph, config: dict) -> list[dict]:
    """Order candidates leaves-first so callee summaries exist before callers."""
    by_addr = {int(r["address"]): r for r in rows}
    ordered = [a for a in build_worklist(graph, config) if a in by_addr]
    seen = set(ordered)
    ordered += [a for a in by_addr if a not in seen]
    return [by_addr[a] for a in ordered]


def _pre_llm_rejection(ctx: dict, config: dict) -> str:
    """Reasons to skip a function without paying for an LLM call."""
    if not ctx.get("pseudocode"):
        return "No Hex-Rays pseudocode available"
    min_lines = config["analysis"].get("min_pseudocode_lines", 3)
    if ctx["pseudocode"].count("\n") + 1 < min_lines:
        return f"Pseudocode < {min_lines} lines — too trivial"
    return ""


# ==========================================================================
# Apply
# ==========================================================================

def _apply_one(
    entry: dict,
    extractor: FunctionContextExtractor,
    policy: RenamePolicy,
    kb: KnowledgeBase,
    audit: AuditLogger,
    *,
    dry_run: bool = False,
) -> tuple[str, str]:
    """
    Apply one KB row's approved rename (if any) to the database right now.

    The single per-row implementation shared by the batch `apply()` below and
    `_run_plan`'s per-function immediate-apply (see `analyze`'s
    `apply_immediately`) -- one policy path, one place that writes, whether
    it's invoked once per pending row at the end of a run or once right after
    each function is analyzed. Never call `idc.set_name`/`idc.set_func_cmt`
    directly anywhere else (renamer.py's docstring invariant).

    Returns (status, detail): status is one of "applied"/"skip"/"fail"/"error"
    (matching the counters/print lines the two callers already used).
    """
    import idc

    addr_hex = str(entry["address"])
    try:
        ea = int(addr_hex, 16)
    except ValueError:
        audit.record_error(address=addr_hex, old_name=entry.get("old_name", "?"),
                           phase="apply", error=f"Unparseable address: {addr_hex!r}")
        return "error", f"Unparseable address: {addr_hex!r}"

    # Trust the database's current name over the stored one — an analyst may
    # have named this function since analysis ran. `current_name` is the
    # single authority (ARCHITECTURE §3a), not the KB's `old_name` shadow.
    current = extractor.current_name(ea)

    if current == entry.get("new_name"):
        # A re-analysis reconfirmed the exact same name (possible now that a
        # confidence upgrade can make an already-applied row pending again --
        # see kb.record). Nothing to rename; treat as a no-op rather than
        # letting resolve_conflict() see the name "collide" with this same
        # function and wrongly suffix it (e.g. into `..._2`).
        if not dry_run:
            if entry.get("summary"):
                idc.set_func_cmt(ea, format_comment(entry["summary"], entry.get("confidence")), 1)
            kb.mark_applied(addr_hex, current)
        verb = "would " if dry_run else "ok    "
        print(f"  {verb}{addr_hex:<14} {current:<34} (already this name)")
        audit.record(
            address=addr_hex, old_name=current, phase="apply",
            status="applied", new_name=current, detail="already this name",
        )
        return "applied", current

    allowed, why = policy.can_rename(current, entry.get("applied_name"))
    if not allowed:
        print(f"  skip  {addr_hex:<14} {current:<34} {why}")
        audit.record(
            address=addr_hex, old_name=current, phase="apply",
            status="skip", new_name=entry.get("new_name") or "", detail=why,
        )
        return "skip", why

    unique = policy.resolve_conflict(entry["new_name"], ea=ea)
    if not unique:
        print(f"  fail  {addr_hex:<14} {current:<34} name conflict")
        audit.record(
            address=addr_hex, old_name=current, phase="apply",
            status="fail", new_name=entry.get("new_name") or "",
            detail="Name conflict: exhausted suffix variants",
        )
        return "fail", "Name conflict: exhausted suffix variants"

    if dry_run:
        print(f"  would {addr_hex:<14} {current:<34} -> {unique}")
        return "applied", unique

    ok, detail = policy.apply_rename(
        ea, unique, summary=entry.get("summary") or "", confidence=entry.get("confidence"),
    )
    if ok:
        kb.mark_applied(addr_hex, unique)
        print(f"  ok    {addr_hex:<14} {current:<34} -> {unique}")
        audit.record(
            address=addr_hex, old_name=current, phase="apply",
            status="applied", new_name=unique,
        )
        return "applied", unique

    print(f"  fail  {addr_hex:<14} {current:<34} {detail}")
    audit.record(
        address=addr_hex, old_name=current, phase="apply",
        status="fail", new_name=entry.get("new_name") or "", detail=detail,
    )
    return "fail", detail


def apply(
    config: dict,
    workspace: Workspace,
    extractor: FunctionContextExtractor,
    *,
    min_confidence: float | None = None,
    dry_run: bool = False,
) -> dict:
    """
    Write approved renames from the knowledge base into the IDA database.
    Makes no LLM calls. Rows already applied are skipped.
    """
    kb = KnowledgeBase(workspace.kb)
    policy = RenamePolicy(config, extractor)

    threshold = (
        min_confidence if min_confidence is not None
        else float(config["analysis"]["confidence_threshold"])
    )
    pending = kb.get_approved_unapplied(threshold)

    if not pending:
        print("[wingman] Nothing to apply — no approved, unapplied renames "
              f"at confidence >= {threshold:.2f}.")
        kb.close()
        return {"applied": 0, "skipped": 0, "errors": 0}

    verb = "Would apply" if dry_run else "Applying"
    print(f"[wingman] {verb} {len(pending)} rename(s) at confidence >= {threshold:.2f}\n")

    applied = skipped = errors = 0
    applied_renames: dict[int, str] = {}  # ea -> final name, for cache patching

    with AuditLogger(workspace.audit) as audit:
        for entry in pending:
            status, detail = _apply_one(entry, extractor, policy, kb, audit, dry_run=dry_run)
            if status == "applied":
                applied += 1
                if not dry_run:
                    applied_renames[int(str(entry["address"]), 16)] = detail
            elif status == "skip":
                skipped += 1
            else:
                errors += 1

    kb.close()

    # Keep the cached call graph's names in sync with what we just wrote to the
    # database, so map views / search / the unnamed filter don't read back the
    # pre-rename `sub_...` names. Only the names change on a rename; the graph
    # structure is untouched, so this targeted patch is exact. Best-effort.
    if not dry_run and applied_renames:
        from .call_graph import update_cached_names
        update_cached_names(workspace.call_graph, applied_renames)

    if dry_run:
        print(f"\n[wingman] Dry run — {applied} would be applied, "
              f"{skipped} skipped, {errors} would fail. Nothing was written.")
    else:
        print(f"\n[wingman] Applied {applied}, skipped {skipped}, errors {errors}.")
        print("[wingman] Changes are saved when the database closes.")
    print(f"[wingman] Audit log: {workspace.audit}")

    return {"applied": applied, "skipped": skipped, "errors": errors}


# ==========================================================================
# Display helpers
# ==========================================================================

def _report_result(old_name: str, entry: dict, base_ctx: int, max_pseudocode_lines: int) -> None:
    """Print what the LLM actually said, right after each function — the
    progress line alone only shows a counter, not whether analysis is any
    good, and bottom-up runs need this to sanity-check as they go."""
    conf = float(entry.get("confidence") or 0.0)
    summary = (entry.get("summary") or "").strip()
    sec = " [security-relevant]" if entry.get("security_relevant") else ""
    risk = entry.get("risk") or ""
    risk_tag = f"  risk={risk}" if risk else ""
    if entry["status"] == STATUS_APPROVED:
        print(f"\n  [OK] {old_name} -> {entry['new_name']}  "
              f"(conf={conf:.2f}){risk_tag}{sec}\n       {summary}")
        for b in (entry.get("interesting_behaviors") or [])[:3]:
            print(f"         • {b}")
    else:
        reason = entry.get("rejection_reason", "")
        print(f"\n  [--] {old_name}  rejected (conf={conf:.2f}){risk_tag}: {reason}")

    # Only surface this when sizing actually picked more than the configured
    # default -- the common case fits easily and printing it every time would
    # bury the signal (a large/central function needed real headroom) in
    # noise from the hundreds of small ones that didn't.
    num_ctx_used = entry.get("num_ctx_used")
    if num_ctx_used and num_ctx_used > base_ctx:
        print(f"       [ctx] sized to {num_ctx_used} (prompt {entry.get('prompt_chars')} chars, "
              f"default would have been {base_ctx})")

    # Real body exceeded analysis.max_pseudocode_lines -- the model's prompt
    # had a "// ... [N more lines truncated]" marker embedded, but that was
    # previously invisible to the operator. Loud on purpose (unlike the
    # ctx-sizing note above, this means real content was NOT shown to the
    # model at all, not just that a bigger bucket was needed) -- confirmed
    # real risk this session, see config.py's rationale on max_pseudocode_lines.
    if entry.get("pseudocode_truncated"):
        print(f"       [WARNING] pseudocode truncated at "
              f"max_pseudocode_lines={max_pseudocode_lines} -- this function's "
              f"real body is longer; some of it was NOT shown to the model. "
              f"Consider raising analysis.max_pseudocode_lines in config.json.")


def _progress(processed: int, total: int, name: str, calls: int, errors: int) -> None:
    pct = int(100 * processed / total) if total else 0
    print(
        f"\r[{pct:3d}%] {processed}/{total}  {name[:40]:<40}  "
        f"llm:{calls}  errors:{errors}",
        end="", flush=True,
    )


def _print_analyze_summary(stats: dict, errors: int, calls: int,
                           workspace: Workspace) -> None:
    print(
        f"\n[wingman] Done — {calls} LLM call(s) this run\n"
        f"  Analyzed total : {stats['analyzed']}\n"
        f"  Approved       : {stats['approved']}\n"
        f"  Rejected       : {stats['rejected']}\n"
        f"  LLM errors     : {errors} (will be retried)\n"
    )
    if stats.get("pseudocode_truncated"):
        print(f"  WARNING: {stats['pseudocode_truncated']} function(s) had real bodies "
              f"longer than analysis.max_pseudocode_lines -- some content was NOT shown "
              f"to the model. See the per-function [WARNING] lines above, or query "
              f"KnowledgeBase.get_pseudocode_truncated() for the full list.\n")
    if stats["pending_apply"]:
        print(f"  {stats['pending_apply']} rename(s) ready to apply.\n")
