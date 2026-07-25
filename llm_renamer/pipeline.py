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

from .audit import AuditLogger
from .call_graph import CallGraph, load_or_build
from .idapro_client import FunctionContextExtractor
from .kb import KnowledgeBase, STATUS_APPROVED, STATUS_REJECTED
from .llm_client import OllamaClient, LLMError
from .prompts import SYSTEM_PROMPT, build_user_prompt
from .refiner import Refiner
from .renamer import RenamePolicy
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

    @property
    def todo(self) -> int:
        return len(self.rows)

    def estimate(self, seconds_per_call: float | None) -> str:
        if not self.todo:
            return "nothing to do"
        if seconds_per_call is None:
            return f"~{self.todo} LLM call(s), duration unknown (first run)"
        total = self.todo * seconds_per_call
        return f"~{self.todo} LLM call(s), about {_duration(total)}"

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
    quick: bool = False,
    targeted: bool = False,
    rebuild: bool = False,
) -> CallGraph | None:
    """
    Load the call graph, building it only when that's the cheaper choice.

    A targeted run on a database with no cached graph does NOT trigger a full
    build — that would make "analyze this one function" cost minutes. It runs
    without callee context instead and says so.
    """
    if quick:
        return None
    if rebuild or workspace.has_graph() or not targeted:
        return load_or_build(extractor, config, workspace.call_graph,
                             force_rebuild=rebuild)
    print("[rh] No cached call graph — running without callee context.\n"
          "[rh] Build it once with `rh map <db> --build` for better results.")
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
) -> Plan:
    """Resolve a scope to concrete, ordered function rows and price it."""
    if addresses is not None:
        targets = [f"0x{a:X}" for a in addresses]
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

    scope_size = len(rows)

    if graph is not None and rows:
        rows = _order_bottom_up(rows, graph, config)

    already = 0
    if not reanalyze:
        kb = KnowledgeBase(workspace.kb)
        keep = []
        for row in rows:
            if kb.is_analyzed(f"0x{int(row['address']):X}"):
                already += 1
            else:
                keep.append(row)
        kb.close()
        rows = keep

    if limit is not None:
        rows = rows[:limit]

    return Plan(label=label, rows=rows, already_done=already,
                scope_size=scope_size)


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
    quick: bool = False,
    rebuild_graph: bool = False,
    refine: bool = True,
    reanalyze: bool = False,
    label: str = "",
    confirm=None,
    graph: CallGraph | None = None,
) -> dict:
    """
    Analyze a scope of functions and record the results.

    `confirm` is an optional callable taking (plan, seconds_per_call) and
    returning a bool — the caller's chance to see the cost and decline.
    Pass `graph` when the caller already resolved it (the scope selectors need
    it), to avoid loading the cache twice.
    """
    if graph is None:
        graph = resolve_graph(config, workspace, extractor,
                              quick=quick, targeted=not all_functions,
                              rebuild=rebuild_graph)

    plan = build_plan(
        config, workspace, extractor, graph,
        addresses=addresses, functions=functions, all_functions=all_functions,
        reanalyze=reanalyze, limit=limit, label=label,
    )

    spc = seconds_per_call(workspace)
    print("\n" + plan.describe(spc) + "\n")

    if not plan.todo:
        if plan.already_done:
            print("[rh] Everything in this scope is already analyzed. "
                  "Use --redo to run it again.\n")
        else:
            print("[rh] Nothing to analyze in this scope.\n")
        kb = KnowledgeBase(workspace.kb)
        stats = kb.stats()
        kb.close()
        return stats

    if confirm is not None and not confirm(plan, spc):
        print("[rh] Cancelled — no LLM calls made.\n")
        kb = KnowledgeBase(workspace.kb)
        stats = kb.stats()
        kb.close()
        return stats

    return _run_plan(config, workspace, extractor, graph, plan,
                     refine=refine and graph is not None and not quick)


def _run_plan(
    config: dict,
    workspace: Workspace,
    extractor: FunctionContextExtractor,
    graph: CallGraph | None,
    plan: Plan,
    *,
    refine: bool,
) -> dict:
    kb = KnowledgeBase(workspace.kb)
    llm = OllamaClient(config)

    scores: dict[int, float] = {}
    if graph is not None:
        depths = depth_from_leaves(graph)
        scores = {
            addr: score_node(node, config) + float(depths.get(addr, 0))
            for addr, node in graph.nodes.items()
        }

    total = plan.todo
    processed = errors = llm_calls = 0
    started = time.time()

    with AuditLogger(workspace.audit) as audit:
        for row in plan.rows:
            ea = int(row["address"])
            name = str(row.get("name", f"sub_{ea:X}"))
            addr_hex = f"0x{ea:X}"

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
            except Exception as e:
                errors += 1
                audit.record_error(address=addr_hex, name=name,
                                   error=f"Context extraction failed: {e}")
                kb.record({**base, "analyzed": True, "status": STATUS_REJECTED,
                           "rejection_reason": f"Context extraction failed: {e}"})
                processed += 1
                continue

            skip_reason = _pre_llm_rejection(ctx, config)
            if skip_reason:
                kb.record({**base, "analyzed": True, "status": STATUS_REJECTED,
                           "rejection_reason": skip_reason})
                audit.record(address=addr_hex, old_name=name, suggested_name="",
                             final_name="", confidence=0.0, risk="", reason="",
                             applied=False, rejection_reason=skip_reason)
                processed += 1
                continue

            callee_entries: list[dict] = []
            if graph is not None:
                callee_entries = kb.get_callee_summaries(graph.callees_of(ea))

            try:
                prompt = build_user_prompt(ctx, callee_kb_entries=callee_entries)
                raw = llm.analyze(SYSTEM_PROMPT, prompt)
                llm_calls += 1
            except LLMError as e:
                # Left unanalyzed on purpose: a transient LLM failure should be
                # retried on the next run, not baked in as a rejection.
                errors += 1
                audit.record_error(address=addr_hex, name=name, error=str(e))
                processed += 1
                continue

            validation = validate_llm_output(raw, config)

            entry = {
                **base,
                "analyzed": True,
                "confidence": float(raw.get("confidence", 0.0) or 0.0),
                "risk": str(raw.get("risk", "")).strip().lower(),
                "reason": str(raw.get("reason", "")).strip(),
                "evidence": raw.get("evidence") or {},
                "summary": raw.get("summary"),
                "security_relevant": bool(raw.get("security_relevant", False)),
                "interesting_behaviors": raw.get("interesting_behaviors") or [],
                "callee_summaries_used": [
                    e.get("new_name") or e.get("old_name", "") for e in callee_entries
                ],
            }
            if validation:
                entry["new_name"] = validation.sanitized_name
                entry["status"] = STATUS_APPROVED
            else:
                entry["new_name"] = None
                entry["status"] = STATUS_REJECTED
                entry["rejection_reason"] = validation.reason

            kb.record(entry)

            if graph is not None:
                for callee in graph.callees_of(ea):
                    kb.upsert_edge(addr_hex, f"0x{callee:X}")
                kb.flush()

            audit.record(
                address=addr_hex, old_name=name,
                suggested_name=str(raw.get("suggested_name", "")).strip(),
                final_name="", confidence=entry["confidence"],
                risk=entry["risk"], reason=entry["reason"], applied=False,
                rejection_reason=entry.get("rejection_reason", ""),
            )
            processed += 1

    print()
    kb.record_timing(llm_calls, time.time() - started)

    if refine and graph is not None:
        Refiner(graph, kb, llm, config).run()

    stats = kb.stats()
    kb.close()
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
        print("[rh] Nothing to apply — no approved, unapplied renames "
              f"at confidence >= {threshold:.2f}.")
        kb.close()
        return {"applied": 0, "skipped": 0, "errors": 0}

    verb = "Would apply" if dry_run else "Applying"
    print(f"[rh] {verb} {len(pending)} rename(s) at confidence >= {threshold:.2f}\n")

    import idc

    applied = skipped = errors = 0

    with AuditLogger(workspace.audit) as audit:
        for entry in pending:
            addr_hex = str(entry["address"])
            try:
                ea = int(addr_hex, 16)
            except ValueError:
                errors += 1
                audit.record_error(address=addr_hex,
                                   name=entry.get("old_name", "?"),
                                   error=f"Unparseable address: {addr_hex!r}")
                continue

            # Trust the database's current name over the stored one — an
            # analyst may have named this function since analysis ran.
            current = idc.get_func_name(ea) or entry.get("old_name", "")
            allowed, why = policy.can_rename(current)
            if not allowed:
                skipped += 1
                print(f"  skip  {addr_hex:<14} {current:<34} {why}")
                audit.record(
                    address=addr_hex, old_name=current,
                    suggested_name=entry.get("new_name", ""), final_name="",
                    confidence=entry.get("confidence") or 0.0,
                    risk=entry.get("risk") or "", reason=entry.get("reason") or "",
                    applied=False, rejection_reason=why,
                )
                continue

            unique = policy.resolve_conflict(entry["new_name"])
            if not unique:
                errors += 1
                print(f"  fail  {addr_hex:<14} {current:<34} name conflict")
                audit.record(
                    address=addr_hex, old_name=current,
                    suggested_name=entry.get("new_name", ""), final_name="",
                    confidence=entry.get("confidence") or 0.0,
                    risk=entry.get("risk") or "", reason=entry.get("reason") or "",
                    applied=False,
                    rejection_reason="Name conflict: exhausted suffix variants",
                )
                continue

            if dry_run:
                applied += 1
                print(f"  would {addr_hex:<14} {current:<34} -> {unique}")
                continue

            ok, detail = policy.apply_rename(
                ea, unique, summary=entry.get("summary") or ""
            )
            if ok:
                applied += 1
                kb.mark_applied(addr_hex, unique)
                print(f"  ok    {addr_hex:<14} {current:<34} -> {unique}")
                audit.record(
                    address=addr_hex, old_name=current,
                    suggested_name=entry.get("new_name", ""), final_name=unique,
                    confidence=entry.get("confidence") or 0.0,
                    risk=entry.get("risk") or "", reason=entry.get("reason") or "",
                    applied=True,
                )
            else:
                errors += 1
                print(f"  fail  {addr_hex:<14} {current:<34} {detail}")
                audit.record(
                    address=addr_hex, old_name=current,
                    suggested_name=entry.get("new_name", ""), final_name="",
                    confidence=entry.get("confidence") or 0.0,
                    risk=entry.get("risk") or "", reason=entry.get("reason") or "",
                    applied=False, rejection_reason=detail,
                )

    kb.close()

    if dry_run:
        print(f"\n[rh] Dry run — {applied} would be applied, "
              f"{skipped} skipped, {errors} would fail. Nothing was written.")
    else:
        print(f"\n[rh] Applied {applied}, skipped {skipped}, errors {errors}.")
        print("[rh] Changes are saved when the database closes.")
    print(f"[rh] Audit log: {workspace.audit}")

    return {"applied": applied, "skipped": skipped, "errors": errors}


# ==========================================================================
# Display helpers
# ==========================================================================

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
        f"\n[rh] Done — {calls} LLM call(s) this run\n"
        f"  Analyzed total : {stats['analyzed']}\n"
        f"  Approved       : {stats['approved']}\n"
        f"  Rejected       : {stats['rejected']}\n"
        f"  LLM errors     : {errors} (will be retried)\n"
    )
    if stats["pending_apply"]:
        print(f"  {stats['pending_apply']} rename(s) ready to apply.\n")
