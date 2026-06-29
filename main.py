#!/usr/bin/env python3
"""
llm_renamer — standalone CLI

Renames auto-generated IDA Pro functions (sub_*, j_*, nullsub_*, …) using a
local Ollama LLM, by opening the IDA database directly via idapro.

Workflow
--------
1. Run in review mode (no DB changes):
       python main.py --database target.i64

2. Inspect the review JSON, then apply:
       python main.py --database target.i64 --apply

3. Process only a batch of N functions (checkpoint resumes next run):
       python main.py --database target.i64 --limit 200

4. Apply from a previous review file:
       python main.py --database target.i64 --apply-file llm_renames_review.json

5. After analysis, build the semantic vector index:
       python main.py --database target.i64 --build-index

6. Query the knowledge base:
       python query.py "user-controlled length without bounds check"

Options
-------
  --database PATH        Path to the .i64 IDA database  (required)
  --config PATH          Path to config.json  (default: llm_renamer/config.json)
  --ollama-url URL       Override Ollama server URL
  --model NAME           Override Ollama model name
  --out-dir DIR          Directory for output files (default: cwd)
  --limit N              Stop after analyzing N functions (checkpoint saves progress)
  --function NAME ...    Analyze only the named function(s); implies --quick
  --quick                Skip call graph build, scoring, and refinement (Phases 1/2/4)
  --apply                Analyze AND apply approved renames + IDA comments into the database
  --apply-file PATH      Apply renames from an existing review JSON (no LLM)
  --rebuild-graph        Discard cached call graph and rebuild
  --skip-refine          Skip Phase 4 top-down refinement pass
  --build-index          Build FAISS vector index after analysis (Phase 5)
  --clear-checkpoint     Reset checkpoint so all functions are reprocessed
  --no-resume            Ignore checkpoint; reprocess everything
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from llm_renamer.config import load_config
from llm_renamer.idapro_client import FunctionContextExtractor
from llm_renamer.llm_client import OllamaClient, LLMError
from llm_renamer.validator import validate_llm_output, is_auto_generated_name
from llm_renamer.renamer import RenamePolicy
from llm_renamer.audit import AuditLogger
from llm_renamer.checkpoint import Checkpoint
from llm_renamer.review import ReviewWriter
from llm_renamer.prompts import SYSTEM_PROMPT, build_user_prompt
from llm_renamer.call_graph import CallGraph, load_or_build
from llm_renamer.scorer import build_worklist, score_node, depth_from_leaves
from llm_renamer.kb import KnowledgeBase
from llm_renamer.refiner import Refiner


# ==========================================================================
# Output path helpers
# ==========================================================================

def _build_paths(config: dict, out_dir: str) -> dict:
    os.makedirs(out_dir, exist_ok=True)
    graph_name = config.get("graph", {}).get("cache_filename", "call_graph.json")
    kb_name    = config.get("kb",    {}).get("sqlite_filename", "knowledge_base.sqlite")
    faiss_name = config.get("kb",    {}).get("faiss_filename",  "kb_vectors.faiss")
    return {
        "review":         os.path.join(out_dir, config["output"]["review_filename"]),
        "audit":          os.path.join(out_dir, config["output"]["audit_filename"]),
        "checkpoint":     os.path.join(out_dir, config["output"]["checkpoint_filename"]),
        "call_graph":     os.path.join(out_dir, graph_name),
        "knowledge_base": os.path.join(out_dir, kb_name),
        "faiss":          os.path.join(out_dir, faiss_name),
    }


# ==========================================================================
# Analysis loop  (Phase 3)
# ==========================================================================

def run_analysis(
    config: dict,
    paths: dict,
    apply_mode: bool,
    extractor: FunctionContextExtractor,
    use_checkpoint: bool = True,
    graph: CallGraph | None = None,
    kb: KnowledgeBase | None = None,
    scores: dict | None = None,
    limit: int | None = None,
    target_functions: list[str] | None = None,
) -> None:
    llm      = OllamaClient(config)
    policy   = RenamePolicy(config, extractor)
    reviewer = ReviewWriter(paths["review"])

    # Targeted mode bypasses checkpoint — the user explicitly asked for these.
    targeted = bool(target_functions)
    checkpoint = (
        _NullCheckpoint() if (not use_checkpoint or targeted)
        else Checkpoint(paths["checkpoint"])
    )

    mode_label = "Apply" if apply_mode else "Review"

    if targeted:
        print(f"[llm_renamer] Targeted mode — looking up {len(target_functions)} function(s)…")
        raw_funcs = extractor.get_functions_by_name(target_functions)
        if not raw_funcs:
            print("[llm_renamer] No matching functions found.")
            return
    else:
        print("[llm_renamer] Fetching auto-generated functions…")
        raw_funcs = extractor.get_all_auto_functions()

    # ---- Phase 2: build scored, bottom-up ordered worklist ----------------
    if graph is not None and raw_funcs:
        auto_addr_set = {int(r["address"]) for r in raw_funcs}
        func_map = {int(r["address"]): r for r in raw_funcs}
        ordered_addrs = [
            a for a in build_worklist(graph, config) if a in auto_addr_set
        ]
        ordered_addrs += [a for a in auto_addr_set if a not in set(ordered_addrs)]
        funcs = [func_map[a] for a in ordered_addrs]
        print(f"[llm_renamer] Worklist built: {len(funcs)} functions in scored order")
    else:
        funcs = raw_funcs

    total     = len(funcs)
    skipped   = checkpoint.count()
    processed = 0
    applied   = 0
    errors    = 0
    llm_calls_this_run = 0

    print(
        f"[llm_renamer] {mode_label} mode — "
        f"{total} auto-generated functions ({skipped} already checkpointed)"
    )
    if limit is not None:
        print(f"[llm_renamer] --limit {limit}: will stop after {limit} LLM calls this run")

    with AuditLogger(paths["audit"]) as audit:
        for func_row in funcs:
            ea   = int(func_row["address"])
            name = str(func_row.get("name", f"sub_{ea:X}"))
            addr_hex = f"0x{ea:X}"

            reviewer.increment_processed()

            # ---- skip if already in KB ------------------------------------
            if kb is not None and kb.is_phase3_done(addr_hex):
                processed += 1
                continue

            # ---- checkpoint skip ------------------------------------------
            if checkpoint.is_done(ea):
                processed += 1
                continue

            _progress(processed, total, name, applied, errors)

            # ---- extract context ------------------------------------------
            try:
                ctx = extractor.extract(func_row)
            except Exception as e:
                errors += 1
                reviewer.increment_errors()
                audit.record_error(address=addr_hex, name=name,
                                   error=f"Context extraction failed: {e}")
                checkpoint.mark_done(ea)
                processed += 1
                continue

            # ---- skip if no pseudocode ------------------------------------
            if not ctx.get("pseudocode"):
                msg = "No Hex-Rays pseudocode available"
                reviewer.add_rejected(address=addr_hex, current_name=name,
                                      rejection_reason=msg)
                audit.record(address=addr_hex, old_name=name,
                             suggested_name="", final_name="",
                             confidence=0.0, risk="", reason="",
                             applied=False, rejection_reason=msg)
                checkpoint.mark_done(ea)
                processed += 1
                continue

            # ---- skip trivially short pseudocode --------------------------
            min_lines = config["analysis"].get("min_pseudocode_lines", 3)
            if ctx["pseudocode"].count("\n") + 1 < min_lines:
                msg = f"Pseudocode < {min_lines} lines — too trivial"
                reviewer.add_rejected(address=addr_hex, current_name=name,
                                      rejection_reason=msg)
                audit.record(address=addr_hex, old_name=name,
                             suggested_name="", final_name="",
                             confidence=0.0, risk="", reason="",
                             applied=False, rejection_reason=msg)
                checkpoint.mark_done(ea)
                processed += 1
                continue

            # ---- enforce per-run limit ------------------------------------
            if limit is not None and llm_calls_this_run >= limit:
                print(
                    f"\n[llm_renamer] --limit {limit} reached. "
                    "Checkpoint saved; run again to continue."
                )
                break

            # ---- inject callee summaries from KB --------------------------
            callee_entries: list[dict] = []
            if kb is not None and graph is not None:
                callee_addrs = graph.callees_of(ea)
                callee_entries = kb.get_callee_summaries(callee_addrs)

            # ---- query LLM ------------------------------------------------
            try:
                user_prompt  = build_user_prompt(ctx, callee_kb_entries=callee_entries)
                raw_response = llm.analyze(SYSTEM_PROMPT, user_prompt)
                llm_calls_this_run += 1
            except LLMError as e:
                errors += 1
                reviewer.increment_errors()
                audit.record_error(address=addr_hex, name=name, error=str(e))
                processed += 1
                continue

            # ---- validate rename ------------------------------------------
            validation = validate_llm_output(raw_response, config)

            confidence = float(raw_response.get("confidence", 0.0))
            risk       = str(raw_response.get("risk", "")).strip().lower()
            reason     = str(raw_response.get("reason", "")).strip()
            evidence   = raw_response.get("evidence", {})
            raw_name   = str(raw_response.get("suggested_name", "")).strip()

            # ---- write to knowledge base ----------------------------------
            if kb is not None:
                node = graph.nodes.get(ea) if graph else None
                kb.upsert({
                    "address":               addr_hex,
                    "old_name":              name,
                    "new_name":              validation.sanitized_name if validation else None,
                    "confidence":            confidence,
                    "summary":               raw_response.get("summary"),
                    "security_relevant":     bool(raw_response.get("security_relevant", False)),
                    "interesting_behaviors": raw_response.get("interesting_behaviors") or [],
                    "callee_summaries_used": [
                        e.get("new_name") or e.get("old_name", "")
                        for e in callee_entries
                    ],
                    "caller_count": node.caller_count if node else 0,
                    "score":        scores.get(ea, 0.0) if scores else 0.0,
                    "phase3_done":  True,
                    "phase4_refined": False,
                })
                if graph is not None:
                    for callee_addr in graph.callees_of(ea):
                        kb.upsert_edge(addr_hex, f"0x{callee_addr:X}")
                    kb.flush()

            # ---- handle validation failure --------------------------------
            if not validation:
                reviewer.add_rejected(
                    address=addr_hex, current_name=name,
                    suggested_name=raw_name,
                    confidence=confidence, risk=risk, reason=reason,
                    evidence=evidence,
                    rejection_reason=validation.reason,
                )
                audit.record(
                    address=addr_hex, old_name=name,
                    suggested_name=raw_name, final_name="",
                    confidence=confidence, risk=risk, reason=reason,
                    applied=False, rejection_reason=validation.reason,
                )
                checkpoint.mark_done(ea)
                processed += 1
                continue

            sanitized = validation.sanitized_name
            reviewer.add_approved(
                address=addr_hex, current_name=name,
                suggested_name=sanitized,
                confidence=confidence, risk=risk,
                reason=reason, evidence=evidence,
            )

            # ---- apply if requested ---------------------------------------
            apply_success = False
            apply_detail  = ""
            summary = str(raw_response.get("summary", "")).strip()

            if apply_mode:
                allowed, policy_reason = policy.can_rename(name)
                if allowed:
                    unique_name = policy.resolve_conflict(sanitized)
                    if unique_name:
                        ok, detail = policy.apply_rename(ea, unique_name, summary=summary)
                        if ok:
                            apply_success = True
                            apply_detail  = unique_name
                            applied += 1
                        else:
                            apply_detail = detail
                    else:
                        apply_detail = "Name conflict: exhausted suffix variants"
                else:
                    apply_detail = policy_reason

            audit.record(
                address=addr_hex, old_name=name,
                suggested_name=sanitized,
                final_name=apply_detail if apply_success else "",
                confidence=confidence, risk=risk, reason=reason,
                applied=apply_success,
                rejection_reason="" if apply_success else apply_detail,
            )

            checkpoint.mark_done(ea)
            processed += 1

    reviewer.save()
    _print_summary(mode_label, processed, total, reviewer, applied, errors, paths)


# ==========================================================================
# Apply-from-file  (no LLM)
# ==========================================================================

def run_apply_from_file(
    config: dict,
    paths: dict,
    review_path: str,
    extractor: FunctionContextExtractor,
) -> None:
    try:
        proposals = ReviewWriter.load_proposals(review_path)
    except (json.JSONDecodeError, IOError) as e:
        print(f"[llm_renamer] ERROR: Cannot load review file: {e}")
        sys.exit(1)

    policy    = RenamePolicy(config, extractor)
    threshold = float(config["analysis"]["confidence_threshold"])
    skip_high = config["analysis"].get("skip_high_risk", True)

    applied = 0
    skipped = 0
    errors  = 0

    with AuditLogger(paths["audit"]) as audit:
        for prop in proposals:
            if prop.get("validation_status") != "approved":
                skipped += 1
                continue

            conf = float(prop.get("confidence", 0.0))
            if conf < threshold:
                skipped += 1
                continue

            risk = str(prop.get("risk", "")).strip().lower()
            if skip_high and risk == "high":
                skipped += 1
                continue

            addr_str = prop.get("address", "")
            try:
                ea = int(addr_str, 16)
            except ValueError:
                errors += 1
                audit.record_error(
                    address=addr_str,
                    name=prop.get("current_name", "?"),
                    error=f"Cannot parse address: {addr_str!r}",
                )
                continue

            import idc
            current_name = idc.get_func_name(ea) or prop.get("current_name", "")

            allowed, reason = policy.can_rename(current_name)
            if not allowed:
                skipped += 1
                audit.record(
                    address=addr_str, old_name=current_name,
                    suggested_name=prop.get("suggested_name", ""),
                    final_name="", confidence=conf, risk=risk,
                    reason=prop.get("reason", ""),
                    applied=False, rejection_reason=reason,
                )
                continue

            unique_name = policy.resolve_conflict(prop["suggested_name"])
            if not unique_name:
                errors += 1
                audit.record(
                    address=addr_str, old_name=current_name,
                    suggested_name=prop["suggested_name"],
                    final_name="", confidence=conf, risk=risk,
                    reason=prop.get("reason", ""),
                    applied=False,
                    rejection_reason="Name conflict: exhausted suffix variants",
                )
                continue

            ok, detail = policy.apply_rename(ea, unique_name)
            if ok:
                applied += 1
                print(f"  0x{ea:X}  {current_name}  →  {unique_name}")
                audit.record(
                    address=addr_str, old_name=current_name,
                    suggested_name=prop["suggested_name"],
                    final_name=unique_name,
                    confidence=conf, risk=risk,
                    reason=prop.get("reason", ""),
                    applied=True,
                )
            else:
                errors += 1
                audit.record(
                    address=addr_str, old_name=current_name,
                    suggested_name=prop["suggested_name"],
                    final_name="", confidence=conf, risk=risk,
                    reason=prop.get("reason", ""),
                    applied=False, rejection_reason=detail,
                )

    print(
        f"\n[llm_renamer] Apply complete — "
        f"applied:{applied}  skipped:{skipped}  errors:{errors}"
    )
    print(f"  Audit log: {paths['audit']}")


# ==========================================================================
# Helpers
# ==========================================================================

class _NullCheckpoint:
    def is_done(self, ea): return False
    def mark_done(self, ea): pass
    def count(self): return 0


def _progress(processed, total, name, applied, errors):
    pct = int(100 * processed / total) if total else 0
    print(
        f"\r[{pct:3d}%] {processed}/{total}  {name[:40]:<40}  "
        f"applied:{applied}  errors:{errors}",
        end="", flush=True,
    )


def _print_summary(mode, processed, total, reviewer, applied, errors, paths):
    print()
    stats = reviewer.stats
    lines = [
        "",
        f"[llm_renamer] {mode} complete",
        f"  Processed   : {processed} / {total}",
        f"  Approved    : {stats['total_proposed_approved']}",
        f"  Rejected    : {stats['total_rejected']}",
        f"  LLM errors  : {errors}",
    ]
    if mode == "Apply":
        lines.append(f"  Applied     : {applied}")
    lines += [
        "",
        f"  Review file      : {paths['review']}",
        f"  Audit log        : {paths['audit']}",
        f"  Checkpoint       : {paths['checkpoint']}",
        f"  Knowledge base   : {paths['knowledge_base']}",
    ]
    print("\n".join(lines))


# ==========================================================================
# CLI entry point
# ==========================================================================

def _parse_args():
    p = argparse.ArgumentParser(
        description="Rename IDA auto-generated functions using a local LLM via idapro",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--database", metavar="PATH", required=True,
        help="Path to the .i64 IDA database file",
    )
    p.add_argument(
        "--config",
        default=os.path.join(os.path.dirname(__file__), "llm_renamer", "config.json"),
        metavar="PATH",
    )
    p.add_argument("--ollama-url", metavar="URL")
    p.add_argument("--model",      metavar="NAME")
    p.add_argument("--out-dir",    metavar="DIR")
    p.add_argument(
        "--limit", metavar="N", type=int, default=None,
        help="Stop after N LLM calls; checkpoint saves progress for the next run",
    )
    p.add_argument(
        "--function", metavar="NAME", nargs="+", default=None,
        help="Analyze only these function(s) by name or hex address; implies --quick",
    )
    p.add_argument(
        "--quick", action="store_true",
        help="Skip call graph build, scoring, and refinement (Phases 1/2/4); "
             "useful for testing or targeting specific functions",
    )

    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--apply",      action="store_true")
    mode.add_argument("--apply-file", metavar="PATH")

    p.add_argument("--rebuild-graph",    action="store_true")
    p.add_argument("--skip-refine",      action="store_true")
    p.add_argument("--build-index",      action="store_true")
    p.add_argument("--clear-checkpoint", action="store_true")
    p.add_argument("--no-resume",        action="store_true")
    return p.parse_args()


def main():
    args = _parse_args()

    # Allow comma-separated function names: --function a,b,c or --function a b c
    if args.function:
        args.function = [f for item in args.function for f in item.split(",") if f]

    # ---- validate database path ------------------------------------------
    db_path = os.path.abspath(args.database)
    if not os.path.exists(db_path):
        print(f"[llm_renamer] ERROR: database not found: {db_path}")
        sys.exit(1)

    config_dir = os.path.dirname(os.path.abspath(args.config))
    config = load_config(config_dir)

    if args.ollama_url:
        config["ollama"]["url"] = args.ollama_url
    if args.model:
        config["ollama"]["model"] = args.model

    out_dir = args.out_dir or config["output"].get("dir") or os.getcwd()
    paths   = _build_paths(config, out_dir)

    # --clear-checkpoint (no IDA needed)
    if args.clear_checkpoint:
        cp = Checkpoint(paths["checkpoint"])
        n  = cp.count()
        cp.clear()
        print(f"[llm_renamer] Checkpoint cleared ({n} addresses removed).")
        return

    # ---- open IDA database -----------------------------------------------
    import idapro
    print(f"[llm_renamer] Opening database: {db_path}")
    idapro.open_database(db_path, run_auto_analysis=False)

    try:
        _run(args, config, paths, db_path)
    finally:
        print("[llm_renamer] Closing database…")
        idapro.close_database()


def _run(args, config, paths, db_path):
    """All work that requires the IDA database to be open."""
    extractor = FunctionContextExtractor(config)

    _check_ollama(config)

    if args.apply:
        print("[llm_renamer] WARNING: apply mode will write renames + IDA comments into the database.")
        answer = input("Proceed? [y/N] ").strip().lower()
        if answer != "y":
            print("Aborted.")
            return

    # --apply-file: no LLM or graph required
    if args.apply_file:
        print(f"[llm_renamer] Apply-from-file: {args.apply_file}")
        run_apply_from_file(config, paths, args.apply_file, extractor)
        return

    # --function implies --quick (no graph needed for targeted runs)
    quick = args.quick or bool(args.function)

    if quick:
        print("[llm_renamer] Quick mode — skipping call graph build and refinement.")
        graph  = None
        scores = None
        kb     = KnowledgeBase(paths["knowledge_base"])
    else:
        # ---- Phase 1: build / load call graph ----------------------------
        graph = load_or_build(
            extractor, config,
            paths["call_graph"],
            force_rebuild=args.rebuild_graph,
        )
        # Pre-compute scores for KB storage
        depths = depth_from_leaves(graph)
        scores: dict[int, float] = {
            addr: score_node(node, config) + float(depths.get(addr, 0))
            for addr, node in graph.nodes.items()
        }
        kb = KnowledgeBase(paths["knowledge_base"])

    # ---- Phase 3 + KB ----------------------------------------------------
    run_analysis(
        config=config,
        paths=paths,
        apply_mode=args.apply,
        extractor=extractor,
        use_checkpoint=not args.no_resume,
        graph=graph,
        kb=kb,
        scores=scores,
        limit=args.limit,
        target_functions=args.function,
    )

    # ---- Phase 4: top-down refinement (skipped in quick mode) ------------
    if quick or args.skip_refine:
        if not quick:
            print("[llm_renamer] Skipping Phase 4 refinement (--skip-refine).")
    else:
        llm = OllamaClient(config)
        Refiner(graph, kb, llm, config).run()

    # ---- Phase 5: build FAISS index --------------------------------------
    if args.build_index:
        _build_faiss_index(config, paths, kb)

    print(
        "\n[llm_renamer] All phases complete.\n"
        f"  Query the KB:  python query.py \"<your research question>\"\n"
        f"  Score report:  python query.py --score-report\n"
        f"  Security fns:  python query.py --report"
    )


def _build_faiss_index(config: dict, paths: dict, kb: KnowledgeBase) -> None:
    try:
        from llm_renamer.embedder import Embedder, EmbedderUnavailable
    except ImportError:
        print("[llm_renamer] Cannot import embedder — is faiss-cpu installed?")
        return

    faiss_config = {
        **config,
        "kb": {
            **config.get("kb", {}),
            "faiss_file": paths["faiss"],
        },
    }
    embedder = Embedder(faiss_config)
    entries  = kb.get_all_for_embedding()
    print(f"[llm_renamer] Building FAISS index for {len(entries)} entries…")
    try:
        embedder.build_index(entries)
    except EmbedderUnavailable as e:
        print(f"[llm_renamer] Embedder unavailable: {e}")


def _check_ollama(config):
    llm = OllamaClient(config)
    if not llm.health_check():
        url   = config["ollama"]["url"]
        model = config["ollama"]["model"]
        print(
            f"[llm_renamer] ERROR: Ollama is not reachable at {url}\n"
            f"  Start it with:  ollama run {model}"
        )
        sys.exit(1)
    print(f"[llm_renamer] Ollama OK  ({config['ollama']['model']})")


if __name__ == "__main__":
    main()
