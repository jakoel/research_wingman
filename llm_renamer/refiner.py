"""
Top-down refinement, plus deterministic naming-defect repair.

Two mechanisms live here (see ARCHITECTURE §8):

`Refiner.run()` -- after the bottom-up LLM pass (Phase 3) completes, one
downward pass re-queries functions whose caller context was unavailable when
they were first analyzed. Rules:
  - One pass per function; no looping.
  - Skip functions at/above kb.refinement_confidence_skip, EXCEPT `wrapper_*`
    entries, whose high confidence is structural (a bare forward) rather than
    semantic, and which are therefore exactly the ones worth a second look.
  - No KB write unless `_response_changed` reports a real change -- which
    trusts a differing `suggested_name` over a contradicting `changed` flag.

`repair_naming_conflicts()` -- a separate, targeted pass that asks "does the
CURRENT stored answer violate a mechanically checkable rule?" rather than "has
anything new changed?". It loops until a round fixes nothing, because repairing
one collision can create another against a third function. It is deliberately
never a blanket re-review: re-rolling unflagged answers measurably regresses
correct ones.
"""

from __future__ import annotations

import re
from collections import defaultdict

from . import family
from .call_graph import CallGraph
from .kb import KnowledgeBase
from .llm_client import OllamaClient, LLMError
from .prompts import load_prompt


_SYSTEM_PROMPT = load_prompt("refine.md")


class Refiner:
    def __init__(
        self,
        graph: CallGraph,
        kb: KnowledgeBase,
        llm: OllamaClient,
        config: dict,
        llm_log=None,
        extractor=None,
    ) -> None:
        self._graph = graph
        self._kb = kb
        self._llm = llm
        self._config = config
        self._llm_log = llm_log
        # Optional: enables real call-site snippets (not just caller
        # summaries) for wrapper_*/trivial-bodied entries -- see
        # `_build_prompt`. Refinement still works without it, just without
        # that extra evidence.
        self._extractor = extractor

    def run(self) -> int:
        """
        Execute one top-down refinement pass.
        Returns the number of KB entries that were updated.
        """
        skip_conf = float(
            self._config.get("kb", {}).get("refinement_confidence_skip", 0.85)
        )
        candidates = self._kb.get_unrefined(skip_conf)
        if not candidates:
            print("[refiner] Nothing to refine.")
            return 0

        total = len(candidates)
        print(f"[refiner] Refining {total} functions…")
        updated = 0

        # Per-item progress -- this loop used to be a black box: one line at
        # the start, one at the end, and nothing for however long it took to
        # get through every candidate in between (a real, live-observed gap:
        # a run silently sat here for minutes with the console indistinguishable
        # from a hang). Every branch below now prints exactly one line, same
        # density as the main analyze loop and the sibling repair pass below,
        # which already logged per-item and never had this problem.
        for i, entry in enumerate(candidates, 1):
            addr_str = str(entry["address"])
            name = entry.get("new_name") or entry.get("old_name") or "?"
            addr_int = _parse_addr(addr_str)
            progress = f"[refiner] ({i}/{total}) {addr_str} {name}"

            if addr_int is None:
                print(f"{progress}: unparseable address, skipped")
                self._kb.mark_refined(addr_str)
                continue

            callers_in_graph = self._graph.callers_of(addr_int)
            caller_entries = self._kb.get_callers_in_kb(addr_str, callers_in_graph)

            if not caller_entries:
                print(f"{progress}: no analyzed caller yet, skipped")
                self._kb.mark_refined(addr_str)
                continue

            callees_in_graph = self._graph.callees_of(addr_int)
            callee_entries = self._kb.get_callee_summaries(callees_in_graph)

            prompt = _build_prompt(entry, caller_entries, callee_entries,
                                   self._extractor, addr_int,
                                   self._graph.nodes.get(addr_int),
                                   config=self._config, kb=self._kb)
            try:
                raw, _, _ = self._llm.analyze_sized(_SYSTEM_PROMPT, prompt)
            except LLMError as e:
                # Deliberately NOT mark_refined here, unlike every other skip
                # branch in this loop -- those are structural facts that a
                # rerun can't change (unparseable address, no caller yet), but
                # an LLM error is transient (a network blip, a busy server).
                # Marking it refined anyway silently drops the function from
                # every future refine pass forever. Confirmed real 2026-08-19:
                # a mid-run Ollama outage left 57 functions permanently
                # unrefined this way until manually reset via a one-off
                # phase4_refined=0 UPDATE.
                print(f"{progress}: LLM error: {e}")
                continue

            if self._llm_log is not None:
                self._llm_log.record(
                    address=addr_str, old_name=entry.get("old_name", ""),
                    phase="refine", model=self._config["ollama"]["model"],
                    raw_response=raw if isinstance(raw, dict) else {"raw": raw},
                    validation={"changed": bool(isinstance(raw, dict) and raw.get("changed"))},
                )

            if not isinstance(raw, dict) or not _response_changed(raw, entry.get("new_name") or ""):
                print(f"{progress}: no change")
                self._kb.mark_refined(addr_str)
                continue

            # Something improved — update the KB
            new_name, summary, confidence, sec_rel, behaviors = \
                _merge_refinement_fields(raw, entry)

            self._kb.update_after_refinement(
                addr_str, new_name, summary, confidence, sec_rel, behaviors
            )
            updated += 1
            print(f"{progress} -> {new_name}  (conf={confidence:.2f})")

        print(f"[refiner] Done — {updated}/{total} entries updated.")
        return updated


# ---------------------------------------------------------------------------
# Naming-conflict repair
#
# The normal refine loop above only writes when the LLM says changed=true,
# which means an entry that already settled into a bad state (before the
# callee-context fix below existed) keeps getting echoed back verbatim on
# every future refine pass -- "has anything NEW changed" is the wrong
# question for "does the CURRENT answer violate a rule we now know about".
# This is a separate, deterministic pass: detect two specific defects that
# real-code verification found (2026-08-01 random-sample audit, see
# queuetask.md) and force a corrective LLM call for exactly those entries,
# regardless of the changed flag.
# ---------------------------------------------------------------------------

_REPAIR_SYSTEM_PROMPT = load_prompt("repair.md")

_DELEGATION_WORDS = r"(?:forwards?|delegates?|calls?|returns?(?: the result of)?)"


_TRAILING_NUMERIC_SUFFIX = re.compile(r"_(\d+)$")


def _is_specific_name(name: str) -> bool:
    """
    True if `name` is a resolved, specific identity rather than a shared
    `wrapper_<word>` FAMILY BUCKET label.

    Many genuinely-distinct functions deliberately propose the identical
    unsuffixed `wrapper_identity` / `wrapper_return_void` / etc. base name
    (by design -- see the conflict-suffix-cap fix in queuetask.md); that
    collision is expected and resolved with a numeric/hex suffix at apply
    time, not a bug. Once a name carries its own trailing `_<digits>` (the
    refiner copied a live, already-resolved name) or never had the
    `wrapper_` prefix at all (a final descriptive name), it is no longer a
    shared bucket label -- any collision or self-reference involving it is
    real, not an artifact of the shared-bucket convention.
    """
    if not name.startswith("wrapper_"):
        return True
    return bool(_TRAILING_NUMERIC_SUFFIX.search(name))


def _detect_conflict(entry: dict, callee_entries: list[dict]) -> str | None:
    """
    Return a short human-readable description of a detected naming defect
    in `entry`, or None if it looks fine.

    1. Collision: `new_name` is identical to one of this function's own
       direct callees -- the real implementation's name got copied onto the
       thunk that forwards to it (collides at apply time).
    2. Self-reference: the summary/reason describes this function as
       forwarding/delegating/calling its OWN current name, when a forwarding
       description should name the callee, never itself.

    Both checks are gated on `_is_specific_name` -- see its docstring for why
    a shared `wrapper_*` bucket label must not be flagged here.
    """
    name = (entry.get("new_name") or "").strip()
    if not name or not _is_specific_name(name):
        return None

    callee_names = {
        (c.get("new_name") or c.get("old_name") or "").strip()
        for c in callee_entries
    }
    callee_names.discard("")

    if name in callee_names:
        return (
            f"proposed name '{name}' is identical to one of this function's "
            f"own callees' names -- the real implementation belongs to the "
            f"callee, not this forwarding thunk"
        )

    text = f"{entry.get('summary') or ''} {entry.get('reason') or ''}"
    if name not in callee_names:
        pattern = rf"\b{_DELEGATION_WORDS}\b[^.]{{0,60}}\b{re.escape(name)}\b"
        if re.search(pattern, text, re.IGNORECASE):
            return (
                f"summary/reason describes this function as forwarding to or "
                f"returning the result of '{name}' -- but that IS this "
                f"function's own current name, not a distinct callee it "
                f"delegates to (self-reference)"
            )

    return None


def _detect_duplicate_name(entry: dict, others_with_same_name: list[dict]) -> str | None:
    """
    Flag a specific (non-`wrapper_*`-bucket, see `_is_specific_name`) name
    shared with a DIFFERENT, unrelated approved function elsewhere in the KB
    -- caller/callee sharing is handled by `_detect_conflict` already, so
    `others_with_same_name` should exclude those before calling this.

    Confirmed real case (2026-08-01, applied then caught by audit): a
    no-op/void callback and a genuine identity/pass-through function ended up
    both named `identity_callback` -- semantically different functions, not
    a coincidental collision between structurally-identical siblings (which
    IS common and fine here -- see `_is_specific_name`'s docstring on the
    `wrapper_*` bucket convention; the same pattern occurs for non-`wrapper_`
    names too, e.g. several genuinely-identical `noop_callback` bodies).
    Apply-time suffixing handles either case mechanically without error, so
    this is advisory context for the model to weigh, not proof of a bug --
    unlike `_detect_conflict`'s two checks, which are always wrong when they
    fire.
    """
    name = (entry.get("new_name") or "").strip()
    if not name or not _is_specific_name(name) or not others_with_same_name:
        return None
    other_addrs = ", ".join(str(o["address"]) for o in others_with_same_name)
    return (
        f"new_name '{name}' is also used by a different, unrelated "
        f"function at {other_addrs} -- confirm this function genuinely "
        f"does the same thing as that one (a real duplicate-body sibling, "
        f"where sharing a name is fine), or if it does something else, "
        f"pick a name describing THIS function's own behavior instead of "
        f"one borrowed from something unrelated nearby"
    )


def repair_naming_conflicts(
    graph: CallGraph,
    kb: KnowledgeBase,
    llm: OllamaClient,
    config: dict,
    extractor=None,
    llm_log=None,
    max_rounds: int | None = None,
) -> int:
    """
    Repeatedly scan all approved, analyzed entries for the defect classes in
    `_detect_conflict` (collision, self-reference -- always genuinely wrong
    when they fire) and `_detect_duplicate_name` (cross-KB "this name is also
    used elsewhere," gated on `body_hash` so a confirmed structural family
    never gets flagged -- see the comment in `_repair_round` for the
    re-enable history), forcing a corrective LLM call for each match, until a
    full round fixes nothing or `max_rounds` is reached.

    Looping (not a single pass) matters: resolving one entry's collision by
    renaming it can land it on a name that collides with a THIRD, previously
    unrelated entry -- confirmed 2026-08-01, twice in the same repair run
    (fixing `0x4113E8`'s collision with `0x41119F` moved it onto
    `set_error_category_vtable`, already used by the unrelated, previously
    fine `0x411433`). A single pass only sees collisions that existed before
    it started; only re-scanning the KB state after each round's writes
    catches ones the round itself just created. `max_rounds` is a safety
    cap against pathological back-and-forth, not an expected ceiling --
    healthy runs converge (a round that fixes nothing) well before it.

    `seen_names` (per-address name history for this call only, not persisted)
    guards against a real, repeatedly-observed failure mode distinct from the
    third-party collision above: an entry ping-pongs between the SAME two
    LLM-proposed names forever (`atomic_compare_and_swap_ptr` <->
    `atomic_compare_and_swap_ptr_check_status`, `atomic_increment_and_check`
    <-> `atomic_increment_and_get`, ... -- confirmed 2026-08-19, twice, in
    consecutive runs of the same sample, still unresolved at max_rounds=5
    both times). `_repair_round` refuses to write a name back onto an
    address once that exact name has already appeared for it earlier in this
    call, which converges a 2-cycle in exactly 2 rounds instead of burning
    every remaining round on the same flip. It also catches the noisier
    variant of the same root cause -- gemma4:26b's repair response sometimes
    sets `no_change: false` while proposing the CURRENT name back unchanged
    (`_response_changed` trusts the flag over the identical name), which
    previously logged a no-op "repaired X -> X" and re-counted as `fixed`
    every single round without anything actually changing.

    This is meant to stay a targeted, bounded mechanism (only entries
    matching a concrete, checkable problem) -- never a blanket re-review of
    everything. A full unconditional resweep was tried once (2026-08-01)
    specifically to catch cases like this that no detector covered yet, and
    while it did surface a genuine, long-standing improvement, it also
    introduced new regressions by re-rolling entries that had never been
    flagged as suspect. Every re-review needs a concrete reason; if a new
    defect shape turns up again, the fix is another targeted check here, not
    another blanket sweep.
    """
    if max_rounds is None:
        max_rounds = int(config.get("kb", {}).get("repair_max_rounds", 5))
    total_fixed = 0
    seen_names: dict[str, set[str]] = {}
    for round_num in range(1, max_rounds + 1):
        fixed = _repair_round(graph, kb, llm, config, extractor, llm_log, round_num, seen_names)
        total_fixed += fixed
        if fixed == 0:
            break
    else:
        print(f"[refiner] Reached max_rounds={max_rounds} without full "
              f"convergence -- some entries may still be flagged; check "
              f"manually rather than raising the cap blindly.")
    return total_fixed


def _repair_round(
    graph: CallGraph,
    kb: KnowledgeBase,
    llm: OllamaClient,
    config: dict,
    extractor,
    llm_log,
    round_num: int,
    seen_names: dict[str, set[str]],
) -> int:
    """One scan-and-fix pass of `repair_naming_conflicts`. See there for why
    this must be called repeatedly rather than once."""
    from .kb import STATUS_APPROVED

    rows = [r for r in kb.get_all_analyzed() if r.get("status") == STATUS_APPROVED]

    # `_detect_duplicate_name` (cross-KB "this name is also used elsewhere")
    # was disabled 2026-08-15 -- on 3b8e... (1246 approved functions) it fired
    # on 881 of them in one run (71%), almost all resolving to "no change
    # needed": large genuine near-duplicate families (obfuscation-primitive
    # functions the model gave a shared descriptive name) got every member
    # individually flagged and individually LLM-confirmed as legitimate, with
    # no cluster-level awareness that the pattern was already confirmed 40+
    # times this round.
    #
    # First re-enable attempt (2026-08-19) gated only on `body_hash`
    # (family.py, added the same day) -- flag a collision only when the two
    # entries do NOT share a body_hash, on the theory that a shared name is
    # more likely a genuine mistake (the motivating case: an unrelated no-op
    # callback and a real identity/pass-through function both named
    # `identity_callback`) than a legitimate family. That alone turned out
    # NOT to fix the actual storm: re-validated live against 3b8e (the exact
    # 1246-function sample the original 881 came from) and it still flagged
    # 849. Root cause, found by inspecting the real collision groups: 3b8e's
    # biggest ones (`obfuscate_and_cache_peb_status`, 62 members;
    # `decrypt_obfuscated_config_blob`, 63; ... one group of 114) have
    # members with 62/63/114 *DIFFERENT* body_hashes each -- these are
    # thematically-similar but structurally-distinct functions the model
    # chose to describe with the same generic name, not structural twins
    # `body_hash` was ever meant to catch. The real bug shape this check
    # exists for is small: `identity_callback` was a PAIR. Confirmed by the
    # actual size distribution of still-flagged collision groups on 3b8e:
    # capping at group size <= 3 cuts 856 flagged members down to 115 while
    # keeping every group of 2-3 (the plausible real-mistake shape) intact.
    #
    # Final gate, both conditions required: (1) doesn't share a body_hash
    # with the other entry (as before -- a confirmed twin is never flagged
    # regardless of group size), AND (2) the group of same-named,
    # not-a-confirmed-twin entries is small (`kb.duplicate_name_max_group_size`,
    # default 3) -- a big residual group is overwhelmingly a shared-name
    # family the hash normalization just doesn't happen to catch, not N
    # independent naming mistakes. Re-validated against 3b8e, 1bb0d16, and
    # f08dbe82 after adding this second gate.
    max_group_size = int(config.get("kb", {}).get("duplicate_name_max_group_size", 3))
    by_name: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        n = (r.get("new_name") or "").strip()
        if n:
            by_name[n].append(r)

    flagged = []
    for entry in rows:
        addr_int = _parse_addr(str(entry["address"]))
        if addr_int is None:
            continue
        callee_entries = kb.get_callee_summaries(graph.callees_of(addr_int))
        problem = _detect_conflict(entry, callee_entries)

        if not problem:
            name = (entry.get("new_name") or "").strip()
            same_name = by_name.get(name, [])
            others_with_same_name = [
                o for o in same_name
                if o["address"] != entry["address"] and not (
                    entry.get("body_hash") and o.get("body_hash")
                    and entry["body_hash"] == o["body_hash"]
                )
            ]
            if 0 < len(others_with_same_name) <= max_group_size:
                problem = _detect_duplicate_name(entry, others_with_same_name)

        if not problem and extractor is not None:
            node = graph.nodes.get(addr_int)
            if node is not None and node.caller_count > 0:
                caller_entries_for_check = kb.get_callers_in_kb(
                    str(entry["address"]), graph.callers_of(addr_int))
                if _is_return_value_blind(entry, extractor, addr_int, caller_entries_for_check, config=config):
                    problem = (
                        "this function's return value is compared (==/!=) "
                        "by at least one real caller, but the summary/reason "
                        "only describe side effects on state -- never what's "
                        "actually returned or why callers check it. The real "
                        "call-site evidence below is what to reason from, not "
                        "the body's side effects"
                    )

        if problem:
            flagged.append((entry, addr_int, callee_entries, problem))

    if not flagged:
        print(f"[refiner] Round {round_num}: no naming conflicts detected.")
        return 0

    print(f"[refiner] Round {round_num}: {len(flagged)} naming conflict(s) "
          f"detected — repairing…")
    fixed = 0
    for entry, addr_int, callee_entries, problem in flagged:
        addr_str = str(entry["address"])
        tried = seen_names.setdefault(addr_str, set())
        tried.add(entry.get("new_name") or "")
        caller_entries = kb.get_callers_in_kb(addr_str, graph.callers_of(addr_int))
        base_prompt = _build_prompt(entry, caller_entries, callee_entries,
                                    extractor, addr_int, graph.nodes.get(addr_int),
                                    config=config, kb=kb)
        prompt = base_prompt.rsplit("\n\n", 1)[0] + (
            f"\n\nDetected problem: {problem}.\n\nFix it now — respond with JSON only."
        )

        try:
            raw, _, _ = llm.analyze_sized(_REPAIR_SYSTEM_PROMPT, prompt)
        except LLMError as e:
            print(f"[refiner] repair LLM error for {addr_str}: {e}")
            continue

        if llm_log is not None:
            llm_log.record(
                address=addr_str, old_name=entry.get("old_name", ""),
                phase="repair", model=config["ollama"]["model"],
                raw_response=raw if isinstance(raw, dict) else {"raw": raw},
                validation={"problem": problem},
            )

        if not isinstance(raw, dict):
            print(f"[refiner] repair for {addr_str} returned no usable JSON — skipped.")
            continue

        new_name, summary, confidence, sec_rel, behaviors = \
            _merge_refinement_fields(raw, entry)
        if not _response_changed(raw, entry.get("new_name") or ""):
            print(f"[refiner] {addr_str}: reviewed, no change needed "
                  f"({problem[:70]}...)")
            continue

        if new_name in tried:
            # Either a genuine 2-cycle (this exact name was already tried
            # and reverted earlier in this call) or the flag-vs-name lie
            # documented on `seen_names` above (proposed name == current
            # name, `tried` already contains it from the line above). Either
            # way, writing it again cannot converge -- stop for this address
            # rather than spending the remaining rounds flipping it back and
            # forth.
            print(f"[refiner] {addr_str}: repair proposed {new_name!r}, "
                  f"already tried this call ({sorted(tried)}) -- stopping "
                  f"repair for this entry to avoid ping-ponging; keeping "
                  f"{entry.get('new_name')!r}.")
            continue

        if raw.get("no_change"):
            print(f"[refiner] {addr_str}: model said no_change but proposed "
                  f"a different name ({entry.get('new_name')!r} -> "
                  f"{new_name!r}) -- writing the proposed name, not the flag.")

        tried.add(new_name)
        kb.update_after_refinement(addr_str, new_name, summary, confidence, sec_rel, behaviors)
        fixed += 1
        print(f"[refiner] repaired {addr_str}: {entry.get('new_name')!r} -> {new_name!r}")

    print(f"[refiner] Round {round_num} done — {fixed}/{len(flagged)} entries fixed.")
    return fixed


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_prompt(entry: dict, caller_entries: list[dict],
                  callee_entries: list[dict],
                  extractor=None, addr_int: int | None = None,
                  graph_node=None, config: dict | None = None,
                  kb: KnowledgeBase | None = None) -> str:
    analysis_cfg = (config or {}).get("analysis", {})
    snippet_line_limit = int(analysis_cfg.get("max_call_site_snippet_lines", 20))

    base_name = entry.get("new_name") or entry.get("old_name") or "?"

    # For trivial-bodied entries, a caller's one-sentence summary
    # ("Reallocates an internal buffer...") routinely doesn't mention how
    # THIS function's return value is actually used at the call site (e.g.
    # compared against a computed size) -- exactly the detail that would
    # reveal it, so pull the real call-site line(s) too when available.
    #
    # Gated on the BODY being trivial, not on `base_name` starting with
    # "wrapper_" -- a name-prefix check breaks the moment a prior refine
    # pass already renamed this entry away from its wrapper_ bucket label
    # (right or wrong), permanently cutting off call-site evidence for every
    # refine pass after the first one, exactly when a wrong first guess most
    # needs a second look.
    #
    # Also fires for a return-value-blind body (see _is_return_value_blind):
    # a different failure shape -- not too small to read, but long enough to
    # look understood while the one line producing the return value is
    # outnumbered by side-effect noise. Same fix either way: real call-site
    # evidence beats a body reading that missed the signal.
    trivial = extractor is not None and addr_int is not None and _is_trivial_body(extractor, addr_int)
    return_blind = (
        not trivial and extractor is not None and addr_int is not None
        and _is_return_value_blind(entry, extractor, addr_int, caller_entries, config=config)
    )
    live_name = None
    if trivial or return_blind:
        try:
            live_name = extractor.current_name(addr_int)
        except Exception:
            live_name = None

    # `base_name` (the KB's pre-uniquification proposal, e.g. "wrapper_x")
    # is what the model was told about at analyze time, but the database may
    # have appended a disambiguation suffix (e.g. "wrapper_x_8") because
    # other functions proposed the same base name -- and a caller's call
    # site necessarily references THAT live name, not the base one. Showing
    # the model a header name that doesn't match what it will see quoted
    # back in a call site is exactly what caused it to mistake references to
    # itself for a separate function it "delegates to". Show the live name
    # as the identity, and call out the mismatch explicitly when there is one.
    display_name = live_name or base_name
    lines = [f"Function : {display_name}"]
    if live_name and live_name != base_name:
        lines.append(
            f"           (proposed base name was '{base_name}'; the database "
            f"appended a disambiguating suffix because other, unrelated "
            f"functions proposed the same base name. '{display_name}' below "
            f"-- including anywhere it appears inside a caller's call site "
            f"-- always refers to THIS SAME function, never a different one.)"
        )
    lines += [
        f"Address  : {entry['address']}",
        f"Summary  : {entry.get('summary') or '(none)'}",
        f"Confidence: {entry.get('confidence', 0):.2f}",
    ]

    # The same deterministic security signals the analyze prompt carries, so a
    # refine pass re-emitting security_relevant weighs them instead of losing
    # them. Only the two that bear on the security judgement -- caller_count is
    # omitted here because this whole prompt IS the caller context.
    if graph_node is not None:
        sinks = list(dict.fromkeys(getattr(graph_node, "dangerous_sink_calls", []) or []))
        if sinks:
            lines.append("Calls memory/allocation primitive(s): " + ", ".join(sinks))
        if getattr(graph_node, "input_reachable", False):
            lines.append("Reachable from an external input source via the call graph.")

    # Same structural-family signal the initial analyze prompt carries (see
    # family.py, prompts._render_family_signal) -- added 2026-08-19. Before
    # this, refine/repair calls never saw it at all: this function builds its
    # own prompt independently of prompts.build_user_prompt, so wiring the
    # signal into one didn't reach the other. Repair is exactly where a
    # missing family signal costs the most -- `_detect_duplicate_name`
    # forces a corrective call precisely when two entries share a name, and
    # without this the model doing the correcting has no more family
    # awareness than the original analyze pass that caused the collision.
    if kb is not None:
        body_hash = entry.get("body_hash")
        family_members = kb.get_family_members(body_hash, exclude_address=str(entry["address"]))
        family_size = kb.count_family_members(body_hash, exclude_address=str(entry["address"]))
        lines.extend(family.render_family_lines(family_members, family_size))

    lines += [
        "",
        "Callers of this function (already analyzed):",
        "(A caller's summary below is that ENTIRE caller's overall purpose --"
        " background only, not evidence about THIS function. Where a call "
        "site is shown, it is the ONLY reliable evidence -- reason from that "
        "literal line alone, not from the caller's summary or domain "
        "vocabulary. Any arithmetic/expression inside the call's own "
        "parentheses, e.g. `foo(x + 1)`, is computed by the CALLER before "
        "invoking this function -- it is not this function's own behavior.)",
    ]

    snippets_shown = 0
    max_snippets = 3  # bounded on purpose -- real pseudocode lines, not a one-line summary
    for caller in caller_entries:  # every real caller, not capped -- see prompts._render_kb_neighbours
        cname = caller.get("new_name") or caller.get("old_name") or "?"
        csummary = caller.get("summary") or "(no summary)"
        cconf = float(caller.get("confidence") or 0.0)
        lines.append(f"  {cname} (conf={cconf:.2f}): {csummary}")

        if live_name and extractor is not None and snippets_shown < max_snippets:
            caller_ea = _parse_addr(str(caller.get("address", "")))
            if caller_ea is not None:
                try:
                    snippet = extractor.call_site_snippet(
                        caller_ea, live_name, max_lines=snippet_line_limit)
                except Exception:
                    snippet = ""
                if snippet:
                    lines.append(
                        f"    Call site in {cname} (refers to THIS SAME "
                        f"function, {display_name}):"
                    )
                    for ln in snippet.splitlines():
                        lines.append(f"      {ln}")
                    snippets_shown += 1

    if callee_entries:
        lines += ["", "This function's own callee(s) (what it actually calls):"]
        for callee in callee_entries:
            cname = callee.get("new_name") or callee.get("old_name") or "?"
            csummary = callee.get("summary") or "(no summary)"
            lines.append(f"  {cname}: {csummary}")
        lines += [
            "  If this function's own body just forwards to one of the "
            "callees above, the real implementation and its name belong to "
            "that callee, not this function. Never propose a name identical "
            "to a callee's, and never describe logic that actually happens "
            "inside the callee as if it were this function's own.",
        ]

    if live_name:
        bookkeeping_names = "', '".join(dict.fromkeys([display_name, base_name]))
        why = (
            "This function's own body is too trivial to reveal its real "
            "purpose on its own (a bare return of a constant or another "
            "value)."
            if trivial else
            "This function's own body is long enough to look understood, but "
            "its return value -- what every caller actually consumes -- is "
            "outnumbered by side-effect noise and was missed on the first "
            "read."
        )
        lines += [
            "",
            f"{why} Do not propose a name that just repeats "
            f"'{bookkeeping_names}' back unchanged -- those are database "
            f"bookkeeping names (a generic structural guess plus whatever "
            f"suffix landed on this address), not evidence of what the "
            f"function actually does.",
        ]

    lines += [
        "",
        "Given this caller context, has your understanding of this function "
        "materially changed? Respond with JSON only.",
    ]
    return "\n".join(lines)


def _merge_refinement_fields(raw: dict, entry: dict) -> tuple[str | None, str, float, bool, list[str]]:
    """Merge a refine/repair LLM response with the KB entry it's revising --
    a field only overrides the entry's existing value when the model actually
    returned something for it. Both `Refiner.run()` and
    `repair_naming_conflicts()` feed this straight into
    `KnowledgeBase.update_after_refinement`; previously each duplicated the
    exact same five-field merge inline."""
    new_name = str(raw.get("suggested_name") or "").strip() or entry.get("new_name")
    summary = str(raw.get("summary") or "").strip() or entry.get("summary") or ""
    # `raw.get("confidence") or ...` was falsy-based, not presence-based --
    # a genuine `confidence: 0.0` from the model (a real, if extreme, value)
    # was silently treated as absent and replaced by the OLD entry's
    # confidence instead. `.get(key) is not None` (matching security_relevant
    # below, which already got this right) fixes it. Confirmed real gap
    # 2026-08-16.
    raw_confidence = raw.get("confidence")
    confidence = float(raw_confidence) if raw_confidence is not None \
        else float(entry.get("confidence") or 0.0)
    sec_rel = bool(raw.get("security_relevant", entry.get("security_relevant", False)))
    behaviors = list(entry.get("interesting_behaviors") or [])
    return new_name, summary, confidence, sec_rel, behaviors


def _response_changed(raw: dict, current_name: str) -> bool:
    """
    Whether a refine/repair LLM response should be treated as a real change,
    trusting the concrete `suggested_name` over the model's own `changed` /
    `no_change` boolean when the two disagree.

    Confirmed 2026-08-01, repeatedly, in both the normal refine path and the
    repair path: gemma4:26b sometimes reasons correctly toward a genuinely
    different name while mislabeling the flag (`changed: false` -- or
    `no_change: true` in the repair prompt's schema -- right alongside a
    `suggested_name` that is NOT the current name). A boolean that
    contradicts the concrete value sitting next to it is not trustworthy;
    the concrete value is the real signal. This only ever recovers a
    real change the flag tried to hide -- if the flag says changed and the
    name matches, this still reports True (a summary-only improvement is
    still a real change even when the name itself doesn't move).

    `raw.get("no_change") is False` (an explicit, present `false` -- not
    just falsy/absent) is checked alongside `changed`, not instead of it:
    the two schemas use different, differently-named fields (`refine.md`'s
    `changed` vs `repair.md`'s inverted `no_change`), and this function is
    shared by both callers. Confirmed real gap 2026-08-16: every repair-path
    call has `raw.get("changed")` as None (that key doesn't exist in that
    schema), so this function only ever fell back to the name-diff check for
    repair -- silently discarding a summary/reason-only fix (e.g. correcting
    self-referential wording) where the model kept the same, already-correct
    name and reported `no_change: false`. The KB write was skipped, so the
    same entry got re-flagged and re-fixed (then re-discarded) every
    subsequent repair round until max_rounds, burning LLM calls on a fix
    that was already right.
    """
    if raw.get("changed") or raw.get("no_change") is False:
        return True
    new_name = str(raw.get("suggested_name") or "").strip()
    return bool(new_name) and new_name != current_name


def _parse_addr(addr_str: str) -> int | None:
    try:
        if isinstance(addr_str, str) and addr_str.startswith("0x"):
            return int(addr_str, 16)
        return int(addr_str)
    except (ValueError, TypeError):
        return None


def _is_trivial_body(extractor, addr_int: int, max_lines: int = 8) -> bool:
    """True if this function's real decompiled body is too small to carry
    its own semantic reading (a bare return/forward/constant), meaning
    caller call-site evidence -- not the body -- is the real signal."""
    try:
        pseudocode = extractor.extract({"address": addr_int}).get("pseudocode") or ""
    except Exception:
        return False
    lines = [ln.strip() for ln in pseudocode.splitlines()]
    real = [ln for ln in lines if ln and not ln.startswith("//") and ln not in ("{", "}")]
    return len(real) <= max_lines


# Real-code case that motivated this (2026-08-15): obfuscate_global_variable
# is a one-line multiplicative string hash buried under ~30 lines of dead
# XOR/rotate noise on a global -- not trivial by line count (_is_trivial_body
# says no), but the analysis text still only ever described the noise, never
# the hash return value every caller actually consumes. Different failure
# shape from a too-small body: a body long enough to look "understood," where
# the one line that produces the return value is outnumbered by junk that
# looks structurally identical to it.
def _is_return_value_blind(entry: dict, extractor, addr_int: int,
                           caller_entries: list[dict],
                           config: dict | None = None) -> bool:
    """True if this function has a non-void return value that at least one
    real caller compares with ==/!= -- the structural signature of a return
    value carrying meaningful information (a hash, a lookup result, a status
    worth distinguishing), not a passthrough pointer nobody branches on.

    Replaces an earlier keyword-text version (2026-08-15) that checked
    summary/reason for words like "return"/"hash" -- live-tested and found
    broken both ways on the same run: false NEGATIVE on the exact motivating
    case (obfuscate_global_variable's reason said "...characteristic of a
    custom rolling hash..." -- describing the junk code's shape, not the
    actual return value, but the bare keyword match couldn't tell those
    apart) and false POSITIVE at volume (317/1246 functions flagged, mostly
    memmove_copy_bytes/memset_buffer_with_char-style wrappers whose return
    value is just their own destination pointer -- technically undescribed,
    never actually meaningful). A real caller comparing the return value
    with == is the same signal a human reviewer would look for, and it
    naturally excludes passthrough-pointer wrappers, since nothing ever
    compares those.

    Costs decompiling up to 5 real callers -- Hex-Rays caches per-ea within
    a session, so this is cache-hit-cheap the second time `_build_prompt`
    asks for the same snippets moments later.
    """
    try:
        ctx = extractor.extract({"address": addr_int})
    except Exception:
        return False
    prototype = (ctx.get("prototype") or "").strip()
    if not prototype or prototype.lower().startswith("void "):
        return False

    try:
        live_name = extractor.current_name(addr_int)
    except Exception:
        return False
    if not live_name:
        return False

    # Same config key _build_prompt uses for its own call_site_snippet call
    # -- kept in sync here too. Confirmed real gap 2026-08-16: this call
    # used the extractor's hardcoded default instead, so raising
    # max_call_site_snippet_lines in config silently wouldn't affect this
    # detector's evidence-gathering even though it does affect the actual
    # prompt rendering moments later.
    snippet_line_limit = int((config or {}).get("analysis", {}).get("max_call_site_snippet_lines", 20))
    for caller in caller_entries[:5]:
        caller_ea = _parse_addr(str(caller.get("address", "")))
        if caller_ea is None:
            continue
        try:
            snippet = extractor.call_site_snippet(caller_ea, live_name, max_lines=snippet_line_limit)
        except Exception:
            continue
        for line in snippet.splitlines():
            if live_name in line and ("==" in line or "!=" in line):
                return True
    return False
