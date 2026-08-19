"""
Old-vs-patched function comparison.

Ask the LLM to spot the concrete logic difference between two decompilations
of "the same" function taken from two versions of a binary (e.g. paired up
via BinDiff), and judge whether the difference is security-relevant.

Both full pseudocode bodies go in a single prompt -- validated 2026-08-07
against a real disclosed CLFS driver fix: the model found an added
bounds-check call unaided when given both bodies together, correctly judged
it security-relevant, and on a second, much larger pair independently
reached the same "not security-relevant" verdict a manual pseudocode diff
did. The one thing that has to be handled explicitly is context size: the
model's default num_ctx (8192) silently truncates a large pair down to just
the old half, and it will honestly report it can't compare rather than
guessing -- so `_call_llm` sizes the request to the actual prompt instead of
relying on the default (via `llm_client.OllamaClient.analyze_sized`, shared
with `pipeline.analyze` for the same reason).

Two more cases beyond the paired old-vs-patched compare, both added
2026-08-07 after a real run showed the gap: a function with NO counterpart
on the other side (`summarize_new_function`, for functions `autopair` found
present only in the patched or only in the old binary -- see
autopair.find_new_and_removed), and cross-candidate relatedness
(`format_related_note`): when two things being diffed in the same run call
each other (per autopair.compute_relatedness), each prompt gets a short
bullet per relation -- the neighbour's own already-computed summary if it's
been analyzed yet this run (new/removed functions go first, leaves-first,
via autopair.sort_leaves_first, specifically so this is usually true), else
just its name. Never the neighbour's full body -- a summary is enough
context without the prompt growing per related function. Omitted entirely
when there's nothing to say, never padded. Real motivating case: a patch
added `CClfsLogCcb::CheckReservation`/`::RecordReservation` as new helpers
called from 7 separately-changed functions; without this, each of the 7 was
diffed with zero awareness that the other 6 (and the two new helpers
themselves) were part of the same change.
"""

from __future__ import annotations

from .llm_client import LLMError, OllamaClient, _CTX_BUCKETS
from .prompts import load_prompt

SYSTEM_PROMPT = load_prompt("diff_compare.md")

_SYSTEM_PROMPT_SINGLE = {
    "new": load_prompt("diff_new_function.md"),
    "removed": load_prompt("diff_removed_function.md"),
}

# The local model has drifted from the exact "meaningful_diff_found" key at
# least twice during validation -- "meaning_diff_found" and, separately,
# "meaning_found" (the latter confirmed live on 2026-08-11 against ntfs.sys:
# it silently mistagged two real diffs as [NO DIFF] because the exact-typo
# alias below didn't cover it). Rather than chase each new misspelling one
# at a time, resolve by substring match: any key containing both "meaning"
# and "found" is the model's attempt at this field.


_RELATED_SUMMARY_MAX_CHARS = 160

_SYNTHESIS_SYSTEM_PROMPT = load_prompt("diff_synthesis.md")

_RISK_ORDER = {"low": 0, "medium": 1, "high": 2}


def _aggregate_differences(differences: list[dict]) -> dict:
    """Roll a `differences` list up into the single-verdict fields the rest
    of the pipeline (console tagging, JSON report top level) consumes:
    meaningful if ANY entry is meaningful, security_relevant if ANY entry is,
    risk is the highest risk among entries, summary/explanation are every
    entry's text joined (empty explanations dropped)."""
    if not differences:
        return {
            "meaningful_diff_found": False, "diff_summary": "",
            "security_relevant": False, "risk": "low", "explanation": "",
        }
    return {
        "meaningful_diff_found": any(d.get("meaningful") for d in differences),
        "diff_summary": "\n".join(d.get("summary", "") for d in differences if d.get("summary")),
        "security_relevant": any(d.get("security_relevant") for d in differences),
        "risk": max((d.get("risk", "low") for d in differences), key=lambda r: _RISK_ORDER.get(r, 0)),
        "explanation": "\n".join(d.get("explanation", "") for d in differences if d.get("explanation")),
    }


def _normalize_difference_entry(raw: dict) -> dict:
    entry = dict(raw)
    entry.setdefault("meaningful", True)
    entry.setdefault("summary", "")
    entry.setdefault("security_relevant", False)
    entry.setdefault("risk", "low")
    entry.setdefault("explanation", "")
    return entry


def _draft_view(result: dict) -> dict:
    return {
        "meaningful_diff_found": result["meaningful_diff_found"],
        "security_relevant": result["security_relevant"],
        "risk": result["risk"],
        "differences": result.get("differences", []),
    }


def _drafts_agree(a: dict, b: dict) -> bool:
    return (
        a["meaningful_diff_found"] == b["meaningful_diff_found"]
        and a["security_relevant"] == b["security_relevant"]
        and a["risk"] == b["risk"]
    )


def build_synthesis_prompt(name: str, old_code: str, patched_code: str, related_note: str,
                            draft1: dict, draft2: dict) -> str:
    def render_draft(label: str, draft: dict) -> str:
        lines = [f"--- Independent analysis {label} ---"]
        for d in draft["differences"]:
            lines.append(f"  * meaningful={d['meaningful']} security_relevant={d['security_relevant']} "
                         f"risk={d['risk']}: {d['summary']}")
        return "\n".join(lines)

    return f"""Function: {name}
{related_note}
=== OLD (pre-patch) ===
{old_code}

=== PATCHED (post-patch) ===
{patched_code}

{render_draft("draft 1", draft1)}

{render_draft("draft 2", draft2)}

These two drafts disagree. Re-examine the actual OLD/PATCHED code above yourself and produce your own
final, comprehensive list of differences -- don't just pick one draft on trust, and consider whether
they found genuinely different real changes that both belong in the final list.
"""


def _synthesize_disagreement(config: dict, name: str, old_code: str, patched_code: str,
                              related_note: str, draft1: dict, draft2: dict) -> dict:
    diff_cfg = config.get("diff", {})
    tiebreak_config = dict(config)
    tiebreak_config["ollama"] = dict(config["ollama"])
    if diff_cfg.get("tiebreak_model"):
        tiebreak_config["ollama"]["model"] = diff_cfg["tiebreak_model"]
    # Applied unconditionally, not just for the `None` sentinel -- the old
    # `is None` check meant an explicit `tiebreak_think: true`/`false` in
    # config never actually took effect (config.py's own default of False
    # never applied either), silently leaving the tiebreak call on whatever
    # the PRIMARY model's think setting happened to be. Confirmed real gap
    # 2026-08-16: only the `null` (gpt-oss) case ever worked.
    if "tiebreak_think" in diff_cfg:
        tiebreak_config["ollama"]["think"] = diff_cfg["tiebreak_think"]

    user_prompt = build_synthesis_prompt(name, old_code, patched_code, related_note, draft1, draft2)
    raw, num_ctx, prompt_chars = _call_llm(tiebreak_config, _SYNTHESIS_SYSTEM_PROMPT, user_prompt)
    result = _normalize_result(raw)
    result["reconciliation_note"] = raw.get("reconciliation_note", "")
    result["num_ctx_used"] = num_ctx
    result["prompt_chars"] = prompt_chars
    return result


def format_related_note(related: list[tuple[str, str, str]], config: dict | None = None) -> str:
    """One short bullet per relation, or empty. `related` is a list of
    (name, 'calls'|'called_by', summary) -- summary is the neighbour's own
    already-computed analysis summary if it's been analyzed yet in this same
    run (see autopair.sort_leaves_first), or "" if not, in which case the
    bullet just names it rather than claiming a description that doesn't
    exist. Never full pseudocode -- a summary is enough for the model to
    reason about the relationship without the prompt growing with every
    related function's full body."""
    if not related:
        return ""
    max_chars = int((config or {}).get("analysis", {})
                     .get("max_related_summary_chars", _RELATED_SUMMARY_MAX_CHARS))
    lines = []
    for name, rel, summary in related:
        verb = "Calls" if rel == "calls" else "Is called by"
        if summary:
            short = summary.strip()
            if len(short) > max_chars:
                short = short[:max_chars].rstrip() + "..."
            lines.append(f"  - {verb} {name} (also changed in this patch): {short}")
        else:
            lines.append(f"  - {verb} {name} (also changed in this patch).")
    return "Related changes in this same patch:\n" + "\n".join(lines) + "\n"


def build_user_prompt(name: str, old_code: str, patched_code: str, related_note: str = "") -> str:
    return f"""Function: {name}
{related_note}
=== OLD (pre-patch) ===
{old_code}

=== PATCHED (post-patch) ===
{patched_code}

Compare the two versions and identify the concrete logic difference, if any.
"""


def build_user_prompt_single(name: str, code: str, related_note: str = "") -> str:
    return f"""Function: {name}
{related_note}
{code}

Summarize this function and judge its security relevance.
"""


def _normalize_result(raw: dict) -> dict:
    """Parse a `differences`-list response (see SYSTEM_PROMPT) into a
    normalized `differences` list plus the aggregate single-verdict fields
    the rest of the pipeline reads (meaningful_diff_found / diff_summary /
    security_relevant / risk / explanation -- see _aggregate_differences).

    Tolerates the model falling back to the old flat single-difference shape
    (meaningful_diff_found/diff_summary/security_relevant/risk/explanation at
    the top level, no `differences` key) by wrapping it into a one-entry
    list -- schema drift from a local model has bitten this module twice
    already (see the meaningful_diff_found key-alias history), so the parser
    stays permissive about the shape actually received rather than assuming
    the prompt is always followed exactly."""
    raw_differences = raw.get("differences")
    if isinstance(raw_differences, list) and raw_differences:
        differences = [_normalize_difference_entry(d) for d in raw_differences if isinstance(d, dict)]
    else:
        # Old flat shape, or missing/empty differences -- salvage what's there.
        # If the model also typo'd the key (meaning_diff_found/meaning_found
        # are both confirmed real, 2026-08-11), meaningful_diff_found is
        # absent and this would silently fall back to bool(diff_summary),
        # which is wrong whenever diff_summary is ALSO empty/mistyped --
        # reproducing the exact silent-no-diff bug this fallback exists to
        # catch. Confirmed real gap 2026-08-16: this substring scan was
        # documented (here and in ARCHITECTURE.md §16.4) but never actually
        # implemented.
        meaningful_key = next(
            (k for k in raw if "meaning" in k.lower() and "found" in k.lower()),
            None,
        )
        meaningful = (
            raw[meaningful_key] if meaningful_key is not None
            else bool(raw.get("diff_summary"))
        )
        entry = {
            "meaningful": meaningful,
            "summary": raw.get("diff_summary", ""),
            "security_relevant": raw.get("security_relevant", False),
            "risk": raw.get("risk", "low"),
            "explanation": raw.get("explanation", ""),
        }
        differences = [_normalize_difference_entry(entry)] if entry["summary"] else []

    result = _aggregate_differences(differences)
    result["differences"] = differences
    return result


def _normalize_result_single(raw: dict) -> dict:
    result = dict(raw)
    result.setdefault("summary", "")
    result.setdefault("security_relevant", False)
    result.setdefault("risk", "low")
    result.setdefault("explanation", "")
    return result


def _call_llm(config: dict, system_prompt: str, user_prompt: str) -> tuple[dict, int, int]:
    """Call Ollama and parse the JSON response, sized to the prompt instead
    of a fixed default -- see `llm_client.OllamaClient.analyze_sized` (this
    module is where that sizing/retry logic was first built; `analyze` now
    shares the same implementation)."""
    return OllamaClient(config).analyze_sized(system_prompt, user_prompt)


def compare_functions(config: dict, name: str, old_code: str, patched_code: str,
                       related_note: str = "") -> dict:
    """Ask the LLM to compare the old and patched pseudocode of one function.

    Returns meaningful_diff_found / diff_summary / security_relevant / risk /
    explanation, plus num_ctx_used and prompt_chars for visibility into what
    was actually sent, plus a `self_consistency` block (see below).
    `related_note` (see format_related_note) tells the model about other
    functions in the same run that this one calls or is called by, if any.

    Self-consistency check: above `diff.self_consistency_min_prompt_chars`
    (default 20000), a second independent sample is taken and compared
    against the first. Real motivating case (2026-08-11): the largest,
    highest-stakes pair in a real ntfs.sys diff run got three qualitatively
    different verdicts across otherwise-identical runs -- exactly the case
    where a single sample is least trustworthy. If the two samples agree,
    the first is returned with `self_consistency: {samples: 2, agreed: true}`.
    If they disagree, a third call re-examines the actual code (optionally on
    a different, `diff.tiebreak_model`) and produces a reconciled verdict;
    the result carries `self_consistency: {..., agreed: false,
    flagged_for_human_review: true, draft_1: ..., draft_2: ...}` so the
    disagreement is visible in the JSON report even after reconciliation,
    not silently smoothed over.
    """
    user_prompt = build_user_prompt(name, old_code, patched_code, related_note)
    raw, num_ctx, prompt_chars = _call_llm(config, SYSTEM_PROMPT, user_prompt)
    result = _normalize_result(raw)
    result["num_ctx_used"] = num_ctx
    result["prompt_chars"] = prompt_chars

    threshold = config.get("diff", {}).get("self_consistency_min_prompt_chars", 20000)
    if prompt_chars < threshold:
        result["self_consistency"] = {"samples": 1, "checked": False}
        return result

    # The second sample and the synthesis call are each a full LLM round-trip
    # on a large prompt -- the same class of call that has been observed to
    # occasionally return truncated/malformed JSON (see llm_client.LLMError,
    # confirmed live 2026-08-11 on crypt32.dll). Losing the whole item because
    # a *bonus* consistency check failed, when a perfectly good first draft
    # already exists, would make self-consistency net negative for
    # reliability instead of positive -- so both are best-effort here, not
    # required for a result to come back.
    try:
        raw2, _, _ = _call_llm(config, SYSTEM_PROMPT, user_prompt)
        result2 = _normalize_result(raw2)
    except LLMError as e:
        result["self_consistency"] = {"samples": 1, "checked": False, "second_sample_failed": str(e)}
        return result

    if _drafts_agree(result, result2):
        result["self_consistency"] = {"samples": 2, "checked": True, "agreed": True}
        return result

    try:
        synth = _synthesize_disagreement(config, name, old_code, patched_code, related_note, result, result2)
    except LLMError as e:
        result["self_consistency"] = {
            "samples": 2, "checked": True, "agreed": False,
            "flagged_for_human_review": True,
            "synthesis_failed": str(e),
            "draft_1": _draft_view(result),
            "draft_2": _draft_view(result2),
        }
        return result

    synth["self_consistency"] = {
        "samples": 3, "checked": True, "agreed": False,
        "flagged_for_human_review": True,
        "draft_1": _draft_view(result),
        "draft_2": _draft_view(result2),
    }
    return synth


def summarize_new_function(config: dict, name: str, code: str, situation: str,
                            related_note: str = "") -> dict:
    """Ask the LLM about a function with no counterpart on the other side.
    `situation` is "new" (exists only in patched) or "removed" (exists only
    in old) -- see autopair.find_new_and_removed.

    Returns summary / security_relevant / risk / explanation, plus
    num_ctx_used and prompt_chars.
    """
    if situation not in _SYSTEM_PROMPT_SINGLE:
        raise ValueError(f"situation must be 'new' or 'removed', got {situation!r}")
    system_prompt = _SYSTEM_PROMPT_SINGLE[situation]
    user_prompt = build_user_prompt_single(name, code, related_note)
    raw, num_ctx, prompt_chars = _call_llm(config, system_prompt, user_prompt)
    result = _normalize_result_single(raw)
    result["situation"] = situation
    result["num_ctx_used"] = num_ctx
    result["prompt_chars"] = prompt_chars
    return result
