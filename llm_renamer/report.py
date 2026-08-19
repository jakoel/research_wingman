"""
Macro-level synthesis reports -- a single LLM call over already-completed
per-function analysis, producing a human-readable narrative instead of the
tool's usual per-function JSON. Two report kinds:

  generate_capability_report()  -- malware capability + IOC report from a
                                    completed --profile malware full analysis.
  generate_diff_report()        -- what-changed narrative from a completed
                                    `diff` run's verdicts.

Both follow the context-engineering shape validated live 2026-08-19 against
the 1bb0d16 sample (274 security-relevant functions, ~27K prompt tokens,
128s, zero hallucinated IOCs found on manual spot-check against the source
evidence): full detail for the security-relevant/meaningful subset, a
compact name-only listing for everything else (redundant bulk, not signal),
one big single-shot call rather than a per-function loop, free-form text
output via OllamaClient.generate_text_sized (not the tool's usual
JSON-constrained analyze_sized).

Neither function touches disk -- writing the output file and printing
progress is the caller's job (research_wingman.py), same separation
diff.py/autopair.py already follow.
"""

from __future__ import annotations

from .kb import STATUS_APPROVED
from .llm_client import OllamaClient
from .prompts import load_prompt

_CAPABILITY_SYSTEM_PROMPT = load_prompt("report_malware_capability.md")
_DIFF_SYSTEM_PROMPT = load_prompt("report_diff_summary.md")

_RISK_ORDER = {"high": 0, "medium": 1, "low": 2}


def _fmt_function_entry(row: dict) -> str:
    name = row.get("new_name") or row.get("old_name") or row.get("address", "?")
    risk = row.get("risk") or "?"
    summary = row.get("summary") or ""
    behaviors = row.get("interesting_behaviors") or []
    line = f"- {name} [risk={risk}]: {summary}"
    if behaviors:
        line += "\n    evidence: " + " | ".join(behaviors)
    return line


def _build_capability_user_prompt(rows: list[dict], graph) -> str:
    sec = sorted(
        (r for r in rows if r.get("security_relevant")),
        key=lambda r: _RISK_ORDER.get((r.get("risk") or "").lower(), 3),
    )
    non_sec = [r for r in rows if not r.get("security_relevant")]

    entry_points = []
    for r in sec:
        try:
            addr_int = int(r["address"], 16)
        except (ValueError, TypeError):
            continue
        node = graph.nodes.get(addr_int)
        if node is not None and node.caller_count == 0:
            entry_points.append(r)

    sec_block = "\n".join(_fmt_function_entry(r) for r in sec)
    non_sec_names = ", ".join(sorted(set(
        r.get("new_name") or r.get("old_name") or r.get("address", "?") for r in non_sec
    )))
    entry_names = ", ".join(
        r.get("new_name") or r.get("old_name") or r.get("address", "?") for r in entry_points
    )

    return (
        f"=== ENTRY POINTS ({len(entry_points)}) ===\n{entry_names}\n\n"
        f"=== SECURITY-RELEVANT FUNCTIONS ({len(sec)}) ===\n{sec_block}\n\n"
        f"=== OTHER (NON-SECURITY-RELEVANT) FUNCTIONS ({len(non_sec)}, names only) ===\n{non_sec_names}\n"
    )


def generate_capability_report(config: dict, kb, graph) -> tuple[str, dict]:
    """Synthesize a malware capability + IOC report from `kb`'s approved,
    analyzed functions and `graph`'s entry-point structure. Returns
    (markdown_text, meta) where meta has num_ctx/prompt_chars/function_count
    for the caller to print/log."""
    rows = [r for r in kb.get_all_analyzed() if r.get("status") == STATUS_APPROVED]
    user_prompt = _build_capability_user_prompt(rows, graph)
    llm = OllamaClient(config)
    text, num_ctx, prompt_chars = llm.generate_text_sized(
        _CAPABILITY_SYSTEM_PROMPT, user_prompt, num_predict=3000
    )
    return text, {"num_ctx": num_ctx, "prompt_chars": prompt_chars, "function_count": len(rows)}


def _fmt_diff_entry(entry: dict) -> str:
    if entry.get("kind") == "pair":
        old_name = entry.get("old_name", "?")
        patched_name = entry.get("patched_name", "?")
        label = old_name if old_name == patched_name else f"{old_name} / {patched_name}"
        tag = "SECURITY" if entry.get("security_relevant") else "DIFF"
        lines = [f"- [{tag} risk={entry.get('risk', '?')}] {label}"]
        if entry.get("diff_summary"):
            lines.append(f"    summary: {entry['diff_summary']}")
        for d in entry.get("differences") or []:
            d_tag = "SECURITY" if d.get("security_relevant") else "diff"
            lines.append(f"    - [{d_tag} risk={d.get('risk', '?')}] {d.get('summary', '')}")
            if d.get("explanation"):
                lines.append(f"      -> {d['explanation']}")
        return "\n".join(lines)
    else:
        situation = entry.get("situation", "?").upper()
        name = entry.get("patched_name") or entry.get("old_name") or "?"
        tag = "SECURITY" if entry.get("security_relevant") else situation
        lines = [f"- [{tag} risk={entry.get('risk', '?')}] ({situation}) {name}"]
        if entry.get("summary"):
            lines.append(f"    summary: {entry['summary']}")
        if entry.get("explanation"):
            lines.append(f"    -> {entry['explanation']}")
        return "\n".join(lines)


def _is_reportable(entry: dict) -> bool:
    """A `results` entry is worth including in the macro report if it's a
    genuinely new/removed function (a change by definition), or a compared
    pair the diff itself judged meaningful/security-relevant. [NO DIFF] pairs
    and error entries are neither -- they'd just be noise in a narrative."""
    if entry.get("error"):
        return False
    if "situation" in entry:
        return True
    return bool(entry.get("meaningful_diff_found") or entry.get("security_relevant"))


def generate_diff_report(config: dict, pairing_report: dict | None, results: list[dict]) -> tuple[str, dict]:
    """Synthesize a what-changed report from `results` (the same list
    cmd_diff already builds and writes to diff_vs_<old>.json). Returns
    (markdown_text, meta)."""
    reportable = [r for r in results if _is_reportable(r)]
    block = "\n".join(_fmt_diff_entry(e) for e in reportable)
    counts = ""
    if pairing_report is not None:
        counts = (
            f"(pairing: {pairing_report.get('paired', 0)} paired, "
            f"{len(pairing_report.get('new', []))} new, "
            f"{len(pairing_report.get('removed', []))} removed)\n\n"
        )
    user_prompt = f"{counts}=== REPORTABLE CHANGES ({len(reportable)}) ===\n{block}\n"
    llm = OllamaClient(config)
    text, num_ctx, prompt_chars = llm.generate_text_sized(
        _DIFF_SYSTEM_PROMPT, user_prompt, num_predict=2500
    )
    return text, {"num_ctx": num_ctx, "prompt_chars": prompt_chars, "entry_count": len(reportable)}
