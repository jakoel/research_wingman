"""
Phase 4 — Top-down refinement pass.

After the bottom-up LLM pass (Phase 3) completes, one downward pass re-queries
functions whose caller context was unavailable when they were first analyzed.

Rules:
  - One pass only; no looping.
  - Skip functions with confidence >= kb.refinement_confidence_skip AND
    security_relevant=False (high-confidence, non-security results rarely
    change from caller context).
  - If the LLM says changed=False, no KB write occurs.
"""

from __future__ import annotations

from .call_graph import CallGraph
from .kb import KnowledgeBase
from .llm_client import OllamaClient, LLMError


_SYSTEM_PROMPT = """You are a reverse engineering expert.
You previously analyzed a binary function and produced a name and summary.
New information is now available: the function's callers have since been analyzed.
Re-evaluate your prior analysis given this caller context.

Respond with ONLY valid JSON — no explanation, no markdown fences:
{
  "changed": <boolean — true only if name or summary materially improves>,
  "suggested_name": "<snake_case name, or empty string if unchanged>",
  "confidence": <float 0.0–1.0>,
  "summary": "<updated one-sentence summary>",
  "security_relevant": <boolean>,
  "interesting_behaviors": ["<observation>", ...],
  "reason": "<why you changed or kept the analysis, 1–2 sentences>"
}

If nothing meaningful changes, set changed=false and repeat the original values.
"""


class Refiner:
    def __init__(
        self,
        graph: CallGraph,
        kb: KnowledgeBase,
        llm: OllamaClient,
        config: dict,
    ) -> None:
        self._graph = graph
        self._kb = kb
        self._llm = llm
        self._config = config

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

        print(f"[refiner] Refining {len(candidates)} functions…")
        updated = 0

        for entry in candidates:
            addr_str = str(entry["address"])
            addr_int = _parse_addr(addr_str)

            if addr_int is None:
                self._kb.mark_phase4_refined(addr_str)
                continue

            callers_in_graph = self._graph.callers_of(addr_int)
            caller_entries = self._kb.get_callers_in_kb(addr_str, callers_in_graph)

            if not caller_entries:
                # No caller context available; mark done with no change.
                self._kb.mark_phase4_refined(addr_str)
                continue

            prompt = _build_prompt(entry, caller_entries)
            try:
                raw = self._llm.analyze(_SYSTEM_PROMPT, prompt)
            except LLMError as e:
                print(f"[refiner] LLM error for {addr_str}: {e}")
                self._kb.mark_phase4_refined(addr_str)
                continue

            if not isinstance(raw, dict) or not raw.get("changed"):
                self._kb.mark_phase4_refined(addr_str)
                continue

            # Something improved — update the KB
            new_name = (str(raw.get("suggested_name") or "").strip()
                        or entry.get("new_name"))
            summary = (str(raw.get("summary") or "").strip()
                       or entry.get("summary") or "")
            confidence = float(
                raw.get("confidence") or entry.get("confidence") or 0.0
            )
            sec_rel = bool(
                raw.get("security_relevant", entry.get("security_relevant", False))
            )
            behaviors = list(
                raw.get("interesting_behaviors")
                or entry.get("interesting_behaviors")
                or []
            )

            self._kb.update_after_refinement(
                addr_str, new_name, summary, confidence, sec_rel, behaviors
            )
            updated += 1

        print(f"[refiner] Done — {updated}/{len(candidates)} entries updated.")
        return updated


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_prompt(entry: dict, caller_entries: list[dict]) -> str:
    name = entry.get("new_name") or entry.get("old_name") or "?"
    lines = [
        f"Function : {name}",
        f"Address  : {entry['address']}",
        f"Summary  : {entry.get('summary') or '(none)'}",
        f"Confidence: {entry.get('confidence', 0):.2f}",
        "",
        "Callers of this function (already analyzed):",
    ]
    for caller in caller_entries[:5]:
        cname = caller.get("new_name") or caller.get("old_name") or "?"
        csummary = caller.get("summary") or "(no summary)"
        cconf = float(caller.get("confidence") or 0.0)
        lines.append(f"  {cname} (conf={cconf:.2f}): {csummary}")

    lines += [
        "",
        "Given this caller context, has your understanding of this function "
        "materially changed? Respond with JSON only.",
    ]
    return "\n".join(lines)


def _parse_addr(addr_str: str) -> int | None:
    try:
        if isinstance(addr_str, str) and addr_str.startswith("0x"):
            return int(addr_str, 16)
        return int(addr_str)
    except (ValueError, TypeError):
        return None
