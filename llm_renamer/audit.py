"""
Append-only JSON Lines audit logger for llm_renamer.

Usage (context manager):
    with AuditLogger(path) as log:
        log.record(...)

One record per action taken (an analyze decision, or an apply attempt) --
NOT a restatement of the analysis itself. Confidence/risk/reason/summary
already live in the knowledge base (current state) and llm_responses.json
(raw model output, every call, both analyze and refine phases) -- repeating
them here was pure duplication with no audit value of its own. What this
file uniquely provides is a permanent, append-only *timeline* of decisions
across every run ever done on this database (the KB only ever holds the
latest row per address), tagged with which phase produced them.
"""

import json
import time


class AuditLogger:
    def __init__(self, path: str):
        self._path = path
        self._fh = None

    def __enter__(self) -> "AuditLogger":
        self._fh = open(self._path, "a", encoding="utf-8", buffering=1)
        return self

    def __exit__(self, *_) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None

    # ------------------------------------------------------------------

    def record(
        self,
        *,
        address: str,
        old_name: str,
        phase: str,
        status: str,
        new_name: str = "",
        detail: str = "",
    ) -> None:
        """
        phase: "analyze" (an LLM proposal was accepted/rejected) or
               "apply" (a write to the .i64 was attempted).
        status: phase="analyze" -> "approved" | "rejected" | "error"
                phase="apply"   -> "applied" | "skip" | "fail" | "error"
                (the same vocabulary _apply_one() already returns, so callers
                pass its result straight through instead of re-deriving it)
        detail: short reason/rejection_reason/error text -- not the LLM's
                full-prose `reason`, which belongs to the KB/llm_responses.json.
        """
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "address": address,
            "old_name": old_name,
            "phase": phase,
            "status": status,
            "new_name": new_name,
            "detail": detail,
        }
        self._write(entry)

    def record_error(self, *, address: str, old_name: str, phase: str, error: str) -> None:
        self.record(address=address, old_name=old_name, phase=phase,
                    status="error", detail=error)

    # ------------------------------------------------------------------

    def _write(self, entry: dict) -> None:
        line = json.dumps(entry, ensure_ascii=False)
        if self._fh:
            self._fh.write(line + "\n")
        else:
            # Fallback: open/close per write (slow but safe)
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
