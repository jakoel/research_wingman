"""
Append-only JSON Lines audit logger for llm_renamer.

Usage (context manager):
    with AuditLogger(path) as log:
        log.record(...)

Every processed function produces exactly one record.
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
        suggested_name: str,
        final_name: str,
        confidence: float,
        risk: str,
        reason: str,
        applied: bool,
        rejection_reason: str = "",
        error: str = "",
    ) -> None:
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "address": address,
            "old_name": old_name,
            "suggested_name": suggested_name,
            "final_name": final_name,
            "confidence": confidence,
            "risk": risk,
            "reason": reason,
            "applied": applied,
            "rejection_reason": rejection_reason,
            "error": error,
        }
        self._write(entry)

    def record_error(self, *, address: str, name: str, error: str) -> None:
        self.record(
            address=address,
            old_name=name,
            suggested_name="",
            final_name="",
            confidence=0.0,
            risk="",
            reason="",
            applied=False,
            rejection_reason="",
            error=error,
        )

    # ------------------------------------------------------------------

    def _write(self, entry: dict) -> None:
        line = json.dumps(entry, ensure_ascii=False)
        if self._fh:
            self._fh.write(line + "\n")
        else:
            # Fallback: open/close per write (slow but safe)
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
