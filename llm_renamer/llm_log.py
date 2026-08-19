"""
Aggregated, human-readable log of every raw LLM response.

Unlike the knowledge base (which stores the *validated, sanitized* result) and
audit.jsonl (one compact line per action), this file keeps the model's actual
JSON reply verbatim, for every function, every run, across both the analyze
pass and the refinement pass. It exists so a researcher can open one file next
to the database and see exactly what the model said, without a SQLite client.

Written as a single JSON array (not JSONL) so it's directly readable/parseable
as a whole. Rewritten atomically (.tmp + os.replace) after every record, same
pattern as call_graph.py, so it is always valid JSON even if a run is killed
mid-way and always current for a viewer following along live.
"""

from __future__ import annotations

import json
import os
import time


class LLMResponseLog:
    """Context manager; appends one record per LLM call to a shared JSON file."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._records: list[dict] = self._load()

    def __enter__(self) -> "LLMResponseLog":
        return self

    def __exit__(self, *_) -> None:
        pass  # already flushed after every record

    def record(
        self,
        *,
        address: str,
        old_name: str,
        phase: str,
        model: str,
        raw_response: dict,
        validation: dict | None = None,
    ) -> None:
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "address": address,
            "old_name": old_name,
            "phase": phase,          # "analyze" | "refine"
            "model": model,
            "raw_response": raw_response,
            "validation": validation or {},
        }
        self._records.append(entry)
        self._flush()

    # ------------------------------------------------------------------

    def _load(self) -> list[dict]:
        if not os.path.exists(self._path):
            return []
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, list) else []
        except (OSError, ValueError):
            return []

    def _flush(self) -> None:
        tmp = self._path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self._records, f, indent=2, ensure_ascii=False)
        os.replace(tmp, self._path)
