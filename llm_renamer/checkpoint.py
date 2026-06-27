"""
Resumable-run checkpoint for llm_renamer.

Tracks which function addresses have already been processed so that a
run interrupted by the user (or by IDA crashing) can pick up where it
left off on the next invocation.

The checkpoint file is a simple JSON object:
    {"processed": [<int ea>, ...]}

Writes happen after every function to ensure maximum recoverability.
"""

import json
import os


class Checkpoint:
    def __init__(self, path: str):
        self._path = path
        self._done: set[int] = set()
        self._load()

    # ------------------------------------------------------------------
    # State accessors
    # ------------------------------------------------------------------

    def is_done(self, ea: int) -> bool:
        return ea in self._done

    def mark_done(self, ea: int) -> None:
        self._done.add(ea)
        self._save()

    def count(self) -> int:
        return len(self._done)

    def clear(self) -> None:
        self._done.clear()
        self._save()
        print(f"[llm_renamer] Checkpoint cleared: {self._path}")

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load(self) -> None:
        if not os.path.exists(self._path):
            return
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                data = json.load(f)
            raw = data.get("processed", [])
            # Stored as strings (JSON keys must be strings) or as ints
            self._done = {int(x) for x in raw}
        except (json.JSONDecodeError, IOError, ValueError) as e:
            print(f"[llm_renamer] Warning: could not load checkpoint ({e}). Starting fresh.")
            self._done = set()

    def _save(self) -> None:
        try:
            tmp = self._path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"processed": list(self._done)}, f)
            # Atomic replace
            os.replace(tmp, self._path)
        except IOError as e:
            print(f"[llm_renamer] Warning: could not save checkpoint: {e}")
