"""
Workspace — resolves where a database's analysis state lives.

All state for a database lives in one directory next to the database itself:

    /path/to/target.i64
    /path/to/target.i64.wingman/
        knowledge_base.sqlite     analysis results — the single source of truth
        call_graph.json           cached call graph
        kb_vectors.faiss  (.map)  semantic index
        audit.jsonl               append-only log of every action taken
        llm_responses.json        every raw LLM response, verbatim
        review.json               exported on demand, never read back

State follows the binary rather than the current working directory, so running
from a different directory can never silently start from an empty knowledge
base and re-run thousands of LLM calls.
"""

from __future__ import annotations

import os

SUFFIX = ".wingman"

_LEGACY_FILENAMES = (
    "knowledge_base.sqlite",
    "call_graph.json",
    "llm_renames_checkpoint.json",
    "llm_renames_review.json",
)


class Workspace:
    """Owns every path derived from a database location."""

    def __init__(self, db_path: str, dir_override: str | None = None) -> None:
        # KNOWN RISK, not fixed here: on a case-insensitive, case-preserving
        # filesystem (default Windows/macOS), two paths differing only in
        # case (`Target.i64` vs `target.i64`) produce different `self.dir`
        # STRINGS that resolve to the SAME directory on disk -- two
        # "different" databases by this code's own string logic would
        # silently share one knowledge base. Not normalized here on purpose:
        # doing so would change the derived directory name for any EXISTING
        # differently-cased workspace already on disk, which is the exact
        # "silently start from an empty knowledge base" failure this module
        # exists to prevent, just moved to the fix itself. Safe to normalize
        # (e.g. via os.path.normcase) only alongside a real migration of any
        # existing `<path>.wingman` directories to the normalized name.
        self.db_path = os.path.abspath(db_path)
        self.dir = (
            os.path.abspath(dir_override) if dir_override
            else self.db_path + SUFFIX
        )
        os.makedirs(self.dir, exist_ok=True)

    def _p(self, name: str) -> str:
        return os.path.join(self.dir, name)

    @property
    def kb(self) -> str:
        return self._p("knowledge_base.sqlite")

    @property
    def call_graph(self) -> str:
        return self._p("call_graph.json")

    @property
    def faiss(self) -> str:
        return self._p("kb_vectors.faiss")

    @property
    def audit(self) -> str:
        return self._p("audit.jsonl")

    @property
    def llm_responses(self) -> str:
        return self._p("llm_responses.json")

    @property
    def review(self) -> str:
        return self._p("review.json")

    # ------------------------------------------------------------------

    def has_graph(self) -> bool:
        return os.path.exists(self.call_graph)

    def has_index(self) -> bool:
        return os.path.exists(self.faiss) and os.path.exists(self.faiss + ".map")

    def index_size(self) -> int:
        """Number of vectors in the on-disk index, or 0 if there is none."""
        import json
        if not self.has_index():
            return 0
        try:
            with open(self.faiss + ".map", "r", encoding="utf-8") as f:
                return len(json.load(f))
        except (OSError, ValueError):
            return 0

    def __repr__(self) -> str:
        return f"Workspace({self.dir!r})"


def warn_if_legacy_state_nearby(workspace: Workspace) -> None:
    """
    Older versions wrote state into the current working directory. If that
    state exists and this workspace is still empty, say so — silently
    re-analyzing from scratch is the expensive failure mode.
    """
    if os.path.exists(workspace.kb):
        return
    cwd = os.getcwd()
    stray = [f for f in _LEGACY_FILENAMES if os.path.exists(os.path.join(cwd, f))]
    if not stray:
        return
    print(
        f"[wingman] NOTE: found older state in the current directory "
        f"({', '.join(stray)}).\n"
        f"[wingman]       State now lives in {workspace.dir}\n"
        f"[wingman]       To reuse the old results, move those files there; "
        f"otherwise analysis starts fresh."
    )
