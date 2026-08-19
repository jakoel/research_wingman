"""
Review export.

The review file is a *view* of the knowledge base, generated on demand. It is
never read back — `research_wingman.py apply` works straight from the knowledge base — so it
cannot drift out of sync with the real state.
"""

from __future__ import annotations

import json
import time

from .kb import KnowledgeBase


def export_review(kb: KnowledgeBase, path: str) -> int:
    """Write every analyzed function to `path` as JSON. Returns the row count."""
    rows = kb.get_all()
    proposals = [
        {
            "address":           r.get("address"),
            "current_name":      r.get("old_name"),
            "suggested_name":    r.get("new_name") or "",
            "confidence":        r.get("confidence") or 0.0,
            "risk":              r.get("risk") or "",
            "reason":            r.get("reason") or "",
            "summary":           r.get("summary") or "",
            "security_relevant": bool(r.get("security_relevant")),
            "interesting_behaviors": r.get("interesting_behaviors") or [],
            "status":            r.get("status") or "",
            "rejection_reason":  r.get("rejection_reason") or "",
            "applied":           bool(r.get("applied")),
            "applied_name":      r.get("applied_name") or "",
            "num_ctx_used":      r.get("num_ctx_used"),
            "prompt_chars":      r.get("prompt_chars"),
        }
        for r in rows
        if r.get("analyzed")
    ]

    document = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "stats": kb.stats(),
        "proposals": proposals,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(document, f, indent=2, ensure_ascii=False)
    return len(proposals)
