"""
Review file writer and reader for llm_renamer.

Review files are the human-auditable output of a review-mode run.
They can also be read back by the apply pass to avoid re-running the LLM.

Schema:
{
  "generated_at": "<ISO 8601>",
  "stats": { ... },
  "proposals": [
    {
      "address": "0x...",
      "current_name": "...",
      "suggested_name": "...",
      "confidence": 0.0,
      "risk": "low|medium|high",
      "reason": "...",
      "evidence": { "strings": [], "apis": [], "behavior": [] },
      "validation_status": "approved|rejected|skipped",
      "rejection_reason": "..."
    },
    ...
  ]
}
"""

import json
import time


class ReviewWriter:
    def __init__(self, path: str):
        self._path = path
        self.proposals: list[dict] = []
        self.stats: dict = {
            "total_processed": 0,
            "total_proposed_approved": 0,
            "total_rejected": 0,
            "total_errors": 0,
            "by_risk": {"low": 0, "medium": 0, "high": 0},
        }

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def add_approved(
        self,
        *,
        address: str,
        current_name: str,
        suggested_name: str,
        confidence: float,
        risk: str,
        reason: str,
        evidence: dict,
    ) -> None:
        self.proposals.append({
            "address": address,
            "current_name": current_name,
            "suggested_name": suggested_name,
            "confidence": confidence,
            "risk": risk,
            "reason": reason,
            "evidence": evidence,
            "validation_status": "approved",
            "rejection_reason": "",
        })
        self.stats["total_proposed_approved"] += 1
        if risk in self.stats["by_risk"]:
            self.stats["by_risk"][risk] += 1

    def add_rejected(
        self,
        *,
        address: str,
        current_name: str,
        rejection_reason: str,
        suggested_name: str = "",
        confidence: float = 0.0,
        risk: str = "",
        reason: str = "",
        evidence=None,
    ) -> None:
        self.proposals.append({
            "address": address,
            "current_name": current_name,
            "suggested_name": suggested_name,
            "confidence": confidence,
            "risk": risk,
            "reason": reason,
            "evidence": evidence or {},
            "validation_status": "rejected",
            "rejection_reason": rejection_reason,
        })
        self.stats["total_rejected"] += 1

    def increment_processed(self) -> None:
        self.stats["total_processed"] += 1

    def increment_errors(self) -> None:
        self.stats["total_errors"] += 1

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self) -> None:
        output = {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "stats": self.stats,
            "proposals": self.proposals,
        }
        with open(self._path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
        print(f"[llm_renamer] Review file saved: {self._path}")

    @staticmethod
    def load_proposals(path: str) -> list[dict]:
        """Load and return the proposals list from a review JSON file."""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("proposals", [])

    @staticmethod
    def load_stats(path: str) -> dict:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("stats", {})
