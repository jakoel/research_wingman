"""
Regression tests for llm_renamer/refiner.py.

Locks in a real bug found live on 2026-08-19 during a genuine Ollama network
outage mid-run: `Refiner.run()` called `kb.mark_refined()` in its
`except LLMError` branch, identical to the other (structural, rerun-proof)
skip branches in the same loop. That's wrong for a *transient* failure --
it silently and permanently dropped 57 real functions from every future
refine pass, discovered only by manually diffing the run log for "LLM error"
lines and hand-resetting `phase4_refined=0` for the affected addresses. The
fix removes that call from the error branch only; every other skip branch
(unparseable address, no analyzed caller yet, no change) still marks refined,
since those are facts a rerun can't change.

Run with:  python -m unittest discover -s tests -v
"""

from __future__ import annotations

import unittest

from llm_renamer import refiner
from llm_renamer.kb import STATUS_APPROVED
from llm_renamer.llm_client import LLMError


class _FakeKB:
    def __init__(self, entries):
        self.entries = entries
        self.mark_refined_calls: list[str] = []

    def get_unrefined(self, skip_confidence):
        return [e for e in self.entries if e.get("_refined_flag", 0) == 0]

    def get_callers_in_kb(self, addr, callers):
        return [{"address": "0xCALLER", "new_name": "caller_fn",
                  "summary": "s", "confidence": 0.9}]

    def get_callee_summaries(self, addrs):
        return []

    def get_family_members(self, body_hash, exclude_address, limit=6):
        return []

    def count_family_members(self, body_hash, exclude_address):
        return 0

    def mark_refined(self, addr):
        self.mark_refined_calls.append(addr)
        for e in self.entries:
            if e["address"] == addr:
                e["_refined_flag"] = 1

    def update_after_refinement(self, *args, **kwargs):
        raise AssertionError("should never write a result for a failed call")


class _FakeGraph:
    nodes: dict = {}

    def callees_of(self, addr_int):
        return []

    def callers_of(self, addr_int):
        return [0xCAFE]


class _FailingLLM:
    def analyze_sized(self, system, prompt):
        raise LLMError("simulated network error")


class TestRefinerLLMErrorNotMarkedRefined(unittest.TestCase):
    def test_transient_llm_error_leaves_function_eligible_for_retry(self):
        entry = {
            "address": "0xDEAD", "old_name": "sub_DEAD", "new_name": "sub_DEAD",
            "status": STATUS_APPROVED, "confidence": 0.5, "summary": "s",
            "security_relevant": False, "interesting_behaviors": [],
            "_refined_flag": 0,
        }
        kb = _FakeKB([entry])
        r = refiner.Refiner(_FakeGraph(), kb, _FailingLLM(),
                             {"kb": {}, "ollama": {"model": "test"}})

        updated = r.run()

        self.assertEqual(updated, 0)
        self.assertEqual(kb.mark_refined_calls, [])
        self.assertEqual(entry["_refined_flag"], 0)


class _FakeRepairKB:
    """Minimal KB double for repair_naming_conflicts()/_repair_round()."""

    def __init__(self, entries):
        self.entries = entries
        self.updated_addresses: list[str] = []

    def get_all_analyzed(self):
        return self.entries

    def get_callee_summaries(self, addrs):
        return []

    def get_callers_in_kb(self, addr, callers):
        return []

    def get_family_members(self, body_hash, exclude_address, limit=6):
        return []

    def count_family_members(self, body_hash, exclude_address):
        return 0

    def update_after_refinement(self, addr_str, new_name, summary, confidence,
                                 sec_rel, behaviors):
        self.updated_addresses.append(addr_str)
        for e in self.entries:
            if e["address"] == addr_str:
                e["new_name"] = new_name


class _RenamingLLM:
    """Always proposes a fresh, non-colliding name -- used to confirm the
    repair pass actually fires for the entry it's supposed to."""

    def __init__(self):
        self.calls: list[str] = []

    def analyze_sized(self, system, prompt):
        self.calls.append(prompt)
        return {"suggested_name": "resolved_unique_name", "no_change": False,
                "summary": "s"}, 0, 0


class TestDuplicateNameGatedOnBodyHash(unittest.TestCase):
    """Locks in the 2026-08-19 re-enable of `_detect_duplicate_name`. Two
    gates, both required to flag:

    1. body_hash mismatch -- a collision between two entries that share a
       body_hash (confirmed structural twins, e.g. two members of a
       syscall-dispatch family) must never be flagged.
    2. small residual group size (`kb.duplicate_name_max_group_size`,
       default 3) -- body_hash ALONE was live-validated against the real
       1246-function sample the original 881-flag storm came from and did
       NOT fix it (still flagged 849): that sample's biggest collision
       groups (up to 114 members) are thematically-similar functions the
       model gave a shared name to, each with a genuinely DIFFERENT
       body_hash -- structurally distinct, just conceptually alike, which
       body_hash was never meant to catch. The real bug shape this check
       exists for is small (the motivating case, `identity_callback`, was a
       PAIR), so a big residual group is treated as a legitimate shared-name
       family, not N independent mistakes."""

    def _entry(self, addr, name, body_hash):
        return {
            "address": addr, "old_name": f"sub_{addr}", "new_name": name,
            "status": STATUS_APPROVED, "confidence": 0.9, "summary": "s",
            "security_relevant": False, "risk": "low", "reason": "",
            "interesting_behaviors": [], "body_hash": body_hash,
        }

    def test_shared_body_hash_is_not_flagged_as_a_duplicate(self):
        twin_a = self._entry("0xAAAA", "dup_name", "HASH1")
        twin_b = self._entry("0xBBBB", "dup_name", "HASH1")
        kb = _FakeRepairKB([twin_a, twin_b])
        llm = _RenamingLLM()

        fixed = refiner.repair_naming_conflicts(
            _FakeGraph(), kb, llm, {"kb": {}, "ollama": {"model": "test"}}
        )

        self.assertEqual(fixed, 0)
        self.assertEqual(llm.calls, [])
        self.assertEqual(kb.updated_addresses, [])

    def test_no_shared_body_hash_is_flagged_and_repaired(self):
        twin_a = self._entry("0xAAAA", "dup_name", "HASH1")
        different = self._entry("0xCCCC", "dup_name", "HASH2")
        kb = _FakeRepairKB([twin_a, different])
        llm = _RenamingLLM()

        fixed = refiner.repair_naming_conflicts(
            _FakeGraph(), kb, llm, {"kb": {}, "ollama": {"model": "test"}}
        )

        # Both entries collide with each other and neither shares the
        # other's body_hash, so both get flagged and repaired in round 1;
        # round 2 then finds nothing left to fix (their new names differ).
        self.assertEqual(fixed, 2)
        self.assertEqual(sorted(kb.updated_addresses), ["0xAAAA", "0xCCCC"])

    def test_missing_body_hash_on_either_side_is_still_flagged(self):
        # Unknown is not the same as confirmed-same -- a row with no
        # body_hash yet (too trivial to hash, or predates the column) must
        # not silently escape the check that predates body_hash entirely.
        no_hash = self._entry("0xAAAA", "dup_name", None)
        has_hash = self._entry("0xBBBB", "dup_name", "HASH1")
        kb = _FakeRepairKB([no_hash, has_hash])
        llm = _RenamingLLM()

        fixed = refiner.repair_naming_conflicts(
            _FakeGraph(), kb, llm, {"kb": {}, "ollama": {"model": "test"}}
        )

        self.assertEqual(fixed, 2)

    def test_large_residual_group_is_not_flagged_even_without_shared_hashes(self):
        # The real live finding on 3b8e (2026-08-19): a 62-member collision
        # group where every single member has a DIFFERENT body_hash --
        # thematically-similar functions sharing one model-chosen name, not
        # structural twins. body_hash alone does nothing here (nothing
        # matches), so this is the case the group-size cap exists for.
        members = [self._entry(f"0x{i:04X}", "shared_theme_name", f"HASH{i}")
                   for i in range(5)]
        kb = _FakeRepairKB(members)
        llm = _RenamingLLM()

        fixed = refiner.repair_naming_conflicts(
            _FakeGraph(), kb, llm, {"kb": {}, "ollama": {"model": "test"}}
        )

        self.assertEqual(fixed, 0)
        self.assertEqual(llm.calls, [])

    def test_group_size_cap_is_configurable(self):
        members = [self._entry(f"0x{i:04X}", "shared_theme_name", f"HASH{i}")
                   for i in range(5)]
        kb = _FakeRepairKB(members)
        llm = _RenamingLLM()

        fixed = refiner.repair_naming_conflicts(
            _FakeGraph(), kb, llm,
            {"kb": {"duplicate_name_max_group_size": 10}, "ollama": {"model": "test"}}
        )

        self.assertEqual(fixed, 5)


if __name__ == "__main__":
    unittest.main()
