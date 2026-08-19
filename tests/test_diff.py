"""
Regression tests for llm_renamer/diff.py.

All of these lock in real bugs found and fixed live against real binaries
(ntfs.sys, http.sys, crypt32.dll) on 2026-08-11 -- see SESSION_NOTES.md.
They were originally verified as one-off `python -c` commands during that
session and never saved; this file exists so a future change can't silently
reintroduce any of them. No network calls, no Ollama, no IDA -- everything
here mocks `_call_llm` or `OllamaClient.analyze` and runs in milliseconds.

Run with:  python -m unittest discover -s tests -v
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

from llm_renamer import diff
from llm_renamer.llm_client import LLMError

_BASE_CONFIG = {
    "ollama": {
        "url": "http://localhost:11434",
        "model": "gemma4:26b",
        "embed_model": "nomic-embed-text",
        "timeout_seconds": 120,
        "temperature": 0.1,
    },
}


def _config(**diff_overrides) -> dict:
    cfg = {"ollama": dict(_BASE_CONFIG["ollama"])}
    if diff_overrides:
        cfg["diff"] = diff_overrides
    return cfg


def _diff_entry(summary="a difference", meaningful=True, security_relevant=False,
                 risk="low", explanation=""):
    return {
        "meaningful": meaningful, "summary": summary,
        "security_relevant": security_relevant, "risk": risk, "explanation": explanation,
    }


# ---------------------------------------------------------------------------
# _normalize_result: differences-list parsing, key-drift tolerance, aggregation
# ---------------------------------------------------------------------------

class TestNormalizeResult(unittest.TestCase):
    def test_single_meaningful_difference(self):
        raw = {"differences": [_diff_entry("did X", risk="medium", security_relevant=True)]}
        result = diff._normalize_result(raw)
        self.assertTrue(result["meaningful_diff_found"])
        self.assertTrue(result["security_relevant"])
        self.assertEqual(result["risk"], "medium")
        self.assertEqual(result["diff_summary"], "did X")
        self.assertEqual(len(result["differences"]), 1)

    def test_aggregation_risk_is_max_across_entries(self):
        # Real shape from the crypt32.dll CryptMsgGetParam finding: several
        # low/medium differences plus one that matters -- the aggregate risk
        # must be the highest of the bunch, not the first or last entry.
        raw = {"differences": [
            _diff_entry("cosmetic refactor", risk="low"),
            _diff_entry("adds a bounds check", risk="medium", security_relevant=True),
            _diff_entry("renames a helper", risk="low"),
        ]}
        result = diff._normalize_result(raw)
        self.assertEqual(result["risk"], "medium")
        self.assertTrue(result["security_relevant"])
        self.assertTrue(result["meaningful_diff_found"])
        self.assertIn("adds a bounds check", result["diff_summary"])

    def test_no_real_difference_single_nonmeaningful_entry(self):
        raw = {"differences": [_diff_entry("only a decompiler artifact", meaningful=False)]}
        result = diff._normalize_result(raw)
        self.assertFalse(result["meaningful_diff_found"])
        self.assertFalse(result["security_relevant"])
        self.assertEqual(result["diff_summary"], "only a decompiler artifact")

    def test_empty_differences_list_produces_safe_defaults(self):
        result = diff._normalize_result({"differences": []})
        self.assertFalse(result["meaningful_diff_found"])
        self.assertEqual(result["diff_summary"], "")
        self.assertEqual(result["risk"], "low")
        self.assertEqual(result["differences"], [])

    def test_old_flat_shape_is_salvaged_into_one_entry(self):
        # Schema drift: model reverts to the pre-2026-08-11 flat shape
        # instead of the differences list. Must not crash or silently drop it.
        raw = {
            "meaningful_diff_found": True, "diff_summary": "old-style summary",
            "security_relevant": True, "risk": "high", "explanation": "why",
        }
        result = diff._normalize_result(raw)
        self.assertTrue(result["meaningful_diff_found"])
        self.assertEqual(result["diff_summary"], "old-style summary")
        self.assertEqual(result["risk"], "high")
        self.assertEqual(len(result["differences"]), 1)

    def test_completely_empty_response_does_not_crash(self):
        result = diff._normalize_result({})
        self.assertFalse(result["meaningful_diff_found"])
        self.assertEqual(result["differences"], [])

    def test_flat_shape_with_typo_d_key_still_resolved_via_substring_match(self):
        # Real 2026-08-11 incident: model reverts to the flat shape AND
        # typos meaningful_diff_found as meaning_found. Without the
        # documented substring fallback, this silently degrades to
        # bool(diff_summary) instead of reading the model's real True/False
        # verdict -- confirmed real gap 2026-08-16, this path had no test.
        raw = {
            "meaning_found": True, "diff_summary": "bounds check removed",
            "security_relevant": True, "risk": "high", "explanation": "why",
        }
        result = diff._normalize_result(raw)
        self.assertTrue(result["meaningful_diff_found"])
        self.assertEqual(result["diff_summary"], "bounds check removed")
        self.assertEqual(len(result["differences"]), 1)

        # The substring match must read the model's real verdict, not just
        # fall back to bool(diff_summary) -- prove it by using a typo'd key
        # with an explicit False that bool(diff_summary) would get wrong.
        raw_false = {
            "meaning_found": False, "diff_summary": "cosmetic rename only",
            "security_relevant": False, "risk": "low", "explanation": "why",
        }
        result_false = diff._normalize_result(raw_false)
        self.assertFalse(result_false["meaningful_diff_found"])


# ---------------------------------------------------------------------------
# _call_llm: retry-on-truncation (added 2026-08-11 after the crypt32.dll crash)
# ---------------------------------------------------------------------------

class TestRetryOnTruncation(unittest.TestCase):
    def test_truncation_error_retries_with_bigger_bucket_and_succeeds(self):
        calls = []

        def fake_analyze(self, system_prompt, user_prompt, num_ctx=None):
            calls.append(num_ctx)
            if len(calls) == 1:
                raise LLMError("LLM response is not valid JSON: Unterminated string starting at...")
            return {"differences": [_diff_entry()]}

        with patch("llm_renamer.llm_client.OllamaClient.analyze", fake_analyze):
            raw, num_ctx, _ = diff._call_llm(_config(), "sys", "user")

        self.assertEqual(len(calls), 2)
        self.assertGreater(calls[1], calls[0])
        self.assertEqual(num_ctx, calls[1])
        self.assertIn("differences", raw)

    def test_network_error_does_not_retry(self):
        calls = []

        def fake_analyze(self, system_prompt, user_prompt, num_ctx=None):
            calls.append(num_ctx)
            raise LLMError("Network error contacting Ollama: timed out")

        with patch("llm_renamer.llm_client.OllamaClient.analyze", fake_analyze):
            with self.assertRaises(LLMError):
                diff._call_llm(_config(), "sys", "user")

        self.assertEqual(len(calls), 1)

    def test_thinking_budget_error_is_treated_as_retryable(self):
        calls = []

        def fake_analyze(self, system_prompt, user_prompt, num_ctx=None):
            calls.append(num_ctx)
            if len(calls) == 1:
                raise LLMError("Model returned only reasoning ('thinking'), no final content")
            return {"differences": [_diff_entry()]}

        with patch("llm_renamer.llm_client.OllamaClient.analyze", fake_analyze):
            diff._call_llm(_config(), "sys", "user")

        self.assertEqual(len(calls), 2)

    def test_already_at_max_bucket_does_not_waste_a_retry_call(self):
        calls = []

        def fake_analyze(self, system_prompt, user_prompt, num_ctx=None):
            calls.append(num_ctx)
            raise LLMError("LLM response is not valid JSON: Unterminated string...")

        huge_prompt = "x" * (diff._CTX_BUCKETS[-1] * 3)
        with patch("llm_renamer.llm_client.OllamaClient.analyze", fake_analyze):
            with self.assertRaises(LLMError):
                diff._call_llm(_config(), "sys", huge_prompt)

        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0], diff._CTX_BUCKETS[-1])


# ---------------------------------------------------------------------------
# compare_functions: self-consistency (agree / disagree / degrade-on-failure)
# ---------------------------------------------------------------------------

class TestSelfConsistency(unittest.TestCase):
    """All of these force self_consistency_min_prompt_chars low enough that
    the ~20-char old_code/patched_code fixtures clear the threshold."""

    def test_below_threshold_takes_only_one_sample(self):
        calls = {"n": 0}

        def fake_call_llm(config, system_prompt, user_prompt):
            calls["n"] += 1
            return {"differences": [_diff_entry()]}, 8192, 100

        with patch("llm_renamer.diff._call_llm", fake_call_llm):
            result = diff.compare_functions(_config(self_consistency_min_prompt_chars=100000),
                                              "Fn", "old", "patched")

        self.assertEqual(calls["n"], 1)
        self.assertEqual(result["self_consistency"], {"samples": 1, "checked": False})

    def test_two_samples_agree_no_synthesis_call(self):
        calls = {"n": 0}

        def fake_call_llm(config, system_prompt, user_prompt):
            calls["n"] += 1
            return {"differences": [_diff_entry("same finding", risk="medium",
                                                  security_relevant=True)]}, 32768, 25000

        with patch("llm_renamer.diff._call_llm", fake_call_llm):
            result = diff.compare_functions(_config(self_consistency_min_prompt_chars=1),
                                              "Fn", "old", "patched")

        self.assertEqual(calls["n"], 2)  # no third (synthesis) call
        self.assertEqual(result["self_consistency"],
                          {"samples": 2, "checked": True, "agreed": True})

    def test_disagreement_triggers_synthesis_and_flags_for_review(self):
        calls = {"n": 0}

        def fake_call_llm(config, system_prompt, user_prompt):
            calls["n"] += 1
            if calls["n"] == 1:
                return {"differences": [_diff_entry("low risk finding", risk="low")]}, 32768, 25000
            if calls["n"] == 2:
                return {"differences": [_diff_entry("high risk finding", risk="high",
                                                      security_relevant=True)]}, 32768, 25000
            # synthesis call
            return {
                "differences": [_diff_entry("reconciled finding", risk="high", security_relevant=True)],
                "reconciliation_note": "draft 2 was right",
            }, 32768, 25000

        with patch("llm_renamer.diff._call_llm", fake_call_llm):
            result = diff.compare_functions(_config(self_consistency_min_prompt_chars=1),
                                              "Fn", "old", "patched")

        self.assertEqual(calls["n"], 3)
        sc = result["self_consistency"]
        self.assertEqual(sc["samples"], 3)
        self.assertFalse(sc["agreed"])
        self.assertTrue(sc["flagged_for_human_review"])
        self.assertIn("draft_1", sc)
        self.assertIn("draft_2", sc)
        self.assertEqual(result["diff_summary"], "reconciled finding")
        self.assertEqual(result["reconciliation_note"], "draft 2 was right")

    def test_second_sample_failure_degrades_to_first_draft_not_a_crash(self):
        calls = {"n": 0}

        def fake_call_llm(config, system_prompt, user_prompt):
            calls["n"] += 1
            if calls["n"] == 1:
                return {"differences": [_diff_entry("good first draft")]}, 32768, 25000
            raise LLMError("LLM response is not valid JSON: truncated")

        with patch("llm_renamer.diff._call_llm", fake_call_llm):
            result = diff.compare_functions(_config(self_consistency_min_prompt_chars=1),
                                              "Fn", "old", "patched")

        self.assertEqual(result["diff_summary"], "good first draft")
        self.assertIn("second_sample_failed", result["self_consistency"])

    def test_synthesis_failure_degrades_to_flagged_first_draft_not_a_crash(self):
        calls = {"n": 0}

        def fake_call_llm(config, system_prompt, user_prompt):
            calls["n"] += 1
            if calls["n"] == 1:
                return {"differences": [_diff_entry("draft one", risk="low")]}, 32768, 25000
            if calls["n"] == 2:
                return {"differences": [_diff_entry("draft two", risk="high",
                                                      security_relevant=True)]}, 32768, 25000
            raise LLMError("LLM response is not valid JSON: truncated during synthesis")

        with patch("llm_renamer.diff._call_llm", fake_call_llm):
            result = diff.compare_functions(_config(self_consistency_min_prompt_chars=1),
                                              "Fn", "old", "patched")

        self.assertEqual(calls["n"], 3)
        self.assertEqual(result["diff_summary"], "draft one")  # first draft preserved, not lost
        sc = result["self_consistency"]
        self.assertTrue(sc["flagged_for_human_review"])
        self.assertIn("synthesis_failed", sc)
        self.assertIn("draft_1", sc)
        self.assertIn("draft_2", sc)


if __name__ == "__main__":
    unittest.main()
