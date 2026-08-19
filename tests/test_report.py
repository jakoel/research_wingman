"""
Regression tests for llm_renamer/report.py.

No network calls, no Ollama, no IDA -- mocks
`llm_client.OllamaClient.generate_text_sized` the same way test_diff.py mocks
`OllamaClient.analyze`, and asserts on the constructed user prompt / filtering
logic rather than anything the model would actually say.

Run with:  python -m unittest discover -s tests -v
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

from llm_renamer import report
from llm_renamer.kb import STATUS_APPROVED, STATUS_REJECTED

_CONFIG = {
    "ollama": {
        "url": "http://localhost:11434",
        "model": "gemma4:26b",
        "embed_model": "nomic-embed-text",
        "timeout_seconds": 120,
        "temperature": 0.1,
    },
}


class _Node:
    def __init__(self, caller_count):
        self.caller_count = caller_count


class _FakeGraph:
    def __init__(self, nodes):
        self.nodes = nodes  # dict[int, _Node]


class _FakeKB:
    def __init__(self, rows):
        self._rows = rows

    def get_all_analyzed(self):
        return self._rows


def _row(addr, name, risk="low", security_relevant=False, status=STATUS_APPROVED,
         summary="s", behaviors=None):
    return {
        "address": addr, "new_name": name, "risk": risk,
        "security_relevant": security_relevant, "status": status,
        "summary": summary, "interesting_behaviors": behaviors or [],
    }


class TestCapabilityReportPromptConstruction(unittest.TestCase):
    def test_security_relevant_rows_get_full_detail_ordered_high_risk_first(self):
        rows = [
            _row("0x1000", "low_risk_fn", risk="low", security_relevant=True, summary="does low stuff"),
            _row("0x2000", "high_risk_fn", risk="high", security_relevant=True, summary="does high stuff"),
            _row("0x3000", "medium_risk_fn", risk="medium", security_relevant=True, summary="does medium stuff"),
        ]
        kb = _FakeKB(rows)
        graph = _FakeGraph({})
        captured = {}

        def fake_generate_text_sized(self, system_prompt, user_prompt, num_predict=None):
            captured["user_prompt"] = user_prompt
            return "REPORT", 8192, len(user_prompt)

        with patch("llm_renamer.llm_client.OllamaClient.generate_text_sized", fake_generate_text_sized):
            text, meta = report.generate_capability_report(_CONFIG, kb, graph)

        prompt = captured["user_prompt"]
        self.assertEqual(text, "REPORT")
        self.assertEqual(meta["function_count"], 3)
        # High-risk function's evidence must appear before medium, which
        # must appear before low -- risk-ordered, not KB row order.
        self.assertLess(prompt.index("high_risk_fn"), prompt.index("medium_risk_fn"))
        self.assertLess(prompt.index("medium_risk_fn"), prompt.index("low_risk_fn"))
        self.assertIn("does high stuff", prompt)

    def test_non_security_relevant_rows_are_names_only_no_summary_leaked(self):
        rows = [
            _row("0x1000", "interesting_fn", security_relevant=True, summary="the real evidence"),
            _row("0x2000", "boring_utility_fn", security_relevant=False, summary="should not leak into prompt"),
        ]
        kb = _FakeKB(rows)
        graph = _FakeGraph({})
        captured = {}

        def fake_generate_text_sized(self, system_prompt, user_prompt, num_predict=None):
            captured["user_prompt"] = user_prompt
            return "REPORT", 8192, len(user_prompt)

        with patch("llm_renamer.llm_client.OllamaClient.generate_text_sized", fake_generate_text_sized):
            report.generate_capability_report(_CONFIG, kb, graph)

        prompt = captured["user_prompt"]
        self.assertIn("boring_utility_fn", prompt)  # name present
        self.assertNotIn("should not leak into prompt", prompt)  # summary withheld

    def test_rejected_rows_are_excluded_entirely(self):
        rows = [
            _row("0x1000", "approved_fn", status=STATUS_APPROVED),
            _row("0x2000", "rejected_fn", status=STATUS_REJECTED),
        ]
        kb = _FakeKB(rows)
        graph = _FakeGraph({})

        def fake_generate_text_sized(self, system_prompt, user_prompt, num_predict=None):
            return user_prompt, 8192, len(user_prompt)

        with patch("llm_renamer.llm_client.OllamaClient.generate_text_sized", fake_generate_text_sized):
            text, meta = report.generate_capability_report(_CONFIG, kb, graph)

        self.assertEqual(meta["function_count"], 1)
        self.assertIn("approved_fn", text)
        self.assertNotIn("rejected_fn", text)

    def test_zero_caller_security_relevant_functions_are_entry_points(self):
        rows = [
            _row("0x1000", "entry_fn", security_relevant=True),
            _row("0x2000", "called_fn", security_relevant=True),
        ]
        kb = _FakeKB(rows)
        graph = _FakeGraph({0x1000: _Node(caller_count=0), 0x2000: _Node(caller_count=3)})
        captured = {}

        def fake_generate_text_sized(self, system_prompt, user_prompt, num_predict=None):
            captured["user_prompt"] = user_prompt
            return "REPORT", 8192, len(user_prompt)

        with patch("llm_renamer.llm_client.OllamaClient.generate_text_sized", fake_generate_text_sized):
            report.generate_capability_report(_CONFIG, kb, graph)

        entry_section = captured["user_prompt"].split("=== SECURITY-RELEVANT")[0]
        self.assertIn("entry_fn", entry_section)
        self.assertNotIn("called_fn", entry_section)


class TestDiffReportFiltering(unittest.TestCase):
    def test_no_diff_and_error_entries_are_excluded(self):
        results = [
            {"kind": "pair", "old_name": "f", "patched_name": "f",
             "meaningful_diff_found": False, "security_relevant": False, "risk": "low"},
            {"kind": "pair", "old_name": "g", "patched_name": "g", "error": "LLM error"},
        ]
        with patch("llm_renamer.llm_client.OllamaClient.generate_text_sized",
                    lambda self, s, u, num_predict=None: (u, 8192, len(u))):
            text, meta = report.generate_diff_report(_CONFIG, None, results)
        self.assertEqual(meta["entry_count"], 0)

    def test_meaningful_pair_and_new_removed_entries_are_included(self):
        results = [
            {"kind": "pair", "old_name": "changed_fn", "patched_name": "changed_fn",
             "meaningful_diff_found": True, "security_relevant": False, "risk": "medium",
             "diff_summary": "added a bounds check"},
            {"situation": "new", "patched_name": "brand_new_helper",
             "security_relevant": True, "risk": "high", "summary": "does the real fix"},
            {"kind": "pair", "old_name": "unchanged_fn", "patched_name": "unchanged_fn",
             "meaningful_diff_found": False, "security_relevant": False, "risk": "low"},
        ]
        with patch("llm_renamer.llm_client.OllamaClient.generate_text_sized",
                    lambda self, s, u, num_predict=None: (u, 8192, len(u))):
            text, meta = report.generate_diff_report(_CONFIG, None, results)
        self.assertEqual(meta["entry_count"], 2)
        self.assertIn("changed_fn", text)
        self.assertIn("brand_new_helper", text)
        self.assertNotIn("unchanged_fn", text)


if __name__ == "__main__":
    unittest.main()
