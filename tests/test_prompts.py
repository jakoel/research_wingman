"""
Regression tests for llm_renamer/prompts.py's graph-signal rendering.

Covers the parameter-to-sink taint line added 2026-08-11 (see
idapro_client.FunctionContextExtractor.sink_argument_taint) -- real ctree-
traced dataflow, not just "this function calls a dangerous sink somewhere."
prompts.py itself needs no IDA import (pure string formatting from a dict),
so this is fully unit-testable.

Run with:  python -m unittest discover -s tests -v
"""

from __future__ import annotations

import unittest

from llm_renamer.prompts import _render_graph_signals


class TestTaintSignalRendering(unittest.TestCase):
    def test_tainted_sink_call_renders_a_specific_argument_claim(self):
        parts: list[str] = []
        ctx = {
            "dangerous_sink_calls": ["ProbeForWrite"],
            "tainted_sink_calls": [{"sink": "ProbeForWrite", "tainted_args": [1, 2]}],
        }
        _render_graph_signals(parts, ctx)
        text = "\n".join(parts)
        self.assertIn("ProbeForWrite", text)
        self.assertIn("#1, #2", text)
        self.assertIn("own input parameter", text)

    def test_untainted_sink_call_only_gets_the_generic_line(self):
        parts: list[str] = []
        ctx = {"dangerous_sink_calls": ["memcpy"], "tainted_sink_calls": []}
        _render_graph_signals(parts, ctx)
        text = "\n".join(parts)
        self.assertIn("Calls memory/allocation primitive(s): memcpy", text)
        self.assertNotIn("own input parameter", text)

    def test_finding_with_no_tainted_args_is_skipped_not_rendered_empty(self):
        # Defensive: a malformed/empty tainted_args list must not produce a
        # blank or malformed line.
        parts: list[str] = []
        ctx = {
            "dangerous_sink_calls": ["memcpy"],
            "tainted_sink_calls": [{"sink": "memcpy", "tainted_args": []}],
        }
        _render_graph_signals(parts, ctx)
        text = "\n".join(parts)
        self.assertNotIn("own input parameter", text)

    def test_absent_tainted_sink_calls_key_does_not_crash(self):
        # Callers without the new field (e.g. functions that never had a
        # sink call, so pipeline.py never sets the key at all) must still work.
        parts: list[str] = []
        ctx = {"dangerous_sink_calls": []}
        _render_graph_signals(parts, ctx)  # should not raise
        self.assertEqual(parts, [])

    def test_single_tainted_arg_uses_singular_wording(self):
        parts: list[str] = []
        ctx = {
            "dangerous_sink_calls": ["memcpy"],
            "tainted_sink_calls": [{"sink": "memcpy", "tainted_args": [2]}],
        }
        _render_graph_signals(parts, ctx)
        text = "\n".join(parts)
        self.assertIn("argument #2", text)
        self.assertNotIn("arguments #2", text)


if __name__ == "__main__":
    unittest.main()
