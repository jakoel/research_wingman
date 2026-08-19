"""
Regression tests for llm_renamer/call_graph.py.

Locks in a real bug found live on 2026-08-11 while verifying the new
constant-operand extraction (see autopair.classify's promotion-by-constants
feature): `idc.get_operand_value` doesn't consistently sign-extend small
negative immediates in 64-bit-mode instructions -- e.g. -1 came back as
18446744073709551615 (and -512 as 18446744073709551104) against real
clfs.sys functions. Without normalizing to
signed 64-bit first, the magnitude filter (`_CONST_MIN_ABS`) doesn't catch
these at all (abs() of a huge unsigned value is still huge), so tiny
near-universal constants would be tracked as if they were large, meaningful
ones.

Run with:  python -m unittest discover -s tests -v
"""

from __future__ import annotations

import unittest

from llm_renamer.call_graph import _to_signed64


class TestToSigned64(unittest.TestCase):
    def test_unsigned_64bit_representation_of_negative_one(self):
        self.assertEqual(_to_signed64(18446744073709551615), -1)

    def test_unsigned_64bit_representation_of_negative_512(self):
        # The exact value observed live in a real clfs.sys function
        # (?AsyncFlush@CClfsFlushElt@@...): 2**64 - 512 = 18446744073709551104.
        self.assertEqual(_to_signed64(18446744073709551104), -512)

    def test_positive_small_value_unchanged(self):
        self.assertEqual(_to_signed64(200), 200)

    def test_positive_large_32bit_value_unchanged(self):
        # Below 2**63 -- a legitimate large positive constant (e.g. a 32-bit
        # bitmask), must not be reinterpreted as negative.
        self.assertEqual(_to_signed64(2147483648), 2147483648)

    def test_zero_unchanged(self):
        self.assertEqual(_to_signed64(0), 0)

    def test_already_negative_python_int_unchanged(self):
        # Defensive: if some code path already hands us a proper signed int
        # (e.g. a smaller-width operand IDA did sign-extend correctly), the
        # mask-and-resubtract round-trip must be a no-op.
        self.assertEqual(_to_signed64(-1), -1)
        self.assertEqual(_to_signed64(-192), -192)


if __name__ == "__main__":
    unittest.main()
