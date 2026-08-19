"""
Regression tests for llm_renamer/family.py.

Real motivation (2026-08): a ~40-function syscall-dispatch cluster on a real
malware sample, bodies identical except for one embedded syscall number,
caused a 126-conflict naming-collision repair storm that never converged --
nothing ever told the model it wasn't looking at something unique. These
tests lock in the two things that matter most for that fix to actually work:
literals that make bodies "the same family" (numbers, auto-generated
addresses) get normalized away, while literals that make bodies genuinely
DIFFERENT (string/char contents, real callee names) do not -- getting this
backwards would make the tool wrongly merge functions that embed different
hardcoded values (a C2 IP, a port), exactly the case this feature targets.

Run with:  python -m unittest discover -s tests -v
"""

from __future__ import annotations

import os
import tempfile
import unittest

from llm_renamer.family import (
    MIN_REAL_LINES,
    body_hash,
    is_hashable,
    normalize_pseudocode,
)
from llm_renamer.kb import KnowledgeBase, STATUS_APPROVED


def _hash(text: str) -> str:
    return body_hash(normalize_pseudocode(text))


# A body with >= MIN_REAL_LINES of real content, shaped like a real
# syscall-dispatch thunk -- padded so every synthetic body below clears the
# is_hashable gate on its own real lines, not by coincidence.
_DISPATCH_TEMPLATE = """\
__int64 __fastcall sub_{addr}(__int64 a1, __int64 a2)
{{
  __int64 result; // rax
  int v3; // [rsp+10h] [rbp-8h]

  v3 = {syscall_num};
  if ( a1 == {check_val} )
  {{
    result = linux_syscall(v3, a2, 0, 0);
  }}
  else
  {{
    result = -1;
  }}
  return result;
}}
"""


class TestNormalizeAndHash(unittest.TestCase):
    def test_bodies_identical_except_hex_and_decimal_literals_hash_equal(self):
        a = _DISPATCH_TEMPLATE.format(addr="19258", syscall_num="0x3F", check_val="4")
        b = _DISPATCH_TEMPLATE.format(addr="1929C", syscall_num="230", check_val="7")
        self.assertEqual(_hash(a), _hash(b))

    def test_genuinely_different_shaped_bodies_hash_differently(self):
        a = _DISPATCH_TEMPLATE.format(addr="19258", syscall_num="0x3F", check_val="4")
        b = """\
__int64 __fastcall sub_2223C(__int64 a1)
{
  void *v2; // rax
  int i; // [rsp+8h] [rbp-4h]

  v2 = mmap(0, 4096, 7, 34, -1, 0);
  for ( i = 0; i < 10; ++i )
  {
    memcpy((char *)v2 + i, &a1, 1);
  }
  mprotect(v2, 4096, 5);
  return (__int64)v2;
}
"""
        self.assertNotEqual(_hash(a), _hash(b))

    def test_real_callee_name_difference_is_not_collapsed(self):
        # Same shape, but each forwards to a DIFFERENT already-meaningful
        # callee -- these are genuinely different thunks (each one's real
        # distinguishing feature IS which target it forwards to), so
        # normalization must NOT treat them as the same family.
        template = """\
__int64 __fastcall sub_{addr}(__int64 a1)
{{
  __int64 result; // rax
  int v2; // [rsp+4h] [rbp-4h]

  v2 = {n};
  if ( v2 > 0 )
  {{
    result = {callee}(a1);
  }}
  else
  {{
    result = 0;
  }}
  return result;
}}
"""
        a = template.format(addr="1000", n="1", callee="parse_header")
        b = template.format(addr="2000", n="2", callee="parse_footer")
        self.assertNotEqual(_hash(a), _hash(b))

    def test_string_literal_difference_is_not_collapsed(self):
        # The false-merge risk this module is specifically built to avoid:
        # two functions embedding different hardcoded values (a C2 IP here)
        # must never normalize to the same hash just because the digits
        # inside the string also look numeric.
        template = """\
__int64 __fastcall sub_{addr}(__int64 a1)
{{
  __int64 result; // rax
  const char *v2; // [rsp+8h] [rbp-8h]

  v2 = "{ip}";
  result = connect_to_host(v2, {port});
  return result;
}}
"""
        a = template.format(addr="3000", ip="192.168.1.1", port="8080")
        b = template.format(addr="4000", ip="192.168.1.2", port="8080")
        self.assertNotEqual(_hash(a), _hash(b))

    def test_min_real_lines_gate_rejects_trivial_body(self):
        trivial = "__int64 __fastcall sub_1000()\n{\n  return -1;\n}\n"
        self.assertLess(
            len([ln for ln in normalize_pseudocode(trivial).splitlines() if ln.strip()]),
            MIN_REAL_LINES,
        )
        self.assertFalse(is_hashable(normalize_pseudocode(trivial)))

    def test_non_trivial_body_passes_the_gate(self):
        a = _DISPATCH_TEMPLATE.format(addr="19258", syscall_num="0x3F", check_val="4")
        self.assertTrue(is_hashable(normalize_pseudocode(a)))

    def test_wrapped_multiline_signature_is_stripped_correctly(self):
        # Hex-Rays sometimes wraps a long signature across two lines for
        # functions with many parameters -- stripping must find the real
        # opening brace, not just blindly drop line 1.
        # Same body content in both -- only the signature's line-wrapping
        # differs, so a hash mismatch here can only come from the signature
        # strip missing the real opening brace on the wrapped form.
        body = """\
{
  __int64 result; // rax
  int v6; // [rsp+4h] [rbp-4h]

  v6 = 0x10;
  if ( a1 == v6 )
    result = 1;
  else
    result = 0;
  return result;
}
"""
        wrapped = (
            "__int64 __fastcall sub_5000(__int64 a1, __int64 a2, __int64 a3,\n"
            "                             __int64 a4, __int64 a5)\n" + body
        )
        unwrapped = "__int64 __fastcall sub_6000(__int64 a1, __int64 a2)\n" + body
        self.assertEqual(_hash(wrapped), _hash(unwrapped))


class TestKnowledgeBaseFamilyQueries(unittest.TestCase):
    """get_family_members/count_family_members against a real, throwaway
    on-disk KB -- needs real SQL (the composite ORDER BY/LIMIT), so a real
    KnowledgeBase instance rather than a fake object."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".sqlite")
        os.close(fd)
        self.kb = KnowledgeBase(self.db_path)

    def tearDown(self):
        self.kb.close()
        os.remove(self.db_path)

    def _record(self, address, body_hash_, confidence=0.8, status=STATUS_APPROVED,
                new_name=None):
        self.kb.record({
            "address": address, "old_name": f"sub_{address}",
            "new_name": new_name or f"named_{address}",
            "confidence": confidence, "summary": f"summary for {address}",
            "status": status, "analyzed": True, "body_hash": body_hash_,
        })

    def test_family_members_excludes_self_and_other_hashes(self):
        self._record("0x1000", "HASHA")
        self._record("0x2000", "HASHA")
        self._record("0x3000", "HASHB")

        members = self.kb.get_family_members("HASHA", exclude_address="0x1000")

        self.assertEqual(len(members), 1)
        self.assertEqual(members[0]["address"], "0x2000")

    def test_count_family_members_is_uncapped_even_when_listing_is_capped(self):
        addrs = [f"0x{5000 + i:X}" for i in range(10)]
        for a in addrs:
            self._record(a, "HASHC")

        count = self.kb.count_family_members("HASHC", exclude_address=addrs[0])
        listed = self.kb.get_family_members("HASHC", exclude_address=addrs[0], limit=3)

        self.assertEqual(count, 9)
        self.assertEqual(len(listed), 3)

    def test_no_hash_returns_empty_and_zero(self):
        self.assertEqual(self.kb.get_family_members(None, exclude_address="0x1000"), [])
        self.assertEqual(self.kb.count_family_members(None, exclude_address="0x1000"), 0)

    def test_approved_members_ordered_before_rejected(self):
        self._record("0x1000", "HASHD")
        self._record("0x2000", "HASHD", status="rejected", confidence=0.99)
        self._record("0x3000", "HASHD", status=STATUS_APPROVED, confidence=0.5)

        members = self.kb.get_family_members("HASHD", exclude_address="0x1000")

        self.assertEqual(members[0]["address"], "0x3000")


if __name__ == "__main__":
    unittest.main()
