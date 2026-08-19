"""
Regression tests for llm_renamer/autopair.py.

Locks in the noise-filter broadening found and fixed live on 2026-08-11:
`is_noise_name`'s Feature_* pattern only matched bare numeric IDs
(`Feature_927__private_...`) but every real Windows build uses descriptive
ones (`Feature_Servicing_MSRC106366__private_...`,
`Feature_NVBugFixes2507__private_...`) -- confirmed against real ntfs.sys and
http.sys diffs. Also locks in extending that same noise classification from
matched pairs (pre-existing) to new/removed functions (added the same day).

Run with:  python -m unittest discover -s tests -v
"""

from __future__ import annotations

import unittest

from llm_renamer import autopair
from llm_renamer.call_graph import CallNode


def _node(address, name, size_bytes=100, basic_block_count=5, constant_operands=None) -> CallNode:
    return CallNode(address=address, name=name, size_bytes=size_bytes,
                     basic_block_count=basic_block_count,
                     constant_operands=constant_operands or [])


class TestIsNoiseName(unittest.TestCase):
    def test_real_descriptive_feature_names_are_noise(self):
        # These are the exact three names that broke before the fix -- none
        # of them matched the old `^Feature_\d+__private_` pattern.
        real_names = [
            "Feature_NTFS_TelemetryUsageForCompat__private_IsEnabledFallback",
            "Feature_Servicing_MSRC106366__private_IsEnabledFallback",
            "Feature_Servicing_MSRC106366__private_IsEnabledDeviceUsageNoInline",
            "Feature_NVBugFixes2507__private_IsEnabledFallback",
            "Feature_NVBugFixes2507__private_IsEnabledDeviceUsageNoInline",
        ]
        for name in real_names:
            with self.subTest(name=name):
                self.assertTrue(autopair.is_noise_name(name))

    def test_bare_numeric_feature_id_still_matches(self):
        # The original, narrower pattern this replaced -- must still work.
        self.assertTrue(autopair.is_noise_name("Feature_927__private_IsEnabledFallback"))

    def test_wil_details_prefix_still_matches(self):
        self.assertTrue(autopair.is_noise_name("wil_details_RecordCachedUsage"))

    def test_msvc_thunk_marker_still_matches(self):
        self.assertTrue(autopair.is_noise_name("??_9SomeClass@@$BWCFA@EAAXXZ"))

    def test_real_function_names_are_not_noise(self):
        real_names = [
            "NtfsWriteRawEncrypted", "CryptMsgGetParam", "PktMonAttachProvider",
            "ASN1Dec_AuthEnvelopedData", "wil_InitializeFeatureStaging",
        ]
        for name in real_names:
            with self.subTest(name=name):
                self.assertFalse(autopair.is_noise_name(name))


class TestClassifyConstantPromotion(unittest.TestCase):
    """Locks in the 2026-08-11 fix for a real gap in the 'unchanged' guarantee:
    identical size+block-count does NOT mean identical logic if a constant
    changed (many x86-64 immediate encodings are fixed-width regardless of
    value) -- e.g. crypt32.dll's real `352 * a2` -> `a2 << 9` allocation-size
    change, invisible to size/BB-count alone."""

    def test_identical_size_and_constants_stays_unchanged(self):
        old = {1: _node(1, "SameFn", constant_operands=[100, 200])}
        patch = {1: _node(1, "SameFn", constant_operands=[100, 200])}
        results = autopair.classify(old, patch, [(1, 1, "name", 1.0)])
        self.assertEqual(results[0]["category"], "unchanged")
        self.assertNotIn("promoted_by_constants", results[0])

    def test_identical_size_but_different_constants_promotes_to_candidate(self):
        old = {1: _node(1, "SameShapeFn", constant_operands=[352])}
        patch = {1: _node(1, "SameShapeFn", constant_operands=[512])}
        results = autopair.classify(old, patch, [(1, 1, "name", 1.0)])
        self.assertEqual(results[0]["category"], "candidate")
        self.assertTrue(results[0]["promoted_by_constants"])

    def test_no_constants_on_either_side_stays_unchanged(self):
        # Legitimate common case: trivial functions with no tracked constants
        # at all -- must not be treated as "differs" just because both are empty.
        old = {1: _node(1, "TrivialFn", constant_operands=[])}
        patch = {1: _node(1, "TrivialFn", constant_operands=[])}
        results = autopair.classify(old, patch, [(1, 1, "name", 1.0)])
        self.assertEqual(results[0]["category"], "unchanged")

    def test_size_mismatch_is_still_a_plain_candidate_not_promoted(self):
        # Promotion only applies to the 'unchanged' path -- a real
        # size/BB-count difference was already going to be a candidate.
        old = {1: _node(1, "ChangedFn", size_bytes=100, constant_operands=[352])}
        patch = {1: _node(1, "ChangedFn", size_bytes=120, constant_operands=[512])}
        results = autopair.classify(old, patch, [(1, 1, "name", 1.0)])
        self.assertEqual(results[0]["category"], "candidate")
        self.assertNotIn("promoted_by_constants", results[0])

    def test_noise_name_with_identical_everything_stays_unchanged_not_noise(self):
        # Existing precedence: identical-size check happens before the noise
        # check, so a noise-named function with truly nothing different is
        # still just 'unchanged' -- constant promotion should not change this
        # precedence when constants also match.
        old = {1: _node(1, "wil_details_RecordCachedUsage", constant_operands=[100])}
        patch = {1: _node(1, "wil_details_RecordCachedUsage", constant_operands=[100])}
        results = autopair.classify(old, patch, [(1, 1, "name", 1.0)])
        self.assertEqual(results[0]["category"], "unchanged")


class TestFindNewAndRemoved(unittest.TestCase):
    def test_splits_into_four_buckets_correctly(self):
        nodes_old = {
            1: _node(1, "sub_1001"),                                          # unnamed -- excluded
            2: _node(2, "MatchedFn"),                                         # matched -- excluded
            3: _node(3, "RemovedRealFn"),                                     # real removed
            4: _node(4, "Feature_Servicing_MSRC106366__private_IsEnabledFallback"),  # noise removed
        }
        nodes_patch = {
            10: _node(10, "nullsub_2"),                                       # unnamed -- excluded
            2: _node(2, "MatchedFn"),                                         # matched -- excluded
            11: _node(11, "NewRealFn"),                                       # real new
            12: _node(12, "Feature_NVBugFixes2507__private_IsEnabledFallback"),  # noise new
        }
        pairs = [(2, 2, "MatchedFn", 1.0)]

        new, removed, noise_new, noise_removed = autopair.find_new_and_removed(
            nodes_old, nodes_patch, pairs
        )

        self.assertEqual([n["name"] for n in new], ["NewRealFn"])
        self.assertEqual([n["name"] for n in removed], ["RemovedRealFn"])
        self.assertEqual([n["name"] for n in noise_new],
                          ["Feature_NVBugFixes2507__private_IsEnabledFallback"])
        self.assertEqual([n["name"] for n in noise_removed],
                          ["Feature_Servicing_MSRC106366__private_IsEnabledFallback"])

    def test_no_changes_produces_four_empty_lists(self):
        nodes = {1: _node(1, "OnlyFn")}
        pairs = [(1, 1, "OnlyFn", 1.0)]
        new, removed, noise_new, noise_removed = autopair.find_new_and_removed(nodes, nodes, pairs)
        self.assertEqual((new, removed, noise_new, noise_removed), ([], [], [], []))


if __name__ == "__main__":
    unittest.main()
